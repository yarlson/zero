package pkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	zeroSSLEABAPIURL = "https://api.zerossl.com/acme/eab-credentials-email"
	zeroSSLURL       = "https://acme.zerossl.com/v2/DV90"
)

type ZeroSSLService struct {
	client *http.Client
}

type ZeroSSLOption func(*ZeroSSLService)

func WithClient(client *http.Client) ZeroSSLOption {
	return func(s *ZeroSSLService) {
		s.client = client
	}
}

func NewZeroSSLService(options ...ZeroSSLOption) *ZeroSSLService {
	service := &ZeroSSLService{
		client: &http.Client{Timeout: 10 * time.Second},
	}

	for _, option := range options {
		option(service)
	}

	return service
}

func (s *ZeroSSLService) FetchCredentials(ctx context.Context, email string) (kid, hmacKey string, err error) {
	data := []byte(fmt.Sprintf("email=%s", email))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, zeroSSLEABAPIURL, bytes.NewBuffer(data))
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch EAB credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response body: %w", err)
	}

	type response struct {
		Success      bool   `json:"success"`
		EABKID       string `json:"eab_kid"`
		EABHMACKey   string `json:"eab_hmac_key"`
		ErrorCode    string `json:"error"`
		ErrorMessage string `json:"message"`
	}
	var result response
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("unmarshal response: %w", err)
	}

	if !result.Success {
		return "", "", fmt.Errorf("API error: %s - %s", result.ErrorCode, result.ErrorMessage)
	}

	return result.EABKID, result.EABHMACKey, nil
}

func (s *ZeroSSLService) ObtainCertificate(ctx context.Context, domain, email string) (*acme.Client, [][]byte, crypto.PrivateKey, error) {
	eabKID, eabHMACKey, err := s.FetchCredentials(ctx, email)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch ZeroSSL credentials: %w", err)
	}

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate account private key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: zeroSSLURL,
	}

	hmacKey, err := base64.RawURLEncoding.DecodeString(eabHMACKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode EAB HMAC key: %w", err)
	}

	account := &acme.Account{
		Contact: []string{"mailto:" + email},
		ExternalAccountBinding: &acme.ExternalAccountBinding{
			KID: eabKID,
			Key: hmacKey,
		},
	}
	_, err = client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create account: %w", err)
	}

	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate certificate private key: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create order: %w", err)
	}

	var challenge *acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get authorization: %w", err)
		}
		for _, c := range auth.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge != nil {
			break
		}
	}
	if challenge == nil {
		return nil, nil, nil, fmt.Errorf("no HTTP-01 challenge found")
	}

	token := challenge.Token
	keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get key authorization: %w", err)
	}

	serverShutdown := setupHTTPChallenge(token, keyAuth)
	defer serverShutdown()

	if _, err := client.Accept(ctx, challenge); err != nil {
		return nil, nil, nil, fmt.Errorf("accept challenge: %w", err)
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wait for order: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	certs, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create order certificate: %w", err)
	}

	return client, certs, certPrivateKey, nil
}

func setupHTTPChallenge(token, keyAuth string) func() {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/"+token, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(keyAuth))
	})

	server := &http.Server{
		Addr:    ":80",
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}
}
