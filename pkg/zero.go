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
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/acme"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	zeroSSLURL       = "https://acme.zerossl.com/v2/DV90"
	zeroSSLEABAPIURL = "https://api.zerossl.com/acme/eab-credentials-email"
	renewBeforeDays  = 30
)

type eabCredentials struct {
	Success      bool   `json:"success"`
	EABKID       string `json:"eab_kid"`
	EABHMACKey   string `json:"eab_hmac_key"`
	ErrorCode    string `json:"error"`
	ErrorMessage string `json:"message"`
}

func fetchZeroSSLCredentials(ctx context.Context, email string) (kid, hmacKey string, err error) {
	data := []byte(fmt.Sprintf("email=%s", email))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, zeroSSLEABAPIURL, bytes.NewBuffer(data))
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch EAB credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response body: %w", err)
	}

	var credentials eabCredentials
	if err := json.Unmarshal(body, &credentials); err != nil {
		return "", "", fmt.Errorf("unmarshal response: %w", err)
	}

	if !credentials.Success {
		return "", "", fmt.Errorf("API error: %s - %s", credentials.ErrorCode, credentials.ErrorMessage)
	}

	return credentials.EABKID, credentials.EABHMACKey, nil
}

func saveCertificate(filename string, certBytes [][]byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create certificate file: %w", err)
	}
	defer file.Close()

	for _, cert := range certBytes {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("encode certificate: %w", err)
		}
	}
	return nil
}

func savePrivateKey(filename string, privateKey crypto.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	defer file.Close()

	key, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unsupported private key type")
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	return pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
}

func LoadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
	return nil, fmt.Errorf("no certificate found in %s", filename)
}

func certificateNeedsRenewal(cert *x509.Certificate) bool {
	return time.Now().Add(renewBeforeDays * 24 * time.Hour).After(cert.NotAfter)
}

func obtainCertificate(ctx context.Context, client *acme.Client, domain, email, certFile, keyFile string) error {
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate certificate private key: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}

	var challenge *acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
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
		return fmt.Errorf("no HTTP-01 challenge found")
	}

	token := challenge.Token
	keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return fmt.Errorf("get key authorization: %w", err)
	}

	serverShutdown := setupHTTPChallenge(token, keyAuth)
	defer serverShutdown()

	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("wait for order: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certPrivateKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	certs, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("create order certificate: %w", err)
	}

	if err := saveCertificate(certFile, certs); err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	if err := savePrivateKey(keyFile, certPrivateKey); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}

	log.Printf("Certificate saved to: %s", certFile)
	log.Printf("Private key saved to: %s", keyFile)
	return nil
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

func DetermineAction(issue, renew bool) string {
	switch {
	case issue && renew:
		log.Fatal("Cannot specify both --issue and --renew.")
	case issue:
		return "issue"
	case renew:
		return "renew"
	default:
		return "auto"
	}
	return ""
}

func ShouldObtainCertificate(action string, cert *x509.Certificate) bool {
	switch action {
	case "issue":
		return true
	case "renew":
		if cert == nil {
			log.Fatal("No existing certificate to renew.")
		}
		return true
	case "auto":
		return cert == nil || certificateNeedsRenewal(cert)
	}
	return false
}

func ObtainOrRenewCertificate(ctx context.Context, domain, email, certFile, keyFile string) error {
	eabKID, eabHMACKey, err := fetchZeroSSLCredentials(ctx, email)
	if err != nil {
		return fmt.Errorf("fetch ZeroSSL credentials: %w", err)
	}

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate account private key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: zeroSSLURL,
	}

	hmacKey, err := base64.RawURLEncoding.DecodeString(eabHMACKey)
	if err != nil {
		return fmt.Errorf("decode EAB HMAC key: %w", err)
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
		return fmt.Errorf("create account: %w", err)
	}

	return obtainCertificate(ctx, client, domain, email, certFile, keyFile)
}
