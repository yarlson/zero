package main

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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/acme"
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

func fetchZeroSSLCredentials(email string) (kid, hmacKey string, err error) {
	data := []byte(fmt.Sprintf("email=%s", email))
	resp, err := http.Post(zeroSSLEABAPIURL, "application/x-www-form-urlencoded", bytes.NewBuffer(data))
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

func loadCertificate(filename string) (*x509.Certificate, error) {
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

	server := setupHTTPChallenge(token, keyAuth)
	defer server.Close()

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

func setupHTTPChallenge(token, keyAuth string) *http.Server {
	http.HandleFunc("/.well-known/acme-challenge/"+token, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(keyAuth))
	})
	server := &http.Server{Addr: ":80"}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
	return server
}

func determineAction(issue, renew bool) string {
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

func shouldObtainCertificate(action string, cert *x509.Certificate) bool {
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

func obtainOrRenewCertificate(domain, email, certFile, keyFile string) error {
	eabKID, eabHMACKey, err := fetchZeroSSLCredentials(email)
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

	ctx := context.Background()

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

func main() {
	var (
		domain  string
		email   string
		certDir string
		issue   bool
		renew   bool
	)

	pflag.StringVarP(&domain, "domain", "d", "", "Domain name for the certificate")
	pflag.StringVarP(&email, "email", "e", "", "Email address for account registration")
	pflag.StringVarP(&certDir, "cert-dir", "c", "./certs", "Directory to store certificates")
	pflag.BoolVarP(&issue, "issue", "i", false, "Issue a new certificate")
	pflag.BoolVarP(&renew, "renew", "r", false, "Renew the existing certificate")

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "  %s -d example.com -e user@example.com [-c /path/to/certs] [-i] [-r]\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}

	pflag.Parse()

	if domain == "" || email == "" {
		fmt.Println("Error: Domain and email are required.")
		pflag.Usage()
		os.Exit(1)
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		log.Fatalf("Create cert directory: %v", err)
	}

	certFile := filepath.Join(certDir, domain+".crt")
	keyFile := filepath.Join(certDir, domain+".key")

	action := determineAction(issue, renew)

	cert, err := loadCertificate(certFile)
	if err != nil && action != "issue" {
		log.Printf("Load existing certificate: %v", err)
	}

	if shouldObtainCertificate(action, cert) {
		if err := obtainOrRenewCertificate(domain, email, certFile, keyFile); err != nil {
			log.Fatalf("Obtain/renew certificate: %v", err)
		}
	} else {
		if cert == nil {
			log.Println("No existing certificate to renew.")
			return
		}
		log.Printf("Certificate is valid until %s. No action needed.", cert.NotAfter)
	}
}
