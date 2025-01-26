package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	t.Run("certificate operations", func(t *testing.T) {
		store := NewStore()
		tmpFile := "test_cert.pem"
		defer os.Remove(tmpFile)

		// Create a self-signed test certificate
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test.example.com",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		require.NoError(t, err)

		// Test saving and loading certificate
		err = store.SaveCertificate(tmpFile, [][]byte{certBytes})
		assert.NoError(t, err)

		loadedCert, err := store.LoadCertificate(tmpFile)
		assert.NoError(t, err)
		assert.Equal(t, "test.example.com", loadedCert.Subject.CommonName)
	})

	t.Run("private key operations", func(t *testing.T) {
		store := NewStore()
		tmpFile := "test_key.pem"
		defer os.Remove(tmpFile)

		// Generate and save private key
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = store.SavePrivateKey(tmpFile, priv)
		assert.NoError(t, err)

		// Verify file exists and has content
		_, err = os.Stat(tmpFile)
		assert.NoError(t, err)
	})

	t.Run("challenge operations", func(t *testing.T) {
		store := NewStore()

		// Store a challenge
		store.StoreChallenge("token1", "response1")

		// Get existing challenge
		response, exists := store.GetChallengeResponse("token1")
		assert.True(t, exists)
		assert.Equal(t, "response1", response)

		// Challenge should be deleted after retrieval
		time.Sleep(10 * time.Millisecond) // Give time for goroutine to complete
		_, exists = store.GetChallengeResponse("token1")
		assert.False(t, exists)

		// Get non-existent challenge
		_, exists = store.GetChallengeResponse("nonexistent")
		assert.False(t, exists)
	})

	t.Run("file operation errors", func(t *testing.T) {
		store := NewStore()
		invalidPath := "/nonexistent/path/cert.pem"

		// Test certificate operations with invalid path
		err := store.SaveCertificate(invalidPath, [][]byte{{}})
		assert.Error(t, err)

		_, err = store.LoadCertificate(invalidPath)
		assert.Error(t, err)

		// Test private key operations with invalid path
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = store.SavePrivateKey(invalidPath, priv)
		assert.Error(t, err)
	})
}
