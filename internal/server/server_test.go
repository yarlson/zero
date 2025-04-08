package server

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yarlson/zero/internal/cert"
)

func TestServer(t *testing.T) {
	t.Run("ACME challenge endpoint", func(t *testing.T) {
		store := cert.NewStore()
		srv := New(store, 8080)

		// Start server in background
		go func() {
			err := srv.Start()
			require.NoError(t, err)
		}()
		defer func() { _ = srv.Stop() }()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Test cases
		tests := []struct {
			name         string
			token        string
			response     string
			method       string
			expectedCode int
			expectedBody string
		}{
			{
				name:         "valid challenge",
				token:        "valid-token",
				response:     "challenge-response",
				method:       http.MethodGet,
				expectedCode: http.StatusOK,
				expectedBody: "challenge-response",
			},
			{
				name:         "non-existent token",
				token:        "nonexistent-token",
				method:       http.MethodGet,
				expectedCode: http.StatusNotFound,
			},
			{
				name:         "wrong method",
				token:        "valid-token",
				method:       http.MethodPost,
				expectedCode: http.StatusMethodNotAllowed,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if tc.response != "" {
					store.StoreChallenge(tc.token, tc.response)
				}

				// Make request
				req, err := http.NewRequest(tc.method,
					fmt.Sprintf("http://localhost:8080/.well-known/acme-challenge/%s", tc.token),
					nil)
				require.NoError(t, err)

				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				defer func() {
					if closeErr := resp.Body.Close(); closeErr != nil {
						t.Logf("Failed to close response body: %v", closeErr)
					}
				}()

				assert.Equal(t, tc.expectedCode, resp.StatusCode)

				if tc.expectedBody != "" {
					body, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					assert.Equal(t, tc.expectedBody, string(body))
				}
			})
		}
	})

	t.Run("HTTPS redirect", func(t *testing.T) {
		store := cert.NewStore()
		srv := New(store, 8081)

		go func() {
			err := srv.Start()
			require.NoError(t, err)
		}()
		defer func() { _ = srv.Stop() }()

		time.Sleep(100 * time.Millisecond)

		// Test cases
		tests := []struct {
			name        string
			requestURL  string
			expectedURL string
		}{
			{
				name:        "basic redirect",
				requestURL:  "http://localhost:8081/path",
				expectedURL: "https://localhost/path",
			},
			{
				name:        "redirect with query params",
				requestURL:  "http://localhost:8081/path?key=value",
				expectedURL: "https://localhost/path?key=value",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				client := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err := client.Get(tc.requestURL)
				require.NoError(t, err)
				defer func() {
					if closeErr := resp.Body.Close(); closeErr != nil {
						t.Logf("Failed to close response body: %v", closeErr)
					}
				}()

				assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
				location := resp.Header.Get("Location")
				assert.Equal(t, tc.expectedURL, location)
			})
		}
	})
}
