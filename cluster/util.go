package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// GenerateInstanceID creates a unique identifier for this cluster instance
// Format: hostname-randomhex (e.g., web1-a1b2c3)
func GenerateInstanceID() string {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Clean hostname - remove any characters that might cause issues
	hostname = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, hostname)

	// Generate 6 random bytes
	randomBytes := make([]byte, 3)
	if _, err := rand.Read(randomBytes); err != nil {
		// If we can't get random bytes, use timestamp-based fallback
		return fmt.Sprintf("%s-%d", hostname, time.Now().UnixNano())
	}

	// Convert to hex and combine with hostname
	return fmt.Sprintf("%s-%s", hostname, hex.EncodeToString(randomBytes))
}
