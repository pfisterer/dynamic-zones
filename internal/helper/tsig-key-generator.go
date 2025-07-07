package helper

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateTSIGKeyHMACSHA512 generates a random HMAC-SHA512 key suitable for TSIG and encodes it with Base64.
func GenerateTSIGKeyHMACSHA512() (string, error) {
	// Define the desired length of the key (in bytes). For HMAC-SHA512, a key length of at least 32 bytes (256 bits) is recommended.
	keyLength := 64

	// Create a byte slice for the key.
	key := make([]byte, keyLength)

	// Fill the byte slice with random data from the cryptographically secure source.
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("Error generating the random key: %w", err)
	}

	// Encode the key with Base64 to represent it as a string. TSIG keys are typically Base64 encoded.
	encodedKey := base64.StdEncoding.EncodeToString(key)

	return encodedKey, nil
}
