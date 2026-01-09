package helper

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func Sha1Hash(input string) string {
	hasher := sha1.New()

	// Write the string data to the hash object.
	// The data must be converted to a byte slice.
	hasher.Write([]byte(input))

	// Get the final hash sum as a byte slice
	sha1Bytes := hasher.Sum(nil)

	// 3. Encode the hash byte slice to a human-readable hexadecimal string
	return hex.EncodeToString(sha1Bytes)

}

// GenerateTSIGKeyHMACSHA512 generates a random HMAC-SHA512 key suitable for TSIG and encodes it with Base64.
func GenerateTSIGKeyHMACSHA512() (string, error) {
	// Define the desired length of the key (in bytes). For HMAC-SHA512, a key length of at least 32 bytes (256 bits) is recommended.
	keyLength := 64

	// Create a byte slice for the key.
	key := make([]byte, keyLength)

	// Fill the byte slice with random data from the cryptographically secure source.
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error generating the random key: %w", err)
	}

	// Encode the key with Base64 to represent it as a string. TSIG keys are typically Base64 encoded.
	encodedKey := base64.StdEncoding.EncodeToString(key)

	return encodedKey, nil
}
