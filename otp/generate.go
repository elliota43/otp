package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// GenerateHOTP computes an HMAC-based One-Time Password (HOTP) as specified in RFC 4226.
// It requires a shared secret, an 8-byte counter, and the desired length of the
// returned numeric string (typically 6 or 8 digits).
func GenerateHOTP(secret []byte, counter uint64, digits int) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[19] & 0x0f

	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryCode &= 0x7fffffff

	modulus := uint32(math.Pow10(digits))
	otp := binaryCode % modulus

	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, otp)
}

// GenerateTOTP computes a Time-Based One-Time Password (TOTP) as specified in RFC 6238.
// It converts the provided timestamp into a discrete time step (T) based on the
// timeStep parameter (typically 30 seconds) and passes it to the underlying HOTP algorithm.
func GenerateTOTP(secret []byte, timeStep uint64, t time.Time, digits int) string {
	unixTime := uint64(t.Unix())

	T := unixTime / timeStep

	return GenerateHOTP(secret, T, digits)
}

// GenerateSecret creates a cryptographically secure, 20-byte random secret.
// It returns both the raw byte slice and a Base32 encoded string (without padding)
// suitable for provisioning in standard authenticator applications via a Key URI.
func GenerateSecret() (secretBytes []byte, base32Secret string, err error) {
	secretBytes = make([]byte, 20)

	_, err = rand.Read(secretBytes)
	if err != nil {
		return nil, "", err
	}

	base32Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	return secretBytes, base32Secret, nil
}
