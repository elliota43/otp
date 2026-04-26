package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"
)

// Config holds all configurable parameters for the OTP.
type Config struct {
	Issuer      string
	AccountName string
	Algorithm   string
	Digits      int
	Period      int
}

// Option is a function that modifies the Config.
type Option func(*Config)

// WithIssuer sets the application name that appears in the authenticator app.
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

// WithAccountName sets the specific user email/identifier.
func WithAccountName(name string) Option {
	return func(c *Config) {
		c.AccountName = name
	}
}

// WithDigits overrides the default 6-digit length.
func WithDigits(digits int) Option {
	return func(c *Config) {
		c.Digits = digits
	}
}

// WithPeriod overrides the default 30-second period.
func WithPeriod(seconds int) Option {
	return func(c *Config) {
		c.Period = seconds
	}
}

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

func ValidateTOTP(secret []byte, passcode string, timeStep uint64, window int) bool {
	currentUnix := uint64(time.Now().Unix())
	currentT := currentUnix / timeStep

	for i := -window; i <= window; i++ {
		stepT := currentT + uint64(i)

		expectedPasscode := GenerateHOTP(secret, stepT, len(passcode))

		if subtle.ConstantTimeCompare([]byte(expectedPasscode), []byte(passcode)) == 1 {
			return true
		}
	}

	return false
}

// BuildKeyURI constructs an otpauth:// URI for QR code generation.
// It uses safe defaults (SHA1, 6 digits, 30 seconds) which can be overriden.
func BuildKeyURI(base32Secret string, opts ...Option) string {
	cfg := &Config{
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	v := url.Values{}
	v.Set("secret", base32Secret)
	v.Set("algorithm", cfg.Algorithm)
	v.Set("digits", strconv.Itoa(cfg.Digits))
	v.Set("period", strconv.Itoa(cfg.Period))

	if cfg.Issuer != "" {
		v.Set("issuer", cfg.Issuer)
	}

	path := fmt.Sprintf("/%s:%s", cfg.Issuer, cfg.AccountName)
	if cfg.Issuer == "" {
		path = fmt.Sprintf("/%s", cfg.AccountName)
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     path,
		RawQuery: v.Encode(),
	}

	return u.String()
}
