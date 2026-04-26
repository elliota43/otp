package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
)

// Algorithm represents the hashing algorithm used for the HMAC computation.
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// Hash returns the standard library hash constructor for the given algorithm.
// It defaults to SHA1.
func (a Algorithm) Hash() func() hash.Hash {
	switch a {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	case AlgorithmSHA1:
		fallthrough
	default:
		return sha1.New
	}
}

// Config holds all configurable parameters for the OTP.
type Config struct {
	Issuer      string
	AccountName string
	Algorithm   Algorithm
	Digits      int
	Period      int
	Window      int
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

// WithAlgorithm overrides the default SHA1 hashing algorithm.
func WithAlgorithm(algo Algorithm) Option {
	return func(c *Config) {
		c.Algorithm = algo
	}
}

// WithWindow sets the acceptable drift window for TOTP validation.
// A window of 1 checks the current, previous, and next time steps.
func WithWindow(window int) Option {
	return func(c *Config) {
		c.Window = window
	}
}

// GenerateHOTP computes an HMAC-based One-Time Password (HOTP) as specified in RFC 4226.
// It requires a shared secret, an 8-byte counter, and the desired length of the
// returned numeric string (typically 6 or 8 digits).
func GenerateHOTP(secret []byte, counter uint64, opts ...Option) string {
	cfg := &Config{
		Algorithm: AlgorithmSHA1,
		Digits:    6,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(cfg.Algorithm.Hash(), secret)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	offset := hash[19] & 0x0f

	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryCode &= 0x7fffffff

	modulus := uint32(math.Pow10(cfg.Digits))
	otp := binaryCode % modulus

	format := fmt.Sprintf("%%0%dd", cfg.Digits)
	return fmt.Sprintf(format, otp)
}

// GenerateTOTP computes a Time-Based One-Time Password (TOTP) as specified in RFC 6238.
// It converts the provided timestamp into a discrete time step (T) based on the
// timeStep parameter (typically 30 seconds) and passes it to the underlying HOTP algorithm.
func GenerateTOTP(secret []byte, t time.Time, opts ...Option) string {

	cfg := &Config{
		Period: 30,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	unixTime := uint64(t.Unix())
	T := unixTime / uint64(cfg.Period)

	return GenerateHOTP(secret, T, opts...)
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

// ValidateTOTP checks if the provided passcode is valid for the given secret.
// It defaults to a 30-second period and a drift window of 1, checking the
// current, previous, and next time steps to account for network latency.
func ValidateTOTP(secret []byte, passcode string, opts ...Option) bool {
	cfg := &Config{
		Period: 30,
		Window: 1,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	currentUnix := uint64(time.Now().Unix())
	currentT := currentUnix / uint64(cfg.Period)

	for i := -cfg.Window; i <= cfg.Window; i++ {
		stepT := currentT + uint64(i)
		expectedPasscode := GenerateHOTP(secret, stepT, opts...)

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
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	v := url.Values{}
	v.Set("secret", base32Secret)
	v.Set("algorithm", string(cfg.Algorithm))
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

// GenerateQRCodePNG returns a raw PNG byte slice representing the QR code for the given URI.
// It uses a medium error recovery level (15%) and the specified width/height in pixels.
func GenerateQRCodePNG(uri string, size int) ([]byte, error) {
	return qrcode.Encode(uri, qrcode.Medium, size)
}

// GenerateQRCodeDataURI returns a Base64 encoded Data URI of the QR code.
// This string can be injected directly into the `src` attribute of an HTML <img> tag.
func GenerateQRCodeDataURI(uri string, size int) (string, error) {
	pngBytes, err := GenerateQRCodePNG(uri, size)
	if err != nil {
		return "", err
	}

	base64Encoded := base64.StdEncoding.EncodeToString(pngBytes)
	return fmt.Sprintf("data:image/png;base64,%s", base64Encoded), nil
}
