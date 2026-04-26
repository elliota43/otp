package otp

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGenerateHOTP(t *testing.T) {
	secret := []byte("12345678901234567890")

	tests := []struct {
		counter  uint64
		expected string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tc := range tests {
		// Defaults to 6 digits
		actual := GenerateHOTP(secret, tc.counter)
		if actual != tc.expected {
			t.Errorf("GenerateHOTP(secret, %d) = %s; expected %s", tc.counter, actual, tc.expected)
		}
	}
}

func TestGenerateTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")

	// Note: RFC 6238 test vectors expect 8-digit outputs
	tests := []struct {
		timestamp int64
		expected  string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range tests {
		testTime := time.Unix(tc.timestamp, 0)

		// Explicitly override the default 6 digits to 8
		actual := GenerateTOTP(secret, testTime, WithDigits(8))
		if actual != tc.expected {
			t.Errorf("GenerateTOTP(secret, %d, WithDigits(8)) = %s; expected %s", tc.timestamp, actual, tc.expected)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	bytes, b32, err := GenerateSecret()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bytes) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(bytes))
	}

	if strings.Contains(b32, "=") {
		t.Errorf("expected no padding in base32 string")
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Errorf("failed to decode base32 string: %v", err)
	}

	if string(decoded) != string(bytes) {
		t.Errorf("decoded base32 does not match raw bytes")
	}
}

func TestValidateTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")

	// Simulating time utilizing the default 30-second period
	now := time.Now()
	currentT := uint64(now.Unix()) / 30

	validCurrent := GenerateHOTP(secret, currentT)
	validPast := GenerateHOTP(secret, currentT-1)
	validFuture := GenerateHOTP(secret, currentT+1)
	invalidPast := GenerateHOTP(secret, currentT-2)

	// Tests using the default Window of 1
	if !ValidateTOTP(secret, validCurrent) {
		t.Errorf("expected current time step code to be valid")
	}

	if !ValidateTOTP(secret, validPast) {
		t.Errorf("expected past window code to be valid")
	}

	if !ValidateTOTP(secret, validFuture) {
		t.Errorf("expected future window code to be valid")
	}

	if ValidateTOTP(secret, invalidPast) {
		t.Errorf("expected code outside window to be invalid")
	}

	// Test validating an override
	if ValidateTOTP(secret, validPast, WithWindow(0)) {
		t.Errorf("expected past window code to be invalid with Window(0)")
	}
}

func TestBuildKeyURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	uri1 := BuildKeyURI(secret, WithAccountName("alice@example.com"))
	parsed1, err := url.Parse(uri1)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	if parsed1.Scheme != "otpauth" || parsed1.Host != "totp" {
		t.Errorf("invalid scheme/host: %s", uri1)
	}

	if parsed1.Path != "/alice@example.com" {
		t.Errorf("expected path /alice@example.com, got %s", parsed1.Path)
	}

	if parsed1.Query().Get("digits") != "6" {
		t.Errorf("expected default 6 digits, got %s", parsed1.Query().Get("digits"))
	}

	if parsed1.Query().Get("period") != "30" {
		t.Errorf("expected default period of 30, got %s", parsed1.Query().Get("period"))
	}

	if parsed1.Query().Get("algorithm") != "SHA1" {
		t.Errorf("expected default algorithm SHA1, got %s", parsed1.Query().Get("algorithm"))
	}

	uri2 := BuildKeyURI(
		secret,
		WithAccountName("bob@example.com"),
		WithIssuer("Acme Corp"),
		WithDigits(8),
		WithPeriod(15),
		WithAlgorithm(AlgorithmSHA256),
	)

	parsed2, err := url.Parse(uri2)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	expectedPath := "/Acme Corp:bob@example.com"
	if parsed2.Path != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, parsed2.Path)
	}

	if parsed2.Query().Get("issuer") != "Acme Corp" {
		t.Errorf("expected issuer Acme Corp, got %s", parsed2.Query().Get("issuer"))
	}

	if parsed2.Query().Get("digits") != "8" {
		t.Errorf("expected overridden 8 digits, got %s", parsed2.Query().Get("digits"))
	}

	if parsed2.Query().Get("period") != "15" {
		t.Errorf("expected overridden 15 period, got %s", parsed2.Query().Get("period"))
	}

	if parsed2.Query().Get("algorithm") != "SHA256" {
		t.Errorf("expected overridden algorithm SHA256, got %s", parsed2.Query().Get("algorithm"))
	}
}

func TestGenerateQRCode(t *testing.T) {
	uri := "otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP"

	pngBytes, err := GenerateQRCodePNG(uri, 256)
	if err != nil {
		t.Fatalf("failed to generate PNG: %v", err)
	}

	// check for PNG header
	if len(pngBytes) < 8 || string(pngBytes[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Errorf("output does not appear to be a valid PNG image")
	}

	dataURI, err := GenerateQRCodeDataURI(uri, 256)
	if err != nil {
		t.Fatalf("failed to generate Data URI: %v", err)
	}

	if !strings.HasPrefix(dataURI, "data:image/png;base64,") {
		t.Errorf("data URI is missing the correct image/png prefix")
	}
}
