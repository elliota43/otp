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
		actual := GenerateHOTP(secret, tc.counter, 6)
		if actual != tc.expected {
			t.Errorf("GenerateHOTP(secret, %d, 6) = %s; expected %s", tc.counter, actual, tc.expected)
		}
	}
}

func TestGenerate(t *testing.T) {
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

		actual := GenerateTOTP(secret, 30, testTime, 8)
		if actual != tc.expected {
			t.Errorf("GenerateTOTP(secret, 30, %d, 8) = %s; expected %s", tc.timestamp, actual, tc.expected)
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
	timeStep := uint64(30)
	window := 1

	now := time.Now()
	currentT := uint64(now.Unix()) / timeStep

	validCurrent := GenerateHOTP(secret, currentT, 6)
	validPast := GenerateHOTP(secret, currentT-1, 6)
	validFuture := GenerateHOTP(secret, currentT+1, 6)
	invalidPast := GenerateHOTP(secret, currentT-2, 6)

	if !ValidateTOTP(secret, validCurrent, timeStep, window) {
		t.Errorf("expected current time step code to be valid")
	}

	if !ValidateTOTP(secret, validPast, timeStep, window) {
		t.Errorf("expected past window code to be valid")
	}

	if !ValidateTOTP(secret, validFuture, timeStep, window) {
		t.Errorf("expected future window code to be valid")
	}

	if ValidateTOTP(secret, invalidPast, timeStep, window) {
		t.Errorf("expected code outside window to be invalid")
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

	uri2 := BuildKeyURI(
		secret,
		WithAccountName("bob@example.com"),
		WithIssuer("Acme Corp"),
		WithDigits(8),
		WithPeriod(15),
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
		t.Errorf("expected overriden 8 digits, got %s", parsed2.Query().Get("digits"))
	}

	if parsed2.Query().Get("period") != "15" {
		t.Errorf("expected overriden 15 period, got %s", parsed2.Query().Get("period"))
	}

}
