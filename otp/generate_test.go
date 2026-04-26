package otp

import (
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
			t.Errorf("generateHOTP(secret, %d, 6) = %s; expected %s", tc.counter, actual, tc.expected)
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
			t.Errorf("Generate(secret, 30, %d, 8) = %s; expected %s", tc.timestamp, actual, tc.expected)
		}
	}
}
