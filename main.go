package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/elliota43/otp/otp"
)

func main() {
	fmt.Println("=== TOTP Setup & Verification ===")

	fmt.Println("\n[*] Provisioning new credentials...")

	secretBytes, base32Secret, err := otp.GenerateSecret()
	if err != nil {
		log.Fatalf("fatal: failed to generate secret: %v", err)
	}

	fmt.Printf("System generated Base32 secret: %s\n", base32Secret)

	uri := otp.BuildKeyURI(
		base32Secret,
		otp.WithIssuer("MyGoApplication"),
		otp.WithAccountName("elliot@localhost"),
	)

	qrDataURI, err := otp.GenerateQRCodeDataURI(uri, 256)
	if err != nil {
		log.Fatalf("fatal: failed to generate QR code data URI: %v", err)
	}

	fmt.Println("\nTo provision your authenticator app, paste the following Data URI directly into a browser address bar:")
	fmt.Printf("\n%s\n", qrDataURI)

	fmt.Println("\n[*] Verification")
	fmt.Println("Scan the QR code, then enter the current 6-digit code")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter TOTP: ")

	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("fatal: failed to read stdin: %v", err)
	}

	input = strings.TrimSpace(input)

	isValid := otp.ValidateTOTP(secretBytes, input)

	fmt.Println("\n=== Result ===")
	if isValid {
		fmt.Println("[OK] Valid code. Auth successful.")
	} else {
		fmt.Println("[FAIL] Invalid or expired code. Auth failed.")
	}
}
