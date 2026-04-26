# otp

A zero-dependency, RFC-compliant Go library for generating and validating One-Time Passwords (OTP).

This package strictly implements **RFC 4226 (HOTP)** and **RFC 6238 (TOTP)**.  It provides
cryptographic secret generation, time-drift validation, and safe Key URI construction
for QR code provisioning.

## Installation

```bash
go get github.com/elliota43/otp
```

## Usage

Integrating TOTP into a web application typically requires two steps: **Provisioning** (when the user enables 2FA)
and **Validation** (when the user logs in).

### Provisioning

When a user chooses to enable 2FA, you must generate a secure secret, store it in your database,
and present them with a QR code to scan using an authenticator app (like Google Authenticator or Authy).

```go
package main

import (
    "fmt"
    "log"

    "github.com/elliota43/otp"
)

func main() {
    // Generate a cryptographically secure 20-byte secret
    // Store secretBytes in your database (stored encrypted and per-user)..
    secretBytes, base32Secret, err := otp.GenerateSecret()
    if err != nil {
        log.Fatalf("failed to generate secret: %v", err)
    }

    // build the key URI for the QR code
    // this uses safe RFC defaults, but can be configured.
    uri := otp.BuildKeyURI(
        base32Secret,
        otp.WithIssuer("My Go App"),
        otp.WithAccountName("your@company.com"),
        )

    // Generate a Base64-encoded QR code (256x256 pixels)
    qrDataURI, err := otp.GenerateQRCodeDataURI(uri, 256)
    if err != nil {
        log.Fatalf("failed to generate QR code: %v", err)
    }

    // you can now pass qrDataURI directly to your HTML frontend:
    // <img src="{{ qrDataURI }}" alt="2FA QR Code" />
    fmt.Println("Embed this Data URI into your HTML img tag:")
    fmt.Println(qrDataURI)

    // or you can just use the URI string for a different custom process:
    fmt.Println("Scan this URI:", uri)
}
```

### Validating a Login

During the login process, you retrieve the user's secret from the database and compare it against
the six-digit code they submitted.

Because network latency and device clock drift are common, you should validate against
a time window rather than an exact timestamp.

```go
package main

import (
    "fmt"

    "github.com/elliota43/otp"
)

func ValidateLogin(userSecret []byte, userInput string) {
    // define the time step (standard is 30 seconds)
    timeStep := uint64(30)

    // Define the drift window.
    // A window of 1 means we check the current 30s block, the previous 30s block,
    // and the next 30s block (a 90-second total valid window).
    window := 1

    // ValidateTOTP handles the constant-time comparison internally
    isValid := otp.ValidateTOTP(userSecret, userInput)

    if isValid {
        fmt.Println("Auth successful!")
    } else {
        fmt.Println("Invalid or expired code")
    }
}
```

### Advanced Configuration

You can override the standard defaults for URI generation using the functional options:

```go
// Build a Key URI with custom options
uri := otp.BuildKeyURI(
    base32Secret,
    otp.WithIssuer("Internal VPN"),
    otp.WithAccountName("admin@corp.com"),
    otp.WithAlgorithm(otp.AlgorithmSHA512),
    otp.WithDigits(8),      // Require 8-digit codes.
    otp.WithPeriod(15),     // Require codes to rotate every 15 seconds.
)

// Validate a passcode utilizing SHA512, an 8-digit code,
// a 15-second rotation, and a strictly disabled drift window.
isValid := otp.ValidateTOTP(
    userSecret,
    userInput,
    otp.WithAlgorithm(otp.AlgorithmSHA512),
    otp.WithDigits(8),
    otp.WithPeriod(15),
    otp.WithWindow(0),
)
```

You can also generate codes manually if you are building an admin tool or testing suite:

```go
import "time"

// Generate a TOTP for the current exact time using default settings
code := otp.GenerateTOTP(secretBytes, time.Now())

// Generate an HOTP for a specific counter value
code := otp.GenerateHOTP(secretBytes, uint64(42))

// Generate a TOTP with specific overrides
code := otp.GenerateTOTP(
    secretBytes,
    time.Now(),
    otp.WithAlgorithm(otp.AlgorithmSHA512),
    otp.WithDigits(8),
)
```
