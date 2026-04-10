package smbserver

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// verifyCandidate checks password against the captured hash regardless of protocol.
// For NTLMv2 it also retries with an empty domain (smbclient / local accounts).
func verifyCandidate(captured *CapturedHash, password string) bool {
	switch captured.Protocol {
	case ProtoNTLMv1, ProtoNTLMv1ESS:
		return NTLMv1Verify(captured, password)
	default: // ProtoNTLMv2
		if NTLMv2Verify(captured, password) {
			return true
		}
		if captured.Domain != "" {
			clone := *captured
			clone.Domain = ""
			return NTLMv2Verify(&clone, password)
		}
		return false
	}
}

// buildDefaultWordlist returns a small candidate list that covers the most
// common weak / default passwords, plus username and domain variations.
// john --single cracks these in milliseconds; we replicate the same idea here.
func buildDefaultWordlist(username, domain string) []string {
	year := time.Now().Year()

	static := []string{
		// classic commons
		"password", "Password", "password1", "Password1",
		"Password123", "password123", "P@ssw0rd", "p@ssw0rd",
		"Welcome1", "welcome1", "Welcome123",
		"Admin123", "admin123", "Admin1", "admin1",
		"12345678", "123456789", "1234567890",
		"letmein", "iloveyou", "monkey", "dragon",
		"master", "shadow", "sunshine", "princess",
		"qwerty", "Qwerty", "abc123", "111111",
		"pass", "Pass", "pass1", "Pass1",
		"changeme", "Changeme1", "Change.me",
		"secret", "Secret1", "s3cr3t",
		"summer", "Summer2024", "Winter2024",
		"Spring2024", "Fall2024",
	}

	var dynamic []string

	// username-based candidates
	titler := cases.Title(language.Und)
	u := strings.ToLower(username)
	uTitle := titler.String(u)
	if u != "" {
		dynamic = append(dynamic,
			u,
			uTitle,
			strings.ToUpper(u),
			u+"1",
			uTitle+"1",
			u+"123",
			uTitle+"123",
			u+"!",
			uTitle+"!",
			u+fmt.Sprintf("%d", year),
			uTitle+fmt.Sprintf("%d", year),
			u+"2025",
			u+"2024",
		)
	}

	// domain-based candidates
	d := strings.ToLower(domain)
	dTitle := titler.String(d)
	if d != "" {
		dynamic = append(dynamic,
			d,
			dTitle,
			strings.ToUpper(d),
			d+"1",
			dTitle+"1",
			d+"123",
			dTitle+"123",
			d+fmt.Sprintf("%d", year),
			dTitle+fmt.Sprintf("%d", year),
			d+"2025",
			d+"2024",
			d+"!",
		)
	}

	// username == domain (common local-only setup)
	if u != "" && d != "" && u != d {
		dynamic = append(dynamic, u+d, d+u)
	}

	// empty password
	dynamic = append(dynamic, "")

	return append(static, dynamic...)
}

// TryCrackDefault tries the built-in wordlist only.
// Safe to call synchronously — ~100 candidates, sub-millisecond.
func TryCrackDefault(captured *CapturedHash) (string, bool) {
	for _, pw := range buildDefaultWordlist(captured.Username, captured.Domain) {
		if verifyCandidate(captured, pw) {
			return pw, true
		}
	}
	return "", false
}

// TryCrackFile streams wordlistPath line-by-line and returns the first match.
// Intended to be called in a goroutine for large lists — do not block the
// SMB response on this.
func TryCrackFile(captured *CapturedHash, wordlistPath string) (string, bool) {
	f, err := os.Open(wordlistPath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if pw := scanner.Text(); verifyCandidate(captured, pw) {
			return pw, true
		}
	}
	return "", false
}
