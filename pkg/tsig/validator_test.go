package tsig

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator("test-key", "test-secret", "hmac-sha256")
	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}

	if v.keyName != "test-key" {
		t.Errorf("Expected keyName 'test-key', got '%s'", v.keyName)
	}

	if v.secret != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got '%s'", v.secret)
	}

	if v.algorithm != "hmac-sha256" {
		t.Errorf("Expected algorithm 'hmac-sha256', got '%s'", v.algorithm)
	}
}

func TestGetAlgorithmName(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  string
	}{
		{"hmac-sha1", dns.HmacSHA1},
		{"hmac-sha256", dns.HmacSHA256},
		{"hmac-sha512", dns.HmacSHA512},
		{"hmac-md5", dns.HmacMD5},
		{"unknown", dns.HmacSHA256}, // defaults to SHA256
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			v := NewValidator("test", "secret", tt.algorithm)
			result := v.GetAlgorithmName()
			if result != tt.expected {
				t.Errorf("GetAlgorithmName() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestGetKeyName(t *testing.T) {
	v := NewValidator("my-key", "secret", "hmac-sha256")
	if v.GetKeyName() != "my-key" {
		t.Errorf("GetKeyName() = %s, want 'my-key'", v.GetKeyName())
	}
}

func TestValidateNoTSIG(t *testing.T) {
	v := NewValidator("test-key", "test-secret", "hmac-sha256")

	// Create a message without TSIG
	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")

	err := v.Validate(msg, "")
	if err == nil {
		t.Error("Expected error for message without TSIG, got nil")
	}
}

func TestValidateTSIGKeyMismatch(t *testing.T) {
	v := NewValidator("correct-key", "test-secret", "hmac-sha256")

	// Create a message with TSIG using different key
	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")
	msg.SetTsig("wrong-key", dns.HmacSHA256, 300, 0)

	err := v.Validate(msg, "")
	if err == nil {
		t.Error("Expected error for key mismatch, got nil")
	}
}

func TestSign(t *testing.T) {
	// Use a proper base64-encoded secret (output of: echo -n "my-secret-key" | base64)
	secret := "bXktc2VjcmV0LWtleQ=="
	v := NewValidator("test-key.", secret, "hmac-sha256") // key needs trailing dot

	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")

	signedMsg, mac, err := v.Sign(msg, "")
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if signedMsg == nil {
		t.Error("Sign() returned nil message")
	}

	if mac == "" {
		t.Error("Sign() returned empty MAC")
	}

	// Check that TSIG record was added
	if signedMsg.IsTsig() == nil {
		t.Error("Signed message does not contain TSIG record")
	}
}
