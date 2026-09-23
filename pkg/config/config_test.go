package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRequiresTSIGFile(t *testing.T) {
	t.Setenv("ALLOWED_ZONES", "example.com")

	_, err := LoadConfig()
	if err == nil {
		t.Fatalf("expected TSIG_FILE required error")
	}
	if !strings.Contains(err.Error(), "TSIG_FILE is required") {
		t.Fatalf("expected TSIG_FILE required error, got: %v", err)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	filePath := writeTempFile(t, "tsig.yaml", `
TSIGs:
  - key: client1
    secret: Y2xpZW50MQ==
  - key: client2.
    secret: Y2xpZW50Mg==
    algorithm: hmac-sha512
`)

	t.Setenv("TSIG_FILE", filePath)
	t.Setenv("ALLOWED_ZONES", "example.com")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if cfg.TSIGFile != filePath {
		t.Fatalf("Expected TSIGFile %q, got %q", filePath, cfg.TSIGFile)
	}

	if len(cfg.TSIGs) != 2 {
		t.Fatalf("Expected 2 TSIG entries, got %d", len(cfg.TSIGs))
	}

	if cfg.TSIGs[0].Algorithm != defaultTSIGAlgorithm {
		t.Errorf("Expected default algorithm %q for first entry, got %q", defaultTSIGAlgorithm, cfg.TSIGs[0].Algorithm)
	}

	if cfg.TSIGs[1].Algorithm != "hmac-sha512" {
		t.Errorf("Expected algorithm hmac-sha512 for second entry, got %q", cfg.TSIGs[1].Algorithm)
	}
}

func TestLoadConfigFromFileValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError string
	}{
		{
			name:        "invalid yaml",
			content:     "TSIGs: [",
			expectError: "invalid YAML",
		},
		{
			name:        "empty file",
			content:     " \n\t ",
			expectError: "file is empty",
		},
		{
			name: "no entries",
			content: `
TSIGs: []
`,
			expectError: "TSIGs must contain at least one entry",
		},
		{
			name: "missing key",
			content: `
TSIGs:
  - secret: Y2xpZW50MQ==
`,
			expectError: "key is required",
		},
		{
			name: "missing secret",
			content: `
TSIGs:
  - key: client1
`,
			expectError: "secret is required",
		},
		{
			name: "invalid base64",
			content: `
TSIGs:
  - key: client1
    secret: invalid***
`,
			expectError: "secret must be valid base64",
		},
		{
			name: "unsupported algorithm",
			content: `
TSIGs:
  - key: client1
    secret: Y2xpZW50MQ==
    algorithm: hmac-sha384
`,
			expectError: "unsupported algorithm",
		},
		{
			name: "deprecated md5 algorithm unsupported",
			content: `
TSIGs:
  - key: client1
    secret: Y2xpZW50MQ==
    algorithm: hmac-md5
`,
			expectError: "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := writeTempFile(t, "tsig.yaml", tt.content)
			t.Setenv("TSIG_FILE", filePath)
			t.Setenv("ALLOWED_ZONES", "example.com")

			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Fatalf("Expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		shouldErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key", Secret: "dGVzdA=="}},
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: false,
		},
		{
			name: "missing TSIG entry key",
			config: &Config{
				TSIGs:        []TSIGEntry{{Secret: "dGVzdA=="}},
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "missing TSIG entry secret",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key"}},
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "no allowed zones",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key", Secret: "dGVzdA=="}},
				AllowedZones: []string{},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "invalid port",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key", Secret: "dGVzdA=="}},
				AllowedZones: []string{"example.com"},
				Port:         0,
			},
			shouldErr: true,
		},
		{
			name: "invalid algorithm",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key", Secret: "dGVzdA==", Algorithm: "invalid"}},
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
		{
			name: "md5 algorithm unsupported",
			config: &Config{
				TSIGs:        []TSIGEntry{{Key: "test-key", Secret: "dGVzdA==", Algorithm: "hmac-md5"}},
				AllowedZones: []string{"example.com"},
				Port:         53,
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.shouldErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestLookupTSIGAndSecretMap(t *testing.T) {
	cfg := &Config{
		TSIGs: []TSIGEntry{
			{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
			{Key: "client2.", Secret: "Y2xpZW50Mg==", Algorithm: "hmac-sha512"},
		},
	}

	entry, ok := cfg.LookupTSIG("CLIENT1.")
	if !ok {
		t.Fatalf("Expected to find client1 TSIG entry")
	}
	if entry.Secret != "Y2xpZW50MQ==" {
		t.Fatalf("Unexpected secret for client1")
	}

	if _, ok := cfg.LookupTSIG("missing"); ok {
		t.Fatalf("Expected missing key lookup to fail")
	}

	secretMap := cfg.TSIGSecretMap()
	if secretMap["client1"] != "Y2xpZW50MQ==" || secretMap["client1."] != "Y2xpZW50MQ==" {
		t.Fatalf("Expected key variants for client1 in TSIG secret map")
	}
	if secretMap["client2"] != "Y2xpZW50Mg==" || secretMap["client2."] != "Y2xpZW50Mg==" {
		t.Fatalf("Expected key variants for client2 in TSIG secret map")
	}
}

func TestValidateRejectsDuplicateNormalizedTSIGKeys(t *testing.T) {
	cfg := &Config{
		TSIGs: []TSIGEntry{
			{Key: "Client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
			{Key: "client1.", Secret: "Y2xpZW50Mg==", Algorithm: "hmac-sha512"},
		},
		AllowedZones: []string{"example.com"},
		Port:         53,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected duplicate normalized key validation error")
	}
	if !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("expected duplicate error, got: %v", err)
	}
}

func TestLoadConfigFromFileRejectsDuplicateNormalizedTSIGKeys(t *testing.T) {
	filePath := writeTempFile(t, "tsig.yaml", `
TSIGs:
  - key: DUPLICATE
    secret: Zmlyc3Q=
  - key: duplicate.
    secret: c2Vjb25k
`)

	t.Setenv("TSIG_FILE", filePath)
	t.Setenv("ALLOWED_ZONES", "example.com")

	_, err := LoadConfig()
	if err == nil {
		t.Fatalf("expected duplicate normalized key validation error")
	}
	if !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("expected duplicate error, got: %v", err)
	}
}

func writeTempFile(t *testing.T, fileName, content string) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), fileName)
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return filePath
}

func TestIsZoneAllowed(t *testing.T) {
	cfg := &Config{
		AllowedZones: []string{"example.com", "test.org"},
	}

	tests := []struct {
		zone    string
		allowed bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"test.example.com", true},
		{"test.example.com.", true},
		{"test.org", true},
		{"test.org.", true},
		{"sub.test.org", true},
		{"notallowed.com", false},
		{"notallowed.com.", false},
		{"example.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			result := cfg.IsZoneAllowed(tt.zone)
			if result != tt.allowed {
				t.Errorf("IsZoneAllowed(%s) = %v, want %v", tt.zone, result, tt.allowed)
			}
		})
	}
}
