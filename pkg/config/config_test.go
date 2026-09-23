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
	filePath := writeTempFile(t, "tsig-file.conf", `
key "client1" {
  algorithm hmac-sha256;
  secret "Y2xpZW50MQ==";
};

key "client2." {
  algorithm hmac-sha512;
  secret "Y2xpZW50Mg==";
};
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

	if cfg.TSIGs[0].Algorithm != "hmac-sha256" {
		t.Errorf("Expected algorithm hmac-sha256 for first entry, got %q", cfg.TSIGs[0].Algorithm)
	}

	if cfg.TSIGs[1].Algorithm != "hmac-sha512" {
		t.Errorf("Expected algorithm hmac-sha512 for second entry, got %q", cfg.TSIGs[1].Algorithm)
	}
}

func TestLoadConfigFromFileParsesWhitespaceAndInlineBlocks(t *testing.T) {
	filePath := writeTempFile(t, "tsig-file.conf", `

key "one"   { algorithm hmac-sha512; secret "b25l"; };
key "two"
{
	algorithm   hmac-sha256;
	secret "dHdv";
};

`)

	t.Setenv("TSIG_FILE", filePath)
	t.Setenv("ALLOWED_ZONES", "example.com")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}

	if len(cfg.TSIGs) != 2 {
		t.Fatalf("Expected 2 TSIG entries, got %d", len(cfg.TSIGs))
	}

	if cfg.TSIGs[0].Key != "one" || cfg.TSIGs[0].Algorithm != "hmac-sha512" {
		t.Fatalf("unexpected first TSIG entry: %+v", cfg.TSIGs[0])
	}

	if cfg.TSIGs[1].Key != "two" || cfg.TSIGs[1].Algorithm != "hmac-sha256" {
		t.Fatalf("unexpected second TSIG entry: %+v", cfg.TSIGs[1])
	}
}

func TestLoadConfigFromFileValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError string
	}{
		{
			name:        "no key blocks",
			content:     "this is not a bind tsig file",
			expectError: "no TSIG key blocks found",
		},
		{
			name:        "empty file",
			content:     " \n\t ",
			expectError: "file is empty",
		},
		{
			name: "missing key",
			content: `
key "" {
  algorithm hmac-sha256;
  secret "Y2xpZW50MQ==";
};
`,
			expectError: "key is required",
		},
		{
			name: "missing secret",
			content: `
key "client1" {
  algorithm hmac-sha256;
};
`,
			expectError: "secret is required",
		},
		{
			name: "missing algorithm",
			content: `
key "client1" {
  secret "Y2xpZW50MQ==";
};
`,
			expectError: "algorithm is required",
		},
		{
			name: "invalid base64",
			content: `
key "client1" {
  algorithm hmac-sha256;
  secret "invalid***";
};
`,
			expectError: "secret must be valid base64",
		},
		{
			name: "unsupported algorithm",
			content: `
key "client1" {
  algorithm hmac-sha384;
  secret "Y2xpZW50MQ==";
};
`,
			expectError: "unsupported algorithm",
		},
		{
			name: "deprecated md5 algorithm unsupported",
			content: `
key "client1" {
  algorithm hmac-md5;
  secret "Y2xpZW50MQ==";
};
`,
			expectError: "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := writeTempFile(t, "tsig-file.conf", tt.content)
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

func TestLoadConfigFromFileDuplicateNormalizedTSIGKeysLastWins(t *testing.T) {
	filePath := writeTempFile(t, "tsig-file.conf", `
key "DUPLICATE" {
  algorithm hmac-sha256;
  secret "Zmlyc3Q=";
};
key "duplicate." {
  algorithm hmac-sha512;
  secret "c2Vjb25k";
};
`)

	t.Setenv("TSIG_FILE", filePath)
	t.Setenv("ALLOWED_ZONES", "example.com")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected duplicate key blocks to be accepted with last-wins, got: %v", err)
	}

	if len(cfg.TSIGs) != 1 {
		t.Fatalf("expected duplicate normalized key blocks to deduplicate to 1 entry, got %d", len(cfg.TSIGs))
	}

	entry, ok := cfg.LookupTSIG("duplicate")
	if !ok {
		t.Fatalf("expected duplicate key to be present")
	}
	if entry.Secret != "c2Vjb25k" || entry.Algorithm != "hmac-sha512" {
		t.Fatalf("expected last duplicate key block to win, got: %+v", entry)
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
