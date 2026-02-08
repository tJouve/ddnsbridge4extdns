package tsig

import (
	"fmt"

	"github.com/miekg/dns"
)

// Validator validates TSIG signatures on DNS messages
type Validator struct {
	keyName   string
	secret    string
	algorithm string
}

// NewValidator creates a new TSIG validator
func NewValidator(keyName, secret, algorithm string) *Validator {
	return &Validator{
		keyName:   keyName,
		secret:    secret,
		algorithm: algorithm,
	}
}

// Validate validates the TSIG signature on a DNS message
func (v *Validator) Validate(msg *dns.Msg, requestMAC string) error {
	if msg.IsTsig() == nil {
		return fmt.Errorf("message does not contain TSIG record")
	}

	tsig := msg.IsTsig()

	// Check if the key name matches
	if tsig.Hdr.Name != v.keyName+"." && tsig.Hdr.Name != v.keyName {
		return fmt.Errorf("TSIG key name mismatch: expected %s, got %s", v.keyName, tsig.Hdr.Name)
	}

	// Validate the algorithm
	expectedAlg := v.getAlgorithmName()
	if tsig.Algorithm != expectedAlg {
		return fmt.Errorf("TSIG algorithm mismatch: expected %s, got %s", expectedAlg, tsig.Algorithm)
	}

	// Verify the TSIG signature using dns.TsigVerify
	buf, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack message: %w", err)
	}

	if err := dns.TsigVerify(buf, v.secret, requestMAC, false); err != nil {
		return fmt.Errorf("TSIG verification failed: %w", err)
	}

	return nil
}

// Sign signs a DNS message with TSIG
func (v *Validator) Sign(msg *dns.Msg, requestMAC string) (*dns.Msg, string, error) {
	msg.SetTsig(v.keyName, v.getAlgorithmName(), 300, int64(msg.MsgHdr.Id))

	// Generate TSIG
	buf, mac, err := dns.TsigGenerate(msg, v.secret, requestMAC, false)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TSIG: %w", err)
	}

	// Unpack the signed message back
	signedMsg := new(dns.Msg)
	if err := signedMsg.Unpack(buf); err != nil {
		return nil, "", fmt.Errorf("failed to unpack signed message: %w", err)
	}

	return signedMsg, mac, nil
}

// getAlgorithmName returns the DNS algorithm name for the configured algorithm
func (v *Validator) getAlgorithmName() string {
	switch v.algorithm {
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-sha256":
		return dns.HmacSHA256
	case "hmac-sha512":
		return dns.HmacSHA512
	case "hmac-md5":
		return dns.HmacMD5
	default:
		return dns.HmacSHA256
	}
}

// GetKeyName returns the TSIG key name
func (v *Validator) GetKeyName() string {
	return v.keyName
}

// GetAlgorithmName returns the DNS algorithm name (exposed for handler)
func (v *Validator) GetAlgorithmName() string {
	return v.getAlgorithmName()
}
