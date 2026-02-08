package update

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestParseUpdate(t *testing.T) {
	parser := NewParser()

	// Create a DNS UPDATE message
	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")

	// Add an A record update
	rr, _ := dns.NewRR("test.example.com. 300 IN A 192.168.1.100")
	msg.Ns = append(msg.Ns, rr)

	updates, err := parser.Parse(msg)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if len(updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(updates))
	}

	upd := updates[0]
	if upd.Type != UpdateTypeCreate {
		t.Errorf("Expected UpdateTypeCreate, got %v", upd.Type)
	}

	if upd.RecordType != dns.TypeA {
		t.Errorf("Expected TypeA, got %d", upd.RecordType)
	}

	if upd.Name != "test.example.com." {
		t.Errorf("Expected name 'test.example.com.', got '%s'", upd.Name)
	}

	expectedIP := net.ParseIP("192.168.1.100")
	if !upd.IP.Equal(expectedIP) {
		t.Errorf("Expected IP %s, got %s", expectedIP, upd.IP)
	}

	if upd.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", upd.TTL)
	}
}

func TestParseAAAAUpdate(t *testing.T) {
	parser := NewParser()

	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")

	// Add an AAAA record update
	rr, _ := dns.NewRR("test.example.com. 300 IN AAAA 2001:db8::1")
	msg.Ns = append(msg.Ns, rr)

	updates, err := parser.Parse(msg)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if len(updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(updates))
	}

	upd := updates[0]
	if upd.RecordType != dns.TypeAAAA {
		t.Errorf("Expected TypeAAAA, got %d", upd.RecordType)
	}

	expectedIP := net.ParseIP("2001:db8::1")
	if !upd.IP.Equal(expectedIP) {
		t.Errorf("Expected IP %s, got %s", expectedIP, upd.IP)
	}
}

func TestParseDeleteUpdate(t *testing.T) {
	parser := NewParser()

	msg := new(dns.Msg)
	msg.SetUpdate("example.com.")

	// Add a delete record (class ANY, TTL 0)
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
	}
	msg.Ns = append(msg.Ns, rr)

	updates, err := parser.Parse(msg)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if len(updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(updates))
	}

	upd := updates[0]
	if upd.Type != UpdateTypeDelete {
		t.Errorf("Expected UpdateTypeDelete, got %v", upd.Type)
	}
}

func TestGetHostname(t *testing.T) {
	tests := []struct {
		name     string
		update   *DNSUpdate
		expected string
	}{
		{
			name: "subdomain",
			update: &DNSUpdate{
				Name: "test.example.com.",
				Zone: "example.com.",
			},
			expected: "test",
		},
		{
			name: "zone apex",
			update: &DNSUpdate{
				Name: "example.com.",
				Zone: "example.com.",
			},
			expected: "@",
		},
		{
			name: "deep subdomain",
			update: &DNSUpdate{
				Name: "host.sub.example.com.",
				Zone: "example.com.",
			},
			expected: "host.sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.update.GetHostname()
			if result != tt.expected {
				t.Errorf("GetHostname() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestParseNonUpdateMessage(t *testing.T) {
	parser := NewParser()

	// Create a regular query (not an UPDATE)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	_, err := parser.Parse(msg)
	if err == nil {
		t.Error("Expected error for non-UPDATE message, got nil")
	}
}

func TestParseNoZone(t *testing.T) {
	parser := NewParser()

	// Create an UPDATE message with no zone
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate},
	}

	_, err := parser.Parse(msg)
	if err == nil {
		t.Error("Expected error for message without zone, got nil")
	}
}
