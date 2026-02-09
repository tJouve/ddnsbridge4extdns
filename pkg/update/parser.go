package update

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// UpdateType represents the type of DNS update operation
type UpdateType int

const (
	UpdateTypeCreate UpdateType = iota
	UpdateTypeUpdate
	UpdateTypeDelete
)

// DNSUpdate represents a parsed DNS update for A or AAAA records
type DNSUpdate struct {
	Type       UpdateType
	RecordType uint16 // dns.TypeA or dns.TypeAAAA
	Name       string
	Zone       string
	IP         net.IP
	TTL        uint32
}

// Parser parses DNS UPDATE messages
type Parser struct{}

// NewParser creates a new DNS UPDATE parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a DNS UPDATE message and extracts A/AAAA record changes
func (p *Parser) Parse(msg *dns.Msg) ([]*DNSUpdate, error) {
	if msg.Opcode != dns.OpcodeUpdate {
		return nil, fmt.Errorf("not a DNS UPDATE message (opcode: %d)", msg.Opcode)
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("UPDATE message has no zone section")
	}

	zone := msg.Question[0].Name
	updates := make([]*DNSUpdate, 0)

	// Process the update section (actual updates from Ns section)
	for _, rr := range msg.Ns {
		update, err := p.parseRR(rr, zone)
		if err != nil {
			// Skip non-A/AAAA records silently
			continue
		}
		if update != nil {
			updates = append(updates, update)
		}
	}

	if len(updates) == 0 {
		return nil, fmt.Errorf("no valid A or AAAA updates found in message")
	}

	return updates, nil
}

// parseRR parses a single resource record from the update section
func (p *Parser) parseRR(rr dns.RR, zone string) (*DNSUpdate, error) {
	header := rr.Header()

	update := &DNSUpdate{
		Name: header.Name,
		Zone: zone,
		TTL:  header.Ttl,
	}

	// Determine update type based on class and TTL
	switch header.Class {
	case dns.ClassANY:
		// Class ANY with TTL 0 means delete
		update.Type = UpdateTypeDelete
		update.RecordType = header.Rrtype

	case dns.ClassNONE:
		// Class NONE means delete specific record
		update.Type = UpdateTypeDelete
		update.RecordType = header.Rrtype

	case dns.ClassINET:
		// Class IN means add/update
		if header.Ttl == 0 {
			update.Type = UpdateTypeDelete
		} else {
			// We treat both create and update the same way
			update.Type = UpdateTypeCreate
		}
		update.RecordType = header.Rrtype
	default:
		return nil, fmt.Errorf("unsupported class: %d", header.Class)
	}

	// Extract IP address for A/AAAA records
	switch header.Rrtype {
	case dns.TypeA:
		if a, ok := rr.(*dns.A); ok {
			update.IP = a.A
		} else if update.Type != UpdateTypeDelete {
			return nil, fmt.Errorf("invalid A record")
		}

	case dns.TypeAAAA:
		if aaaa, ok := rr.(*dns.AAAA); ok {
			update.IP = aaaa.AAAA
		} else if update.Type != UpdateTypeDelete {
			return nil, fmt.Errorf("invalid AAAA record")
		}

	default:
		// Skip other record types
		return nil, nil
	}

	return update, nil
}

// String returns a string representation of the update
func (u *DNSUpdate) String() string {
	var typeStr string
	switch u.Type {
	case UpdateTypeCreate:
		typeStr = "CREATE"
	case UpdateTypeUpdate:
		typeStr = "UPDATE"
	case UpdateTypeDelete:
		typeStr = "DELETE"
	}

	var recordTypeStr string
	switch u.RecordType {
	case dns.TypeA:
		recordTypeStr = "A"
	case dns.TypeAAAA:
		recordTypeStr = "AAAA"
	}

	if u.IP != nil {
		msg := fmt.Sprintf("%s %s %s -> %s (TTL: %d)", typeStr, recordTypeStr, u.Name, u.IP.String(), u.TTL)
		logrus.Debugf("Parsed DNS update: %s", msg)
		return msg
	}
	msg := fmt.Sprintf("%s %s %s", typeStr, recordTypeStr, u.Name)
	logrus.Debugf("Parsed DNS update: %s", msg)
	return msg
}

// GetHostname returns the hostname without the zone suffix
func (u *DNSUpdate) GetHostname() string {
	name := strings.TrimSuffix(u.Name, ".")
	zone := strings.TrimSuffix(u.Zone, ".")

	if strings.HasSuffix(name, "."+zone) {
		return strings.TrimSuffix(name, "."+zone)
	}
	if name == zone {
		return "@"
	}
	return name
}
