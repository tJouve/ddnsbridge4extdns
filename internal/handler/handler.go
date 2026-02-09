package handler

import (
	"log"

	"github.com/miekg/dns"
	"github.com/tJouve/ddnsbridge4extdns/pkg/config"
	"github.com/tJouve/ddnsbridge4extdns/pkg/k8s"
	"github.com/tJouve/ddnsbridge4extdns/pkg/tsig"
	"github.com/tJouve/ddnsbridge4extdns/pkg/update"
)

// Handler handles DNS UPDATE requests
type Handler struct {
	config    *config.Config
	tsig      *tsig.Validator
	k8sClient *k8s.Client
	parser    *update.Parser
}

// NewHandler creates a new DNS UPDATE handler
func NewHandler(cfg *config.Config, tsigValidator *tsig.Validator, k8sClient *k8s.Client) *Handler {
	return &Handler{
		config:    cfg,
		tsig:      tsigValidator,
		k8sClient: k8sClient,
		parser:    update.NewParser(),
	}
}

// ServeDNS implements the dns.Handler interface
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Printf("=== ServeDNS CALLED === from %s", w.RemoteAddr())
	log.Printf("Received message from %s: opcode=%d, hasQuestion=%d, hasTSIG=%v",
		w.RemoteAddr(), r.Opcode, len(r.Question), r.IsTsig() != nil)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Only process UPDATE opcodes
	if r.Opcode != dns.OpcodeUpdate {
		log.Printf("Rejected non-UPDATE request (opcode: %d) from %s", r.Opcode, w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(msg)
		return
	}

	// Note: TSIG validation is handled automatically by the server when TsigSecret is set
	// If the request reaches this handler, TSIG has already been validated (if present)

	// Get the request MAC for response signing (if TSIG was present)
	requestMAC := ""
	if t := r.IsTsig(); t != nil {
		requestMAC = t.MAC
		log.Printf("Request has TSIG from key: %s", t.Hdr.Name)
	}

	// Validate zone
	if len(r.Question) == 0 {
		log.Printf("UPDATE message has no zone section from %s", w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	zone := r.Question[0].Name
	if !h.config.IsZoneAllowed(zone) {
		log.Printf("Zone %s not allowed from %s", zone, w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeRefused)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	// Parse updates
	updates, err := h.parser.Parse(r)
	if err != nil {
		log.Printf("Failed to parse UPDATE from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	// Apply updates to Kubernetes
	for _, upd := range updates {
		log.Printf("Processing update from %s: %s", w.RemoteAddr(), upd.String())

		if err := h.k8sClient.ApplyUpdate(upd); err != nil {
			log.Printf("Failed to apply update to Kubernetes: %v", err)
			msg.SetRcode(r, dns.RcodeServerFailure)
			h.writeResponse(w, msg, requestMAC)
			return
		}

		log.Printf("Successfully applied update: %s", upd.String())
	}

	// Success response
	msg.SetRcode(r, dns.RcodeSuccess)
	h.writeResponse(w, msg, requestMAC)
}

// writeResponse writes a DNS response
// When TsigSecret is set on the server, it automatically handles TSIG signing
func (h *Handler) writeResponse(w dns.ResponseWriter, msg *dns.Msg, requestMAC string) {
	w.WriteMsg(msg)
}
