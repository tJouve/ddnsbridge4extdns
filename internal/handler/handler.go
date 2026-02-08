package handler

import (
	"log"

	"github.com/miekg/dns"
	"github.com/tJouve/ddnstoextdns/pkg/config"
	"github.com/tJouve/ddnstoextdns/pkg/k8s"
	"github.com/tJouve/ddnstoextdns/pkg/tsig"
	"github.com/tJouve/ddnstoextdns/pkg/update"
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

	// Validate TSIG
	if err := h.tsig.Validate(r, ""); err != nil {
		log.Printf("TSIG validation failed from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeNotAuth)
		// Sign the response
		msg.SetTsig(h.tsig.GetKeyName(), h.tsig.GetAlgorithmName(), 300, int64(msg.MsgHdr.Id))
		w.WriteMsg(msg)
		return
	}

	// Get the request MAC for signing the response
	requestMAC := ""
	if t := r.IsTsig(); t != nil {
		requestMAC = t.MAC
	}

	// Validate zone
	if len(r.Question) == 0 {
		log.Printf("UPDATE message has no zone section from %s", w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeFormatError)
		h.signResponse(msg, requestMAC)
		w.WriteMsg(msg)
		return
	}

	zone := r.Question[0].Name
	if !h.config.IsZoneAllowed(zone) {
		log.Printf("Zone %s not allowed from %s", zone, w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeRefused)
		h.signResponse(msg, requestMAC)
		w.WriteMsg(msg)
		return
	}

	// Parse updates
	updates, err := h.parser.Parse(r)
	if err != nil {
		log.Printf("Failed to parse UPDATE from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeFormatError)
		h.signResponse(msg, requestMAC)
		w.WriteMsg(msg)
		return
	}

	// Apply updates to Kubernetes
	for _, upd := range updates {
		log.Printf("Processing update from %s: %s", w.RemoteAddr(), upd.String())

		if err := h.k8sClient.ApplyUpdate(upd); err != nil {
			log.Printf("Failed to apply update to Kubernetes: %v", err)
			msg.SetRcode(r, dns.RcodeServerFailure)
			h.signResponse(msg, requestMAC)
			w.WriteMsg(msg)
			return
		}

		log.Printf("Successfully applied update: %s", upd.String())
	}

	// Success response
	msg.SetRcode(r, dns.RcodeSuccess)
	h.signResponse(msg, requestMAC)
	w.WriteMsg(msg)
}

// signResponse signs the response with TSIG
func (h *Handler) signResponse(msg *dns.Msg, requestMAC string) {
	msg.SetTsig(h.tsig.GetKeyName(), h.tsig.GetAlgorithmName(), 300, int64(msg.MsgHdr.Id))

	// The miekg/dns library will automatically sign when WriteMsg is called
	// if the TSIG record is present
}
