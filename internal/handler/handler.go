package handler

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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
	logrus.Debugf("Received message from %s: opcode=%d, hasQuestion=%d, hasTSIG=%v",
		w.RemoteAddr(), r.Opcode, len(r.Question), r.IsTsig() != nil)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Only process UPDATE opcodes
	if r.Opcode != dns.OpcodeUpdate {
		logrus.Warnf("Rejected non-UPDATE request (opcode: %d) from %s", r.Opcode, w.RemoteAddr())
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
		logrus.Debugf("Request has TSIG from key: %s", t.Hdr.Name)
	}

	// Validate zone
	if len(r.Question) == 0 {
		logrus.Warnf("UPDATE message has no zone section from %s", w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	zone := r.Question[0].Name
	if !h.config.IsZoneAllowed(zone) {
		logrus.Warnf("Zone %s not allowed from %s", zone, w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeRefused)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	// Parse updates
	updates, err := h.parser.Parse(r)
	if err != nil {
		logrus.Errorf("Failed to parse UPDATE from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, requestMAC)
		return
	}

	// Apply updates to Kubernetes
	for _, upd := range updates {
		logrus.Infof("Processing update from %s: %s", w.RemoteAddr(), upd.String())

		if err := h.k8sClient.ApplyUpdate(w.RemoteAddr(), upd); err != nil {
			logrus.Errorf("Failed to apply update to Kubernetes: %v", err)
			msg.SetRcode(r, dns.RcodeServerFailure)
			h.writeResponse(w, msg, requestMAC)
			return
		}

		logrus.Infof("Successfully applied update: %s", upd.String())
	}

	// Success response
	msg.SetRcode(r, dns.RcodeSuccess)
	h.writeResponse(w, msg, requestMAC)
}

// writeResponse writes a DNS response with TSIG signing if the request had TSIG
func (h *Handler) writeResponse(w dns.ResponseWriter, msg *dns.Msg, requestMAC string) {
	// If the request had TSIG, we need to sign the response
	if requestMAC != "" {
		// Add TSIG to the response
		// The key name should end with a dot (FQDN)
		keyName := h.config.TSIGKey
		if keyName[len(keyName)-1] != '.' {
			keyName = keyName + "."
		}

		// Get the algorithm in FQDN format
		algorithm := h.tsig.GetAlgorithmName()

		// Set TSIG parameters on the message
		msg.SetTsig(keyName, algorithm, 300, 0)

		// Sign the message using the request MAC for chaining
		// dns.TsigGenerate returns the packed signed message
		buf, _, err := dns.TsigGenerate(msg, h.config.TSIGSecret, requestMAC, false)
		if err != nil {
			logrus.Errorf("Failed to generate TSIG for response: %v", err)
			w.WriteMsg(msg)
			return
		}

		// Write the signed response directly
		w.Write(buf)
		return
	}

	w.WriteMsg(msg)
}
