package handler

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/tJouve/ddnsbridge4extdns/pkg/config"
	"github.com/tJouve/ddnsbridge4extdns/pkg/k8s"
	"github.com/tJouve/ddnsbridge4extdns/pkg/update"
)

// Handler handles DNS UPDATE requests
type Handler struct {
	config    *config.Config
	k8sClient updateApplier
	parser    *update.Parser
}

type updateApplier interface {
	ApplyUpdate(remote net.Addr, tsigKey string, upd *update.DNSUpdate) (bool, error)
}

type responseTSIGSigner struct {
	keyName    string
	algorithm  string
	secret     string
	requestMAC string
}

// NewHandler creates a new DNS UPDATE handler
func NewHandler(cfg *config.Config, k8sClient *k8s.Client) *Handler {
	return &Handler{
		config:    cfg,
		k8sClient: k8sClient,
		parser:    update.NewParser(),
	}
}

// ServeDNS implements the dns.Handler interface
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	tsigPresent := r.IsTsig() != nil
	logrus.Debugf("Received message from %s: opcode=%d, hasQuestion=%d, hasTSIG=%v",
		w.RemoteAddr(), r.Opcode, len(r.Question), tsigPresent)
	// If TSIG is present, log its details
	if tsigPresent {
		tsig := r.IsTsig()
		logrus.Debugf("TSIG details: keyName=%s, algorithm=%s, timeSigned=%d, fudge=%d",
			tsig.Hdr.Name, tsig.Algorithm, tsig.TimeSigned, tsig.Fudge)
	}

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

	// Enforce TSIG presence - the DNS server handles automatic verification when TsigSecret is set
	// If the request reaches here with TSIG, it has already been verified by the server
	// We just need to ensure TSIG is present (reject requests without TSIG)
	tsigRecord := r.IsTsig()
	if tsigRecord == nil {
		logrus.Warnf("Rejected UPDATE request without TSIG from %s", w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(msg)
		return
	}

	// TSIG is present and was already verified by the DNS server
	if err := w.TsigStatus(); err != nil {
		logrus.Warnf("Rejected UPDATE request with invalid TSIG from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(msg)
		return
	}

	requestMAC := tsigRecord.MAC
	requestKey := tsigRecord.Hdr.Name
	requestAlgorithm := tsigRecord.Algorithm
	logrus.Infof("Authenticated DNS UPDATE request from %s with TSIG key %s", w.RemoteAddr(), requestKey)
	logrus.Debugf("Request authenticated with TSIG key %s using algorithm %s", requestKey, requestAlgorithm)

	responseSigner, err := h.prepareResponseTSIGSigner(requestKey, requestAlgorithm, requestMAC)
	if err != nil {
		logrus.Errorf("Failed to prepare TSIG response signing for key %q: %v", requestKey, err)
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}

	// Validate zone
	if len(r.Question) == 0 {
		logrus.Warnf("UPDATE message has no zone section from %s", w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, responseSigner)
		return
	}

	zone := r.Question[0].Name
	if !h.config.IsZoneAllowed(zone) {
		logrus.Warnf("Zone %s not allowed from %s", zone, w.RemoteAddr())
		msg.SetRcode(r, dns.RcodeRefused)
		h.writeResponse(w, msg, responseSigner)
		return
	}

	// Parse updates
	updates, err := h.parser.Parse(r)
	if err != nil {
		logrus.Errorf("Failed to parse UPDATE from %s: %v", w.RemoteAddr(), err)
		msg.SetRcode(r, dns.RcodeFormatError)
		h.writeResponse(w, msg, responseSigner)
		return
	}

	// Apply updates to Kubernetes
	for _, upd := range updates {
		logrus.Debugf("Processing update from %s: %s", w.RemoteAddr(), upd.String())
		updated, err := h.k8sClient.ApplyUpdate(w.RemoteAddr(), requestKey, upd)
		if err != nil {
			logrus.Errorf("Failed to apply update to Kubernetes: %v", err)
			msg.SetRcode(r, dns.RcodeServerFailure)
			h.writeResponse(w, msg, responseSigner)
			return
		}
		if updated {
			logrus.Infof("Successfully applied update: %s", upd.String())
		}
	}

	// Success response
	msg.SetRcode(r, dns.RcodeSuccess)
	h.writeResponse(w, msg, responseSigner)
}

// writeResponse writes a DNS response with TSIG signing if the request had TSIG
func (h *Handler) writeResponse(w dns.ResponseWriter, msg *dns.Msg, signer *responseTSIGSigner) {
	if signer == nil {
		w.WriteMsg(msg)
		return
	}

	buf, err := signer.sign(msg)
	if err != nil {
		logrus.Errorf("Failed to generate TSIG for response: %v", err)
		w.WriteMsg(msg)
		return
	}

	w.Write(buf)
}

func (h *Handler) prepareResponseTSIGSigner(requestKey, requestAlgorithm, requestMAC string) (*responseTSIGSigner, error) {
	if requestMAC == "" {
		return nil, nil
	}

	keyName, tsigSecret, ok := h.resolveResponseTSIG(requestKey)
	if !ok {
		return nil, fmt.Errorf("request key %q not configured", requestKey)
	}

	algorithm := dns.CanonicalName(strings.TrimSpace(requestAlgorithm))
	if algorithm == "" {
		return nil, fmt.Errorf("request algorithm empty for key %q", requestKey)
	}

	signer := &responseTSIGSigner{
		keyName:    keyName,
		algorithm:  algorithm,
		secret:     tsigSecret,
		requestMAC: requestMAC,
	}

	if err := signer.preflight(); err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *responseTSIGSigner) preflight() error {
	probe := new(dns.Msg)
	probe.SetTsig(s.keyName, s.algorithm, 300, 0)

	if _, _, err := dns.TsigGenerate(probe, s.secret, s.requestMAC, false); err != nil {
		return fmt.Errorf("response TSIG preflight failed: %w", err)
	}

	return nil
}

func (s *responseTSIGSigner) sign(msg *dns.Msg) ([]byte, error) {
	msg.SetTsig(s.keyName, s.algorithm, 300, 0)
	buf, _, err := dns.TsigGenerate(msg, s.secret, s.requestMAC, false)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (h *Handler) resolveResponseTSIG(requestKey string) (keyName, secret string, ok bool) {
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" {
		return "", "", false
	}

	ts, found := h.config.LookupTSIG(requestKey)
	if !found {
		return "", "", false
	}

	return ensureTrailingDot(requestKey), ts.Secret, true
}

func ensureTrailingDot(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
