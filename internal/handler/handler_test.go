package handler

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/tJouve/ddnsbridge4extdns/pkg/config"
	"github.com/tJouve/ddnsbridge4extdns/pkg/update"
)

type fakeUpdateApplier struct {
	applyCount    int
	updated       bool
	err           error
	lastRemote    net.Addr
	lastTSIGKey   string
	lastDNSUpdate *update.DNSUpdate
}

func (f *fakeUpdateApplier) ApplyUpdate(remote net.Addr, tsigKey string, upd *update.DNSUpdate) (bool, error) {
	f.applyCount++
	f.lastRemote = remote
	f.lastTSIGKey = tsigKey
	f.lastDNSUpdate = upd
	return f.updated, f.err
}

func TestResolveResponseTSIG(t *testing.T) {
	h := &Handler{
		config: &config.Config{
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
				{Key: "client2.", Secret: "Y2xpZW50Mg==", Algorithm: "hmac-sha512"},
			},
		},
	}

	keyName, secret, ok := h.resolveResponseTSIG("client2")
	if !ok {
		t.Fatalf("expected TSIG key to be resolved")
	}
	if keyName != "client2." {
		t.Fatalf("expected keyName client2., got %q", keyName)
	}
	if secret != "Y2xpZW50Mg==" {
		t.Fatalf("unexpected secret for client2")
	}

	if _, _, ok := h.resolveResponseTSIG("missing"); ok {
		t.Fatalf("expected missing key resolution to fail")
	}
}

func TestWriteResponseUsesRequestAlgorithmAndMatchingKeySecret(t *testing.T) {
	h := &Handler{
		config: &config.Config{
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
				// Deliberately different from request algorithm to assert request-algorithm behavior.
				{Key: "client2", Secret: "Y2xpZW50Mg==", Algorithm: "hmac-sha256"},
			},
		},
	}

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeSOA)
	request.SetTsig("client2.", dns.HmacSHA512, 300, 0)
	_, requestMAC, err := dns.TsigGenerate(request, "Y2xpZW50Mg==", "", false)
	if err != nil {
		t.Fatalf("failed to generate request TSIG: %v", err)
	}

	response := new(dns.Msg)
	response.SetReply(request)
	signer, err := h.prepareResponseTSIGSigner("client2", dns.HmacSHA512, requestMAC)
	if err != nil {
		t.Fatalf("failed to prepare response signer: %v", err)
	}

	w := &captureResponseWriter{}
	h.writeResponse(w, response, signer)

	if len(w.buf) == 0 {
		t.Fatalf("expected raw signed response to be written")
	}
	if w.msg != nil {
		t.Fatalf("expected signed raw response path, got WriteMsg fallback")
	}
	if w.writeRawCount != 1 {
		t.Fatalf("expected raw write count 1, got %d", w.writeRawCount)
	}
	if w.writeMsgCount != 0 {
		t.Fatalf("expected no WriteMsg call in signed path, got %d", w.writeMsgCount)
	}

	verifyBuf := append([]byte(nil), w.buf...)
	if err := dns.TsigVerify(verifyBuf, "Y2xpZW50Mg==", requestMAC, false); err != nil {
		t.Fatalf("response TSIG verification failed: %v", err)
	}

	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(w.buf); err != nil {
		t.Fatalf("failed to unpack signed response: %v", err)
	}

	ts := unpacked.IsTsig()
	if ts == nil {
		t.Fatalf("expected TSIG in response")
	}
	if ts.Hdr.Name != "client2." {
		t.Fatalf("expected response signed with request key client2., got %q", ts.Hdr.Name)
	}
	if ts.Algorithm != dns.HmacSHA512 {
		t.Fatalf("expected response algorithm %q, got %q", dns.HmacSHA512, ts.Algorithm)
	}
}

func TestServeDNSResponseTSIGPreflightFailureSkipsMutation(t *testing.T) {
	fakeK8s := &fakeUpdateApplier{}
	h := &Handler{
		config: &config.Config{
			AllowedZones: []string{"example.com"},
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "bad-secret", Algorithm: "hmac-sha256"},
			},
		},
		k8sClient: fakeK8s,
		parser:    update.NewParser(),
	}

	req := new(dns.Msg)
	req.SetUpdate("example.com.")
	rr, err := dns.NewRR("host.example.com. 300 IN A 192.168.1.10")
	if err != nil {
		t.Fatalf("failed to build RR: %v", err)
	}
	req.Ns = append(req.Ns, rr)
	req.SetTsig("client1.", dns.HmacSHA256, 300, 0)
	signedReq, _, err := signRequestMessage(req, "Y2xpZW50MQ==")
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := &captureResponseWriter{}
	h.ServeDNS(w, signedReq)

	if fakeK8s.applyCount != 0 {
		t.Fatalf("expected no Kubernetes mutation on response TSIG preflight failure, got %d", fakeK8s.applyCount)
	}
	if w.writeMsgCount != 1 {
		t.Fatalf("expected unsigned WriteMsg response, got %d", w.writeMsgCount)
	}
	if w.writeRawCount != 0 {
		t.Fatalf("expected no raw signed write on preflight failure, got %d", w.writeRawCount)
	}
	if w.msg == nil {
		t.Fatalf("expected DNS response message")
	}
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got %d", w.msg.Rcode)
	}
	if w.msg.IsTsig() != nil {
		t.Fatalf("expected unsigned response on preflight failure")
	}
}

func TestServeDNSValidPathMutatesAndSignsResponse(t *testing.T) {
	fakeK8s := &fakeUpdateApplier{updated: true}
	h := &Handler{
		config: &config.Config{
			AllowedZones: []string{"example.com"},
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
			},
		},
		k8sClient: fakeK8s,
		parser:    update.NewParser(),
	}

	req := new(dns.Msg)
	req.SetUpdate("example.com.")
	rr, err := dns.NewRR("host.example.com. 300 IN A 192.168.1.10")
	if err != nil {
		t.Fatalf("failed to build RR: %v", err)
	}
	req.Ns = append(req.Ns, rr)
	req.SetTsig("client1.", dns.HmacSHA256, 300, 0)
	signedReq, requestMAC, err := signRequestMessage(req, "Y2xpZW50MQ==")
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := &captureResponseWriter{}
	h.ServeDNS(w, signedReq)

	if fakeK8s.applyCount != 1 {
		t.Fatalf("expected one Kubernetes mutation, got %d", fakeK8s.applyCount)
	}
	if fakeK8s.lastTSIGKey != "client1." {
		t.Fatalf("expected propagated TSIG key client1., got %q", fakeK8s.lastTSIGKey)
	}
	if w.writeRawCount != 1 {
		t.Fatalf("expected signed raw response write, got %d", w.writeRawCount)
	}
	if w.writeMsgCount != 0 {
		t.Fatalf("expected no unsigned WriteMsg fallback, got %d", w.writeMsgCount)
	}

	verifyBuf := append([]byte(nil), w.buf...)
	if err := dns.TsigVerify(verifyBuf, "Y2xpZW50MQ==", requestMAC, false); err != nil {
		t.Fatalf("response TSIG verification failed: %v", err)
	}

	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(w.buf); err != nil {
		t.Fatalf("failed to unpack signed response: %v", err)
	}
	if unpacked.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR response, got %d", unpacked.Rcode)
	}
}

func TestServeDNSRejectsInvalidTSIGStatusBeforeMutationPath(t *testing.T) {
	h := &Handler{
		config: &config.Config{
			AllowedZones: []string{"example.com"},
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
			},
		},
		k8sClient: nil,
		parser:    update.NewParser(),
	}

	req := new(dns.Msg)
	req.SetUpdate("example.com.")
	rr, err := dns.NewRR("host.example.com. 300 IN A 192.168.1.10")
	if err != nil {
		t.Fatalf("failed to build RR: %v", err)
	}
	req.Ns = append(req.Ns, rr)
	req.SetTsig("client1.", dns.HmacSHA256, 300, 0)

	w := &captureResponseWriter{tsigStatusErr: errors.New("bad tsig")}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ServeDNS panicked; expected early TSIG-status rejection: %v", r)
		}
	}()

	h.ServeDNS(w, req)

	if w.writeMsgCount != 1 {
		t.Fatalf("expected 1 WriteMsg call, got %d", w.writeMsgCount)
	}
	if w.writeRawCount != 0 {
		t.Fatalf("expected no raw signed write on invalid TSIG, got %d", w.writeRawCount)
	}
	if w.msg == nil {
		t.Fatalf("expected DNS response message")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED rcode, got %d", w.msg.Rcode)
	}
	if w.msg.IsTsig() != nil {
		t.Fatalf("expected unsigned response on invalid request TSIG status")
	}
}

func TestServeDNSChecksTSIGStatusBeforeZoneParse(t *testing.T) {
	h := &Handler{
		config: &config.Config{
			AllowedZones: []string{"example.com"},
			TSIGs: []config.TSIGEntry{
				{Key: "client1", Secret: "Y2xpZW50MQ==", Algorithm: "hmac-sha256"},
			},
		},
		parser: update.NewParser(),
	}

	req := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate}}
	req.SetTsig("client1.", dns.HmacSHA256, 300, 0)

	w := &captureResponseWriter{tsigStatusErr: errors.New("bad tsig")}
	h.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatalf("expected DNS response message")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED rcode before zone parsing, got %d", w.msg.Rcode)
	}
}

type captureResponseWriter struct {
	buf           []byte
	msg           *dns.Msg
	tsigStatusErr error
	writeMsgCount int
	writeRawCount int
}

func (w *captureResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *captureResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (w *captureResponseWriter) Close() error         { return nil }
func (w *captureResponseWriter) TsigStatus() error    { return w.tsigStatusErr }
func (w *captureResponseWriter) TsigTimersOnly(bool)  {}
func (w *captureResponseWriter) Hijack()              {}
func (w *captureResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	w.writeMsgCount++
	return nil
}
func (w *captureResponseWriter) Write(buf []byte) (int, error) {
	w.buf = append([]byte(nil), buf...)
	w.writeRawCount++
	return len(buf), nil
}

func signRequestMessage(req *dns.Msg, secret string) (*dns.Msg, string, error) {
	buf, requestMAC, err := dns.TsigGenerate(req, secret, "", false)
	if err != nil {
		return nil, "", err
	}
	signedReq := new(dns.Msg)
	if err := signedReq.Unpack(buf); err != nil {
		return nil, "", err
	}
	return signedReq, requestMAC, nil
}
