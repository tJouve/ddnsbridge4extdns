package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/tJouve/ddnsbridge4extdns/internal/handler"
	"github.com/tJouve/ddnsbridge4extdns/pkg/config"
	"github.com/tJouve/ddnsbridge4extdns/pkg/k8s"
	"github.com/tJouve/ddnsbridge4extdns/pkg/tsig"
)

func main() {
	// Load configuration first
	cfg, err := config.LoadConfig()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logrus with configured log level
	level, err := logrus.ParseLevel(strings.ToLower(cfg.LogLevel))
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceColors:     true,
	})

	logrus.Println("Starting ddnsbridge4extdns - RFC2136 DNS UPDATE server for Kubernetes ExternalDNS")
	logrus.Infof("Log level set to: %s", level.String())

	logrus.Infof("Configuration loaded: listening on %s:%d", cfg.ListenAddr, cfg.Port)
	logrus.Debugf("Allowed zones: %v", cfg.AllowedZones)
	logrus.Debugf("TSIG key: %s, algorithm: %s", cfg.TSIGKey, cfg.TSIGAlgorithm)
	logrus.Debugf("Kubernetes namespace: %s", cfg.Namespace)

	// Initialize TSIG validator
	tsigValidator := tsig.NewValidator(cfg.TSIGKey, cfg.TSIGSecret, cfg.TSIGAlgorithm)
	logrus.Debugf("TSIG validator initialized")

	// Initialize Kubernetes client
	k8sClient, err := k8s.NewClient(cfg.Namespace, cfg.CustomLabels)
	if err != nil {
		logrus.Fatalf("Failed to initialize Kubernetes client: %v", err)
	}
	logrus.Debugf("Kubernetes client initialized")
	if len(cfg.CustomLabels) > 0 {
		logrus.Debugf("Custom labels configured: %v", cfg.CustomLabels)
	}

	// Create DNS handler
	dnsHandler := handler.NewHandler(cfg, tsigValidator, k8sClient)

	// Create DNS server for UDP and TCP
	// Set TsigSecret on the server - this is required for TSIG to work properly
	// The server will handle TSIG verification automatically before calling the handler
	serverAddr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port)

	// TSIG secret map - include both with and without trailing dot
	tsigSecret := map[string]string{
		cfg.TSIGKey:       cfg.TSIGSecret,
		cfg.TSIGKey + ".": cfg.TSIGSecret,
	}

	// Custom MsgAcceptFunc: accept queries, notifies and UPDATE opcodes; ignore responses; reject others
	msgAccept := func(dh dns.Header) dns.MsgAcceptAction {
		// QR flag (response) is the most significant bit (1<<15 == 0x8000)
		if dh.Bits&0x8000 != 0 { // is a response
			return dns.MsgIgnore
		}
		opcode := int((dh.Bits >> 11) & 0xF)
		if opcode == dns.OpcodeQuery || opcode == dns.OpcodeNotify || opcode == dns.OpcodeUpdate {
			return dns.MsgAccept
		}
		return dns.MsgRejectNotImplemented
	}

	udpServer := &dns.Server{
		Addr:          serverAddr,
		Net:           "udp",
		Handler:       dnsHandler,
		TsigSecret:    tsigSecret,
		MsgAcceptFunc: msgAccept,
	}

	tcpServer := &dns.Server{
		Addr:          serverAddr,
		Net:           "tcp",
		Handler:       dnsHandler,
		TsigSecret:    tsigSecret,
		MsgAcceptFunc: msgAccept,
	}

	// Start UDP server
	go func() {
		logrus.Infof("Starting UDP server on %s", serverAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			logrus.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	// Start TCP server
	go func() {
		logrus.Infof("Starting TCP server on %s", serverAddr)
		if err := tcpServer.ListenAndServe(); err != nil {
			logrus.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	logrus.Println("DNS UPDATE server started successfully")

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	logrus.Println("Shutting down servers...")
	udpServer.Shutdown()
	tcpServer.Shutdown()
	logrus.Println("Servers stopped")
}
