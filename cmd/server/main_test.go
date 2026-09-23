package main

import "testing"

func TestServerAddress(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		port       int
		want       string
	}{
		{
			name:       "ipv4 any",
			listenAddr: "0.0.0.0",
			port:       5353,
			want:       "0.0.0.0:5353",
		},
		{
			name:       "localhost",
			listenAddr: "127.0.0.1",
			port:       53,
			want:       "127.0.0.1:53",
		},
		{
			name:       "hostname",
			listenAddr: "dns.internal",
			port:       8053,
			want:       "dns.internal:8053",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serverAddress(tt.listenAddr, tt.port)
			if got != tt.want {
				t.Fatalf("serverAddress(%q, %d) = %q, want %q", tt.listenAddr, tt.port, got, tt.want)
			}
		})
	}
}
