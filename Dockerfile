# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ddnsbridge4extdns ./cmd/server

# Final stage
FROM gcr.io/distroless/base-debian13:nonroot

WORKDIR /

# Copy the binary from builder
COPY --from=builder --chown=65532:65532 /app/ddnsbridge4extdns .
# Expose DNS port
EXPOSE 5353/udp 5353/tcp

# Run the server
USER 65532
ENTRYPOINT ["./ddnsbridge4extdns"]
