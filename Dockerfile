# Build stage: use Alpine-based Golang image and install CA certificates.
FROM golang:1.23.1-alpine AS builder

# Install CA certificates.
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy go.mod and go.sum and download dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code.
COPY . .

# Build a fully static binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o rapid7exporter .

# Final stage: create a minimal image from scratch.
FROM scratch

# Copy CA certificates from the builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from the builder.
COPY --from=builder /app/rapid7exporter /rapid7exporter

# Expose the port that the app listens on.
EXPOSE 9090

# Set the entrypoint.
ENTRYPOINT ["/rapid7exporter"]
