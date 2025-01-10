# Stage 1: Build the Go app with CGO_ENABLED=1 and x86_64 (amd64)
FROM --platform=linux/amd64 golang:1.23-alpine AS builder

# Set up environment
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

# Install required build tools and SQLite dependencies
RUN apk add --no-cache musl-dev sqlite-dev gcc g++ make git libc6-compat binutils wget

# Install glibc for full compatibility (Build stage)
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r0/glibc-2.35-r0.apk && \
    apk add --force-overwrite glibc-2.35-r0.apk && \
    rm -rf glibc-2.35-r0.apk /etc/apk/keys/sgerrand.rsa.pub

# Set the working directory inside the container
WORKDIR /app

# Copy Go modules and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

RUN gcc --version

# Build the application explicitly for CGO and x86_64
RUN CC="gcc" go build -o securemessages-app -ldflags "-s -w" ./cmd/securemessages/main.go

# Stage 2: Create the minimal runtime container
FROM alpine:3.18

# Install runtime dependencies and glibc again in final stage
RUN apk add --no-cache bash ca-certificates tzdata gettext sqlite-libs wget bash

# Install glibc for runtime compatibility
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r0/glibc-2.35-r0.apk && \
    apk add --force-overwrite glibc-2.35-r0.apk && \
    rm -rf glibc-2.35-r0.apk /etc/apk/keys/sgerrand.rsa.pub

# Create a non-root user and group named 'appuser'
RUN addgroup -S --gid 1001 appuser && adduser -S --uid 1001 appuser -G appuser

# Set working directory in the runtime container
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/securemessages-app .

# Copy templates and static files from project root
COPY templates ./templates
COPY assets ./assets

# Ensure the appuser owns these files
RUN chown -R appuser:appuser /app

USER appuser

# Expose the application port (matches the PORT env if set, otherwise app defaults)
EXPOSE 9203

# By default, just run the application directly
CMD ["./securemessages-app"]
