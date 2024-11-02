# Base image
FROM golang:1.23.1-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Go modules and dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN go build -o go-oidc-client main.go

# Expose the port that the client will run on
EXPOSE 8080

# Set environment variables (these can be overridden in docker-compose.yml)
ENV CLIENT_ID="client_id"
ENV CLIENT_SECRET="client_secret"
ENV REDIRECT_URI="http://localhost:8080/callback"
ENV AUTH_ENDPOINT="http://auth-server:8080/auth"
ENV TOKEN_ENDPOINT="http://auth-server:8080/token"

# Command to run the client application
CMD ["./go-oidc-client"]
