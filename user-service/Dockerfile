# Dockerfile for user-service
FROM golang:1.23.1-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Go modules and dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

RUN go build -o user-service main.go

EXPOSE 8082

CMD ["./user-service"]
