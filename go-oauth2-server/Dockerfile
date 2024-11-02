# Use the official Golang image to build the service
FROM golang:1.23.1-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the application
RUN go build -o go-oauth2-server

# Final stage: minimal image to run the app
FROM alpine:3.18

# Set environment variables if needed
ENV GIN_MODE=release

# Copy the built binary from the builder stage
COPY --from=builder /app/go-oauth2-server /usr/local/bin/go-oauth2-server

# Expose the necessary port (change this if your service uses a different port)
EXPOSE 8080

# Run the anchor service
CMD ["go-oauth2-server"]