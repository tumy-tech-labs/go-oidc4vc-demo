# go-oidc-server

The Authorization Server is an implementation of an OAuth 2.0 authorization service in Go. It allows users to authenticate and authorize access to resources using access tokens. This project also supports the issuance of verifiable credentials (VCs) in compliance with the W3C DID standards.

## Features

- OAuth 2.0 Authorization Code Flow
- JWT-based Access Token generation and validation
- User login and authentication
- Verifiable Credential issuance
- DID creation for both issuer and subject, in compliance with W3C DID standards

## Prerequisites

- Go 1.15+
- github.com/dgrijalva/jwt-go for JWT token management
- github.com/gorilla/mux for HTTP request routing
- github.com/google/uuid for UUID generation

Install dependencies:

```bash
go get github.com/dgrijalva/jwt-go
go get github.com/gorilla/mux
go get github.com/google/uuid
```

## Getting Started

Clone the repository

```bash
git clone https://github.com/tumy-tech-labs/go-oauth2-server
cd go-oauth2-server
```

Run the server

```bash
go run main.go

```

Server will start on port 9090:

```bash
Starting server on :9090
```

## API Endpoints

### POST /login

Authenticate users and receive an access token.

#### Requst

```json
{
  "username": "user",
  "password": "password"
}
```

#### Response

```json
{
  "access_token": "<token>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### GET /authorize

Starts the authorization flow, generating an authorization code for the client.

#### Parameters

**client_id** - The client ID requesting authorization

**response_type** - Must be set to code

**redirect_uri** - The URI to redirect the user to after authorization

**scope** - Optional, requested permissions scope

### POST /token

Exchange an authorization code for an access token.

#### Request

```json
{
  "code": "<authorization_code>",
  "client_id": "<client_id>",
  "redirect_uri": "<redirect_uri>"
}
```

#### Response

```json
{
  "code": "<authorization_code>",
  "client_id": "<client_id>",
  "redirect_uri": "<redirect_uri>"
}
```

### GET /request-credential

Issue a verifiable credential for an authenticated user.

Headers:
Authorization: Bearer <access_token>

#### Response

```json
{
  "id": "uuid-generated-credential-id",
  "type": ["VerifiableCredential"],
  "issuer": {
    "id": "did:example:issuer-id"
  },
  "credentialSubject": {
    "id": "did:example:subject-id",
    "user_id": "<user_id>"
  },
  "issued_at": "2024-11-02T10:00:00Z",
  "expires_at": "2024-11-03T10:00:00Z"
}
```

### Code Overview

#### Token Generation and Validation

- The generateAccessToken function creates a signed JWT token using a shared secret.
- The verifyAccessToken function validates the token against the same secret.

#### DID and Verifiable Credential Generation

The DID and verifiable credential generation process follows W3C standards, assigning a unique DID to both the issuer and the subject.

### Example Flow

- Login - The user logs in via /login and receives an access token.
- Authorization - A client application requests authorization for a user, obtaining an authorization code.
- Token Exchange - The client exchanges the authorization code for an access token via /token.
- Credential Request - The client application requests a verifiable credential on behalf of the user by including the access token in the /request-credential request.

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
