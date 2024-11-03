package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Use a secure key in production
var jwtSecret = []byte("your_secure_secret_key") // Replace with a more secure value

// User represents the structure for user login credentials
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthCode represents the structure of an authorization code
type AuthCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	ExpiresAt   time.Time
}

// Mock user database (replace this with your actual user management)
var users = map[string]string{
	"bob": "password123", // Example username and password
}

// generateUUID generates a new UUID and returns it as a string.
func generateUUID() string {
	newUUID := uuid.New()
	return newUUID.String()
}

// GenerateAuthCode generates a secure random authorization code
func GenerateAuthCode(clientID string, userID string, redirectURI string) (*AuthCode, error) {
	// Generate a random 32-byte slice
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	// Encode to base64 and strip out any URL-unsafe characters
	authCode := base64.RawURLEncoding.EncodeToString(b)

	// Set expiration time (e.g., 10 minutes from now)
	expiration := time.Now().Add(10 * time.Minute)

	return &AuthCode{
		Code:        authCode,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		ExpiresAt:   expiration,
	}, nil
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/authorize", authorizeHandler).Methods("GET")
	r.HandleFunc("/callback", handleCallback).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/credential", RequestCredentialHandler).Methods("POST") // New endpoint for requesting credentials
	r.HandleFunc("/token", tokenHandler).Methods("POST")

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// Authorization handler for the /authorize endpoint
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	//log.Println("Received /authorize request")

	// Extract parameters from the request
	clientID := r.URL.Query().Get("client_id")
	responseType := r.URL.Query().Get("response_type")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	//state := r.URL.Query().Get("state")

	// Validate the request parameters
	if clientID == "" || responseType != "code" || redirectURI == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// TODO: Check if client ID is valid and redirect URI is registered
	// Simulate user consent (for now, redirect with a sample auth code)
	// Generate an authorization code

	userID := "Bob"

	// Generate an authorization code
	authCode, err := GenerateAuthCode(clientID, userID, "http://localhost:8080/callback")
	if err != nil {
		http.Error(w, "Error generating authorization code", http.StatusInternalServerError)
		return
	}
	// Redirect to the redirect URI with the authorization code
	redirectURI = fmt.Sprintf("%s?code=%s", authCode.RedirectURI, url.QueryEscape(authCode.Code))

	// If scope is used, you could append it to the redirect URL or log it
	if scope != "" {
		redirectURI += "&scope=" + url.QueryEscape(scope)
		//log.Printf("Scope requested: %s", scope)
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// Handle the callback from the authorization server
func handleCallback(w http.ResponseWriter, r *http.Request) {
	//log.Println("Received /callback request")

	// Retrieve the authorization code from the query
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	// Validate the state parameter
	expectedState := "expected_state_value" // Replace this with your actual expected state value
	if state != expectedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Simulate exchanging the authorization code for an access token

	userID := "Bob"

	accessToken, err := generateAccessToken(userID) // In a real scenario, generate and return a real token
	if err != nil {
		log.Println("Error generating Access Token")
	}

	// Respond with the access token (or redirect, etc.)
	w.Write([]byte(fmt.Sprintf("Access Token: %s\n", accessToken)))
}

// Add a new function to handle token requests
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	//log.Println("Received /token request")

	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")

	// Validate the authorization code and client ID
	if code == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Here you would check if the code is valid, match it with the stored values, etc.
	// For this example, we'll simulate it by directly generating an access token.

	// Generate a sample access token
	userID := "Bob"
	accessToken, err := generateAccessToken(userID)

	if err != nil {
		log.Println("There was an error generating the Access Token::", err)
	}

	// Respond with the access token in JSON format
	tokenResponse := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600, // token expiration time in seconds
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)
}

// Generate a JWT access token
func generateAccessToken(userID string) (string, error) {

	// Create the claims
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 1).Unix(), // Token valid for 1 hour
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with our secret
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Login handler to authenticate users and issue access tokens
func loginHandler(w http.ResponseWriter, r *http.Request) {
	//log.Println("Received /login request")

	// Parse the request body for username and password
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate user credentials
	storedPassword, ok := users[user.Username]
	if !ok || storedPassword != user.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate an access token for the authenticated user
	accessToken, err := generateAccessToken(user.Username)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	// Respond with the access token
	response := map[string]string{"access_token": accessToken}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RequestCredentialHandler handles the request for a verifiable credential
func RequestCredentialHandler(w http.ResponseWriter, r *http.Request) {

	// Get the token from the Authorization header
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		return
	}

	// Extract the token from the Authorization header
	tokenString := authHeader[len("Bearer "):]

	// Verify the access token
	userID, err := verifyAccessToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Create a unique ID for the credential (this could be a UUID or similar)
	credentialID := fmt.Sprintf("urn:uuid:%s", generateUUID())
	userDID := "did:example:123456789"    // Replace with the actual user's DID
	issuerDID := "did:example:issuer1234" // Replace with the actual issuer's DID

	// Simulate the issuance of a verifiable credential
	credential := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1", // The W3C credential context
		},
		"id":     credentialID,
		"type":   []string{"VerifiableCredential"}, // The type of credential
		"issuer": issuerDID,                        // The issuer's DID

		"credential": "Verifiable Credential Data",
		"credentialSubject": map[string]interface{}{
			"id": userDID, // The subject's DID
			// Add any claims about the subject here
			"claims": map[string]interface{}{
				"email":  "user@example.com", // Example claim
				"name":   "John Doe",         // Example claim
				"userid": userID,             // Example claim
			},
		},
		"issuanceDate":   time.Now().Format(time.RFC3339),                     // Date issued
		"expirationDate": time.Now().Add(24 * time.Hour).Format(time.RFC3339), // Valid for 24 hours

	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credential)
}

// Verify access token and extract user ID
func verifyAccessToken(tokenString string) (string, error) {
	// Parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Use the predefined jwtSecret for verification
		return jwtSecret, nil
	})

	// Check if the token is valid and extract the claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), nil
	}
	return "", err
}
