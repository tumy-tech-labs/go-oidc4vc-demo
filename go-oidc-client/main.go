package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var (
	clientID      string
	clientSecret  string
	redirectURI   string
	authEndpoint  string
	tokenEndpoint string
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func init() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	redirectURI = os.Getenv("REDIRECT_URI")
	authEndpoint = os.Getenv("AUTH_ENDPOINT")
	tokenEndpoint = os.Getenv("TOKEN_ENDPOINT")
}

func main() {
	// Start the OAuth flow by redirecting the user
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=openid",
		authEndpoint, clientID, url.QueryEscape(redirectURI))

	fmt.Printf("Open the following URL in your browser:\n%s\n", authURL)

	// Start HTTP server to handle the callback
	http.HandleFunc("/callback", handleCallback)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Received /callback request")

	// Retrieve the authorization code and state from the query
	code := r.URL.Query().Get("code")
	//state := r.URL.Query().Get("state") // Capture the state for validation if needed

	if code == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Authorization code received. You may close this window.")

	// Exchange the authorization code for an access token
	token, err := exchangeCodeForToken(code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return // Avoid calling Fatal here, as it will exit the program
	}

	fmt.Printf("Access Token: %s\n", token.AccessToken)
}

func exchangeCodeForToken(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	fmt.Println("Token Endpoint:", tokenEndpoint)

	// Create a new POST request
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body) // Read the body for more info on the error
		return nil, fmt.Errorf("failed to exchange token: %s (status code: %d)", string(body), resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}
