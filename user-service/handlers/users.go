package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User struct to hold incoming JSON data
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Response struct for API responses
type Response struct {
	Message string `json:"message"`
}

// CreateUserHandler handles creating a new user
func CreateUserHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Hash and salt the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert the new user into the database
	query := `INSERT INTO users (username, email, password_hash, salt, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = db.Exec(query, user.Username, user.Email, string(hashedPassword), "bcrypt", time.Now(), time.Now())
	if err != nil {
		log.Printf("Failed to insert user: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "User created successfully"})
}
