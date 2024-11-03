package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tumy-tech-labs/go-oidc4vc-demo/user-service/handlers"

	_ "github.com/lib/pq"
)

func main() {
	// Database connection
	connStr := "postgres://oidc_user:oidc_password@postgres-db:5432/oidc_db?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()

	// HTTP handlers
	http.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		handlers.CreateUserHandler(w, r, db)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	fmt.Printf("Starting server on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
