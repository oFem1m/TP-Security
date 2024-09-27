package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("POSTGRES_HOST", "db"),
		getEnv("POSTGRES_PORT", "5432"),
		getEnv("POSTGRES_USER", "proxy_user"),
		getEnv("POSTGRES_PASSWORD", "password"),
		getEnv("POSTGRES_DB", "proxy_db"),
	)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Инициализируем таблицы
	initTables()
}

func initTables() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS requests (
			id SERIAL PRIMARY KEY,
			method TEXT,
			path TEXT,
			get_params JSONB,
			headers JSONB,
			cookies JSONB,
			post_params JSONB,
			body TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS responses (
			id SERIAL PRIMARY KEY,
			request_id INTEGER REFERENCES requests(id),
			status_code INTEGER,
			status_message TEXT,
			headers JSONB,
			body TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultVal
}
