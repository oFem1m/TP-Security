package main

import (
	"log"
	"os"
)

func main() {
	createServer()
}

func initCA() {
	// Проверка существования корневого сертификата (CA) и его создание при необходимости
	if _, err := os.Stat("certs/ca.crt"); os.IsNotExist(err) {
		log.Println("CA certificate not found. Generating new CA certificate...")
		if err := createCACertificate(); err != nil {
			log.Fatalf("Failed to create CA certificate: %v", err)
		}
		log.Println("CA certificate created successfully!")
	}
}
