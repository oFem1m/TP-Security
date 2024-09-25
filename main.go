package main

import (
	"log"
	"net/http"
	"os"
	"sync"
)

func main() {
	// Инициализация корневого сертификата (CA), если его еще нет
	initCA()

	var wg sync.WaitGroup
	wg.Add(2)

	// proxy
	go func() {
		defer wg.Done()
		http.HandleFunc("/", handleProxy)
		log.Println("Starting proxy server on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// API
	go func() {
		defer wg.Done()
		http.HandleFunc("/requests", handleRequests)
		http.HandleFunc("/requests/", handleRequestByID)
		log.Println("Starting API server on :8000")
		log.Fatal(http.ListenAndServe(":8000", nil))
	}()

	wg.Wait()
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// Определяем, является ли запрос CONNECT (для HTTPS)
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r) // Вызов функции для обработки HTTPS-запросов
	} else {
		handleHTTP(w, r) // Вызов функции для обработки HTTP-запросов
	}
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
