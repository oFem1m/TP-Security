package main

import (
	"log"
	"net/http"
	"sync"
)

func main() {
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
