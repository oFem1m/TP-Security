package main

import (
	"sync"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(2)
	// proxy
	go func() {
		defer wg.Done()
		createServer()
	}()

	// API
	go func() {
		defer wg.Done()
		createApiServer()
	}()

	wg.Wait()
}
