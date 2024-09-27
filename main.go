package main

import (
	"sync"
)

func main() {
	// Инициализация подключения к MongoDB
	initMongo()

	var wg sync.WaitGroup
	wg.Add(2)

	// Proxy-сервер
	go func() {
		defer wg.Done()
		createServer()
	}()

	// API-сервер
	go func() {
		defer wg.Done()
		createApiServer()
	}()

	wg.Wait()
}
