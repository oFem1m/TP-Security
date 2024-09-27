package main

import (
	"sync"
)

func main() {
	// Подключаемся к базе данных
	initDB()

	// Инициализируем таблицы (если они не созданы)
	initTables()
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
