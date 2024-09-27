package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func createApiServer() {
	ApiServer := &http.Server{
		Addr:    ":8000",
		Handler: http.HandlerFunc(handleAPI),
	}
	fmt.Println("API-Сервер запущен на порту 8000")
	err := ApiServer.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	log.Printf("(API-server) Received request method: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	switch r.URL.String() {
	case "/requests":
		handleRequests(w, r)
	case "/requests/":
		handleRequestByID(w, r)
	case "/repeat/":
		handleRepeatRequest(w, r)

	}

}

// Получение всех запросов из базы данных
func handleRequests(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	requestList := make([]map[string]string, len(requests))
	for i, req := range requests {
		requestList[i] = map[string]string{
			"Method": req.Method,
			"URL":    req.URL.String(),
		}
	}

	// Возвращаем результат в формате JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requestList)
}

// Получение одного запроса по его ID
func handleRequestByID(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID из URL
	idStr := strings.TrimPrefix(r.URL.Path, "/requests/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 0 || id >= len(requests) {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	req := requests[id]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"Method": req.Method,
		"URL":    req.URL.String(),
	})
}

// Повторная отправка запроса
func handleRepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	collection := db.Collection("requests")
	var storedReq StoredRequest
	err = collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&storedReq)
	if err != nil {
		http.Error(w, "Запрос не найден", http.StatusNotFound)
		return
	}

	// Отправляем запрос повторно
	resp, err := repeatRequest(storedReq.Request)
	if err != nil {
		http.Error(w, "Ошибка при повторной отправке запроса", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
