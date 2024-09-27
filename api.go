package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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
	ctx := context.TODO()
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var requestList []map[string]string
	for cursor.Next(ctx) {
		var request map[string]interface{}
		if err = cursor.Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		requestList = append(requestList, map[string]string{
			"Method": request["Method"].(string),
			"URL":    request["URL"].(string),
		})
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
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	ctx := context.TODO()
	var request bson.M
	filter := bson.M{"_id": id}
	err = collection.FindOne(ctx, filter).Decode(&request)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Request not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"Method": request["Method"].(string),
		"URL":    request["URL"].(string),
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
