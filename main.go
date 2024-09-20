package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

var requests = make([]*http.Request, 0)
var mutex = &sync.Mutex{}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// Логируем запрос
	mutex.Lock()
	requests = append(requests, r)
	mutex.Unlock()

	// Читаем данные из запроса
	uri, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Определяем хост
	host := uri.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	// Устанавливаем соединение с целевым сервером
	conn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "Error connecting to host", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Перезаписываем запрос
	requestLine := fmt.Sprintf("%s %s %s\r\n", r.Method, uri.Path, r.Proto)
	conn.Write([]byte(requestLine))

	// Передаем заголовки, удаляем "Proxy-Connection"
	for header, values := range r.Header {
		if header == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", header, value)))
		}
	}

	// Убедитесь, что заголовок "Host" установлен корректно
	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", uri.Host)))

	// Завершаем отправку заголовков
	conn.Write([]byte("\r\n"))

	// Читаем ответ от сервера
	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, r)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusBadGateway)
		return
	}

	// Передаем ответ обратно клиенту
	for header, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

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

	json.NewEncoder(w).Encode(requestList)
}

func handleRequestByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/requests/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 0 || id >= len(requests) {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	req := requests[id]
	json.NewEncoder(w).Encode(map[string]string{
		"Method": req.Method,
		"URL":    req.URL.String(),
	})
}

func main() {
	// Прокси-сервер
	go func() {
		http.HandleFunc("/", handleProxy)
		log.Println("Starting proxy server on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// Веб-API
	http.HandleFunc("/requests", handleRequests)
	http.HandleFunc("/requests/", handleRequestByID)

	log.Println("Starting API server on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
