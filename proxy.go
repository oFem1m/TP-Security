package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var requests = make([]*http.Request, 0)
var mutex = &sync.Mutex{}

func createServer() {
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleProxy),
	}
	fmt.Println("Сервер запущен и слушает на порту 8080")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request method: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	// Определяем, является ли запрос CONNECT (для HTTPS)
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r) // Вызов функции для обработки HTTPS-запросов
	} else {
		handleHTTP(w, r) // Вызов функции для обработки HTTP-запросов
	}
}

// Обработка HTTPS-запросов
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling HTTPS request: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	// Логируем запрос
	mutex.Lock()
	requests = append(requests, r)
	mutex.Unlock()

	// Извлекаем хост и порт из запроса CONNECT
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	// Сообщаем клиенту, что соединение установлено
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Error hijacking connection", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Генерируем сертификат для запрашиваемого хоста
	certFile, keyFile, err := generateHostCertificate(r.Host)
	if err != nil {
		http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
		return
	}

	// Загрузка сертификата и ключа
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		http.Error(w, "Failed to load certificate", http.StatusInternalServerError)
		return
	}

	// Создаем TLS-сервер с нашим сгенерированным сертификатом
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConn := tls.Server(clientConn, tlsConfig)

	// Устанавливаем TLS-соединение с клиентом
	err = tlsConn.Handshake()
	if err != nil {
		log.Println("TLS Handshake error:", err)
		return
	}
	defer tlsConn.Close()

	// Читаем запрос клиента
	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Println("Failed to read request:", err)
		return
	}

	// Модифицируем запрос перед отправкой на целевой сервер (пример)
	req.Header.Set("User-Agent", "Modified-MITM-Proxy")

	// Пересылаем измененный запрос на целевой сервер
	destConn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Println("Failed to connect to destination:", err)
		return
	}
	defer destConn.Close()

	err = req.Write(destConn)
	if err != nil {
		log.Println("Failed to forward request:", err)
		return
	}

	// Читаем ответ от сервера
	resp, err := http.ReadResponse(bufio.NewReader(destConn), req)
	if err != nil {
		log.Println("Failed to read response from destination:", err)
		return
	}
	defer resp.Body.Close()

	// Пересылаем ответ клиенту
	err = resp.Write(tlsConn)
	if err != nil {
		log.Println("Failed to write response to client:", err)
		return
	}
}

// Обработка HTTP-запросов
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Логируем запрос
	log.Printf("Handling HTTPS request: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	mutex.Lock()
	requests = append(requests, r)
	mutex.Unlock()

	uri, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Определяем хост
	host := uri.Host
	if host == "" {
		host = r.Host
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	// Устанавливаем соединение с сервером
	conn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "Error connecting to host", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Перезаписываем запрос
	requestLine := fmt.Sprintf("%s %s %s\r\n", r.Method, uri.RequestURI(), r.Proto)
	conn.Write([]byte(requestLine))

	// Передаем заголовки, удаляем "Proxy-Connection"
	for header, values := range r.Header {
		if strings.EqualFold(header, "Proxy-Connection") {
			continue
		}
		for _, value := range values {
			conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", header, value)))
		}
	}

	// Убеждаемся, что заголовок "Host" установлен корректно
	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", host)))

	// Завершаем отправку заголовков
	conn.Write([]byte("\r\n"))

	// Копируем тело запроса (для POST, PUT, итд.)
	if r.Method == "POST" || r.Method == "PUT" {
		io.Copy(conn, r.Body)
	}

	// Читаем ответ от сервера
	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, r)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Передаем ответ
	for header, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	resp.Body.Close()
}
