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

// Обработка HTTPS-запросов (CONNECT)
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Логируем запрос
	mutex.Lock()
	requests = append(requests, r)
	mutex.Unlock()

	host := r.Host
	log.Printf("Handling HTTPS request for host: %s", host)

	// Устанавливаем соединение с клиентом
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Отправляем ответ клиенту, что соединение установлено
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Генерируем сертификат для хоста
	certFile, keyFile, err := generateHostCertificate(host)
	if err != nil {
		log.Printf("Error generating host certificate: %v", err)
		return
	}

	// Настраиваем TLS-сервер с динамически сгенерированным сертификатом
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("Error loading key pair: %v", err)
		return
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	tlsListener := tls.Server(clientConn, tlsConfig)

	// Устанавливаем соединение с реальным сервером
	remoteConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("Error connecting to remote host: %v", err)
		return
	}
	defer remoteConn.Close()

	// Проксим данные между клиентом и сервером
	go io.Copy(remoteConn, tlsListener)
	io.Copy(tlsListener, remoteConn)
}

// Обработка HTTP-запросов
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling HTTP request: %s", r.URL.String())
	// Логируем запрос
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
