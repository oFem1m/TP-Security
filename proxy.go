package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var requests = make([]*http.Request, 0)
var mutex = &sync.Mutex{}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
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
	requestLine := fmt.Sprintf("%s %s %s\\r\\n", r.Method, uri.Path, r.Proto)
	conn.Write([]byte(requestLine))

	// Передаем заголовки, удаляем "Proxy-Connection"
	for header, values := range r.Header {
		if header == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			conn.Write([]byte(fmt.Sprintf("%s: %s\\r\\n", header, value)))
		}
	}

	// Убедитесь, что заголовок "Host" установлен корректно
	conn.Write([]byte(fmt.Sprintf("Host: %s\\r\\n", host)))

	// Завершаем отправку заголовков
	conn.Write([]byte("\\r\\n"))

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

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Получаем хост и порт из строки CONNECT
	host := r.Host

	// Устанавливаем соединение с целевым сервером
	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, "Unable to connect to destination", http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Отправляем клиенту ответ о успешном установлении соединения
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "HTTP/1.0 200 Connection established\\r\\n\\r\\n")

	// Превращаем HTTP-соединение с клиентом в TCP-соединение
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

	// Передаем данные между клиентом и сервером
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}
