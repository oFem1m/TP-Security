package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
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
	fmt.Println("Proxy-Сервер запущен на порту 8080")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	log.Printf("(proxy-server) Received request method: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	// Определяем, является ли запрос CONNECT (для HTTPS)
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r) // Вызов функции для обработки HTTPS-запросов
	} else {
		handleHTTP(w, r) // Вызов функции для обработки HTTP-запросов
	}
}

// Обработка HTTPS-запросов
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("(proxy-server) Handling HTTPS request: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
	// Логируем запрос
	mutex.Lock()
	requests = append(requests, r)
	mutex.Unlock()

	// Читаем хост и порт из первой строки запроса
	hostPort := r.Host
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443" // Добавляем порт по умолчанию
	}
	host, _, err := net.SplitHostPort(hostPort)

	// Устанавливаем соединение с клиентом
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

	// Отправляем клиенту сообщение о том, что соединение установлено
	_, err = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("(proxy-server) Failed to send connection established:", err)
		return
	}

	// Устанавливаем соединение с целевым сервером
	serverConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		log.Println("(proxy-server) Failed to connect to destination:", err)
		return
	}
	defer serverConn.Close()

	// Генерация серийного номера для сертификата
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("(proxy-server) Error generating serial number: %v\n", err)
		return
	}

	certFile := fmt.Sprintf("certs/%s.crt", host)
	certKey := fmt.Sprintf("certs/%s.key", host)

	// Проверка существования файлов сертификата
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("(proxy-server) Certificate file %s does not exist", certFile)
		// Генерация сертификата для хоста
		log.Println("(proxy-server) Generating host certificate:", host)
		err = generateHostCertificate(host, serialNumber)
		if err != nil {
			log.Println("(proxy-server) Failed to generate host certificate:", err)
			return
		}
	}

	// Загружаем сертификат и ключ
	cert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		log.Printf("(proxy-server) Failed to load certificate from %s and key from %s: %v", certFile, certKey, err)
		return
	}
	log.Printf("(proxy-server) Successfully loaded certificate from %s and key from %s", certFile, certKey)

	// Создаем TLS-конфигурацию для соединения с клиентом
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Устанавливаем TLS-соединение с клиентом
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	err = tlsClientConn.Handshake()
	if err != nil {
		log.Println("(proxy-server) TLS handshake with client failed:", err)
		return
	}
	defer tlsClientConn.Close()

	// TLS-соединение с сервером
	tlsServerConn := tls.Client(serverConn, &tls.Config{InsecureSkipVerify: true})
	err = tlsServerConn.Handshake()
	if err != nil {
		log.Println("(proxy-server) TLS handshake with server failed:", err)
		return
	}
	defer tlsServerConn.Close()

	// Проксирование данных между клиентом и сервером
	go io.Copy(tlsServerConn, tlsClientConn)
	io.Copy(tlsClientConn, tlsServerConn)
}

// Обработка HTTP-запросов
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Логируем запрос
	log.Printf("(proxy-server) Handling HTTP request: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())
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

	// Копируем тело запроса (для POST, PUT и др.)
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

	// Передаем ответ клиенту
	for header, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Сохранение запроса в базу данных
func saveRequest(req *http.Request, parsedBody map[string]interface{}) (int64, error) {
	// Парсинг заголовков, Cookie, GET/POST параметров
	headers := parseHeaders(req.Header)
	cookies := parseCookies(req.Cookies())
	getParams := parseGetParams(req.URL.Query())
	postParams := parsedBody

	// Сохранение запроса в БД
	var requestID int64
	err := db.QueryRow(`
		INSERT INTO requests (method, path, get_params, headers, cookies, post_params, body)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
	`,
		req.Method,
		req.URL.Path,
		getParams,
		headers,
		cookies,
		postParams,
		req.Body,
	).Scan(&requestID)

	if err != nil {
		return 0, fmt.Errorf("failed to save request: %v", err)
	}
	return requestID, nil
}

// Сохранение ответа в базу данных
func saveResponse(requestID int64, resp *http.Response) error {
	headers := parseHeaders(resp.Header)

	_, err := db.Exec(`
		INSERT INTO responses (request_id, status_code, status_message, headers, body)
		VALUES ($1, $2, $3, $4, $5)
	`,
		requestID,
		resp.StatusCode,
		resp.Status,
		headers,
		resp.Body,
	)

	if err != nil {
		return fmt.Errorf("failed to save response: %v", err)
	}
	return nil
}

func parseHeaders(headers http.Header) map[string]string {
	parsedHeaders := make(map[string]string)
	for key, values := range headers {
		parsedHeaders[key] = strings.Join(values, ", ")
	}
	return parsedHeaders
}

func parseCookies(cookies []*http.Cookie) map[string]string {
	parsedCookies := make(map[string]string)
	for _, cookie := range cookies {
		parsedCookies[cookie.Name] = cookie.Value
	}
	return parsedCookies
}

func parseGetParams(params url.Values) map[string]interface{} {
	parsedParams := make(map[string]interface{})
	for key, values := range params {
		if len(values) == 1 {
			parsedParams[key] = values[0]
		} else {
			parsedParams[key] = values
		}
	}
	return parsedParams
}

func resendRequest(requestID int64) error {
	// Получаем запрос из БД
	var reqData struct {
		Method  string
		Path    string
		Headers map[string]string
		Body    string
	}

	err := db.QueryRow(`SELECT method, path, headers, body FROM requests WHERE id = $1`, requestID).Scan(
		&reqData.Method,
		&reqData.Path,
		&reqData.Headers,
		&reqData.Body,
	)
	if err != nil {
		return fmt.Errorf("failed to retrieve request: %v", err)
	}

	// Создаем HTTP-запрос для повторной отправки
	req, err := http.NewRequest(reqData.Method, reqData.Path, strings.NewReader(reqData.Body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Устанавливаем заголовки
	for key, value := range reqData.Headers {
		req.Header.Set(key, value)
	}

	// Отправляем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to resend request: %v", err)
	}
	defer resp.Body.Close()

	// Сохраняем новый ответ
	err = saveResponse(requestID, resp)
	if err != nil {
		return fmt.Errorf("failed to save response: %v", err)
	}

	return nil
}
