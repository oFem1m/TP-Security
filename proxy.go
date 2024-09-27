package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var requests = make([]*http.Request, 0)
var mutex = &sync.Mutex{}
var collection *mongo.Collection
var db *mongo.Database

// Структура для хранения параметров запроса
type ParsedRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	GetParams  map[string]string `json:"get_params"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	PostParams map[string]string `json:"post_params"`
	Body       string            `json:"body"` // Добавляем поле для тела запроса
}

// Структура для хранения параметров ответа
type ParsedResponse struct {
	Code    int               `bson:"code"`
	Message string            `bson:"message"`
	Headers map[string]string `bson:"headers"`
	Body    string            `bson:"body"`
}

// Структура для хранения запроса и ответа вместе
type StoredRequest struct {
	Request  ParsedRequest  `bson:"request"`
	Response ParsedResponse `bson:"response"`
}

func initMongo() {
	// Подключение к MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("proxydb").Collection("requests")
	fmt.Println("Connected to MongoDB!")
}

func createServer() {
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleProxy),
	}
	fmt.Println("Proxy-сервер запущен на порту 8080")
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
	storeRequest(r, nil)

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

	_, err = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("(proxy-server) Failed to send connection established:", err)
		return
	}

	serverConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		log.Println("(proxy-server) Failed to connect to destination:", err)
		return
	}
	defer serverConn.Close()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Printf("(proxy-server) Error generating serial number: %v\n", err)
		return
	}

	certFile := fmt.Sprintf("certs/%s.crt", host)
	certKey := fmt.Sprintf("certs/%s.key", host)

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("(proxy-server) Certificate file %s does not exist", certFile)
		err = generateHostCertificate(host, serialNumber)
		if err != nil {
			log.Println("(proxy-server) Failed to generate host certificate:", err)
			return
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		log.Printf("(proxy-server) Failed to load certificate from %s and key from %s: %v", certFile, certKey, err)
		return
	}
	log.Printf("(proxy-server) Successfully loaded certificate from %s and key from %s", certFile, certKey)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	err = tlsClientConn.Handshake()
	if err != nil {
		log.Println("(proxy-server) TLS handshake with client failed:", err)
		return
	}
	defer tlsClientConn.Close()

	tlsServerConn := tls.Client(serverConn, &tls.Config{InsecureSkipVerify: true})
	err = tlsServerConn.Handshake()
	if err != nil {
		log.Println("(proxy-server) TLS handshake with server failed:", err)
		return
	}
	defer tlsServerConn.Close()

	go io.Copy(tlsServerConn, tlsClientConn)
	io.Copy(tlsClientConn, tlsServerConn)
}

// Обработка HTTP-запросов
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Логируем запрос
	log.Printf("(proxy-server) Handling HTTP request: %s, host: %s, URL: %s", r.Method, r.Host, r.URL.String())

	uri, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	host := uri.Host
	if host == "" {
		host = r.Host
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "Error connecting to host", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	requestLine := fmt.Sprintf("%s %s %s\r\n", r.Method, uri.RequestURI(), r.Proto)
	conn.Write([]byte(requestLine))

	for header, values := range r.Header {
		if strings.EqualFold(header, "Proxy-Connection") {
			continue
		}
		for _, value := range values {
			conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", header, value)))
		}
	}

	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", host)))
	conn.Write([]byte("\r\n"))

	if r.Method == "POST" || r.Method == "PUT" {
		io.Copy(conn, r.Body)
	}

	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, r)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	storeRequest(r, resp)

	for header, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Функция для сохранения запроса и ответа в MongoDB
func storeRequest(r *http.Request, resp *http.Response) {
	// Парсинг GET параметров
	queryParams := r.URL.Query()
	getParams := make(map[string]string)
	for key, values := range queryParams {
		getParams[key] = values[0] // Берем первое значение, если параметр встречается несколько раз
	}

	// Парсинг POST параметров
	postParams := make(map[string]string)
	bodyBytes, err := io.ReadAll(r.Body) // Считываем тело запроса
	if err == nil {
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Восстанавливаем r.Body для последующего использования
	}

	if r.Method == "POST" || r.Method == "PUT" {
		// Если тип данных - application/x-www-form-urlencoded, парсим форму
		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			err := r.ParseForm()
			if err == nil {
				for key, values := range r.PostForm {
					postParams[key] = values[0] // Берем первое значение
				}
			}
		}
	}

	// Парсинг заголовков
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = strings.Join(values, ", ") // Объединяем несколько значений заголовка в одну строку
	}

	// Парсинг Cookie
	cookieParams := make(map[string]string)
	for _, cookie := range r.Cookies() {
		cookieParams[cookie.Name] = cookie.Value
	}

	parsedReq := ParsedRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		GetParams:  getParams,
		Headers:    headers,
		Cookies:    cookieParams,
		PostParams: postParams,
		Body:       string(bodyBytes), // Сохраняем тело запроса
	}

	parsedResp := ParsedResponse{}
	if resp != nil {
		// Парсинг заголовков ответа
		responseHeaders := make(map[string]string)
		for name, values := range resp.Header {
			responseHeaders[name] = strings.Join(values, ", ")
		}

		// Обрабатываем сжатие
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Восстанавливаем тело ответа для последующего использования

		// Декодируем тело, если оно сжато (gzip, deflate и т.д.)
		if resp.Header.Get("Content-Encoding") == "gzip" {
			bodyBytes, err = decodeGzip(bodyBytes)
			if err != nil {
				log.Println("Error decoding gzip:", err)
			}
		}

		bodyString := string(bodyBytes)

		parsedResp = ParsedResponse{
			Code:    resp.StatusCode,
			Message: resp.Status,
			Headers: responseHeaders,
			Body:    bodyString,
		}
	}

	// Сохраняем запрос и ответ в MongoDB
	storedReq := StoredRequest{
		Request:  parsedReq,
		Response: parsedResp,
	}

	_, err = collection.InsertOne(context.TODO(), storedReq)
	if err != nil {
		log.Println("Error inserting into MongoDB:", err)
	}
}

// Функция для декодирования gzip
func decodeGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Повторная отправка запроса
func repeatRequest(req ParsedRequest) (*http.Response, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Отключаем проверку сертификатов для HTTPS-запросов
			},
		},
	}

	// Формируем новый HTTP-запрос
	httpReq, err := http.NewRequest(req.Method, req.Path, strings.NewReader(req.Body)) // Добавляем тело запроса, если оно есть
	if err != nil {
		return nil, err
	}

	// Добавляем заголовки и куки
	for header, value := range req.Headers {
		httpReq.Header.Add(header, value)
	}
	for cookie, value := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: cookie, Value: value})
	}

	// Отправляем запрос
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
