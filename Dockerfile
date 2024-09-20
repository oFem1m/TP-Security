# Используем официальный образ Go
FROM golang:1.22

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем go.mod и go.sum для установки зависимостей
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Сборка приложения
RUN go build -o /proxy-server

# Экспонируем порты для API и Proxy
EXPOSE 8080
EXPOSE 8000

# Запуск приложения
CMD ["/proxy-server"]
