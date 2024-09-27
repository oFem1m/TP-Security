# 1. Используем официальный образ Go
FROM golang:1.21-alpine

# 2. Устанавливаем нужные утилиты и зависимости
RUN apk add --no-cache bash ca-certificates git

# 3. Создаем рабочую директорию в контейнере
WORKDIR /app

# 4. Копируем go.mod и go.sum для загрузки зависимостей
COPY go.mod go.sum ./

# 5. Загружаем зависимости
RUN go mod download

# 6. Копируем весь код проекта в рабочую директорию
COPY . .

# 7. Компилируем Go-приложение
RUN go build -o proxyserver .

# 8. Команда для запуска вашего прокси-сервера
CMD ["./proxyserver"]
