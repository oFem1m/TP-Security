package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// Генерация корневого сертификата (CA)
func createCACertificate() error {
	// Генерация приватного ключа для CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Шаблон сертификата для CA
	caCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Aleksandr Volokhov"},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{"Moscow"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // срок действия 10 лет
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Подписываем сертификат самого себя
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Создаем директорию для хранения сертификатов
	os.MkdirAll("certs", 0755)

	// Сохраняем корневой сертификат (CA)
	certOut, err := os.Create("certs/ca.crt")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	certOut.Close()

	// Сохраняем приватный ключ CA
	keyOut, err := os.Create("certs/ca.key")
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	keyOut.Close()

	log.Println("CA certificate and key generated successfully!")
	return nil
}

// Генерация сертификата для конкретного хоста, подписанного CA
func generateHostCertificate(host string) (certFile, keyFile string, err error) {
	// Загрузка приватного ключа CA
	caKeyBytes, err := os.ReadFile("certs/ca.key")
	if err != nil {
		return "", "", err
	}
	caKeyBlock, _ := pem.Decode(caKeyBytes)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", "", err
	}

	// Загрузка сертификата CA
	caCertBytes, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		return "", "", err
	}
	caCertBlock, _ := pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", "", err
	}

	// Генерация приватного ключа для хоста
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Шаблон сертификата для хоста
	hostCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:    []string{host},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Срок действия 1 год
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Подписываем сертификат хоста с помощью CA
	hostCertBytes, err := x509.CreateCertificate(rand.Reader, hostCertTemplate, caCert, &hostKey.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}

	// Сохраняем сертификат и ключ хоста в файлы
	certFile = fmt.Sprintf("certs/%s.crt", host)
	keyFile = fmt.Sprintf("certs/%s.key", host)

	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: hostCertBytes})
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(hostKey)})
	keyOut.Close()

	return certFile, keyFile, nil
}
