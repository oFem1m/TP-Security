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

func generateHostCertificate(hostname string, serialNumber *big.Int) error {
	// Загрузка корневого сертификата (CA)
	caCertPEM, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %v", err)
	}
	caKeyPEM, err := os.ReadFile("certs/ca.key")
	if err != nil {
		return fmt.Errorf("error reading CA key: %v", err)
	}

	// Парсинг CA сертификата и ключа
	caCertBlock, _ := pem.Decode(caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing CA certificate: %v", err)
	}

	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing CA private key: %v", err)
	}

	// Генерация приватного ключа для хоста
	hostPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating private key for host: %v", err)
	}

	// Создание шаблона сертификата для хоста
	hostCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Срок действия: 1 год
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Подписываем сертификат корневым сертификатом (CA)
	hostCertBytes, err := x509.CreateCertificate(rand.Reader, hostCertTemplate, caCert, &hostPrivKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("error creating host certificate: %v", err)
	}

	// Сохраняем приватный ключ хоста в файл host.key
	hostKeyFile, err := os.Create(fmt.Sprintf("certs/%s.key", hostname))
	if err != nil {
		return fmt.Errorf("error creating host key file: %v", err)
	}
	defer hostKeyFile.Close()

	err = pem.Encode(hostKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(hostPrivKey)})
	if err != nil {
		return fmt.Errorf("error writing host private key to file: %v", err)
	}

	// Сохраняем сертификат хоста в файл host.crt
	hostCertFile, err := os.Create(fmt.Sprintf("certs/%s.crt", hostname))
	if err != nil {
		return fmt.Errorf("error creating host certificate file: %v", err)
	}
	defer hostCertFile.Close()

	err = pem.Encode(hostCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: hostCertBytes})
	if err != nil {
		return fmt.Errorf("error writing host certificate to file: %v", err)
	}

	log.Printf("Host certificate and key generated for %s and saved to %s.crt and %s.key\n", hostname, hostname, hostname)
	return nil
}
