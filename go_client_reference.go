// go_client.go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
)

const (
	PEER_DISCOVERY_PORT = 9999
	FILE_TRANSFER_PORT  = 10000
	SHARED_FOLDER       = "./shared_files"
)

var (
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	encryptionKey []byte
)

func generateKeys() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey
}

func encryptMessage(message []byte, pub *rsa.PublicKey) []byte {
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, message, nil)
	if err != nil {
		panic(err)
	}
	return encrypted
}

func decryptMessage(ciphertext []byte) []byte {
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return decrypted
}

func peerDiscovery() {
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", PEER_DISCOVERY_PORT))
	conn, _ := net.ListenUDP("udp", addr)

	fmt.Println("[*] Listening for peers...")
	buf := make([]byte, 1024)

	for {
		n, remoteAddr, _ := conn.ReadFromUDP(buf)
		fmt.Printf("[*] Discovered peer: %s says %s\n", remoteAddr, string(buf[:n]))
	}
}

func broadcastDiscover() {
	conn, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4bcast, Port: PEER_DISCOVERY_PORT})
	defer conn.Close()
	msg := []byte("Hello from Go Client!")
	conn.Write(msg)
}

func startFileServer() {
	ln, _ := net.Listen("tcp", fmt.Sprintf(":%d", FILE_TRANSFER_PORT))
	fmt.Println("[*] File server started...")

	for {
		conn, _ := ln.Accept()
		go handleFileRequest(conn)
	}
}

func handleFileRequest(conn net.Conn) {
	defer conn.Close()

	buf, _ := ioutil.ReadAll(conn)
	var request map[string]string
	json.Unmarshal(buf, &request)

	action := request["action"]
	if action == "LIST_FILES" {
		files, _ := ioutil.ReadDir(SHARED_FOLDER)
		fileNames := []string{}
		for _, f := range files {
			fileNames = append(fileNames, f.Name())
		}
		response, _ := json.Marshal(fileNames)
		conn.Write(response)
	} else if action == "REQUEST_FILE" {
		filename := request["filename"]
		filepath := SHARED_FOLDER + "/" + filename
		fileData, err := ioutil.ReadFile(filepath)
		if err != nil {
			conn.Write([]byte("File not found!"))
			return
		}

		block, _ := aes.NewCipher(encryptionKey)
		aesGCM, _ := cipher.NewGCM(block)
		nonce := make([]byte, aesGCM.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		encryptedFile := aesGCM.Seal(nonce, nonce, fileData, nil)

		conn.Write(encryptedFile)
	}
}

func main() {
	generateKeys()
	encryptionKey = make([]byte, 32)
	io.ReadFull(rand.Reader, encryptionKey)

	go peerDiscovery()
	go startFileServer()

	var cmd string
	for {
		fmt.Print("Enter command (discover/list/request): ")
		fmt.Scanln(&cmd)
		if cmd == "discover" {
			broadcastDiscover()
		} else if cmd == "list" {
			// implement peer list request
		} else if cmd == "request" {
			// implement peer file request
		}
	}
}
