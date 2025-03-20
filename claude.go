package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh/terminal"
)

// SecureP2PClient is the Go equivalent of the Python client
type SecureP2PClient struct {
	Username    string
	StoragePath string
	Port        int
	Contacts    map[string]ContactInfo
	Files       map[string]string   // filename -> hash
	FileSources map[string][]string // hash -> []username
	SessionKeys map[string][]byte
	PrivateKey  *rsa.PrivateKey
	PublicKey   *rsa.PublicKey
	Server      net.Listener
	Zeroconf    *zeroconf.Server
	mu          sync.Mutex
}

// ContactInfo stores information about a contact
type ContactInfo struct {
	Address   string
	Port      int
	PublicKey *rsa.PublicKey
}

// Message represents a message between peers
type Message struct {
	Type       string            `json:"type,omitempty"`
	Sender     string            `json:"sender,omitempty"`
	Address    string            `json:"address,omitempty"`
	Port       int               `json:"port,omitempty"`
	PublicKey  string            `json:"public_key,omitempty"`
	Files      map[string]string `json:"files,omitempty"`
	Filename   string            `json:"filename,omitempty"`
	FileHash   string            `json:"file_hash,omitempty"`
	FileData   string            `json:"file_data,omitempty"`
	Status     string            `json:"status,omitempty"`
	SessionKey string            `json:"session_key,omitempty"`
	// For encrypted messages
	Encrypted bool   `json:"encrypted,omitempty"`
	IV        string `json:"iv,omitempty"`
	Data      string `json:"data,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// NewSecureP2PClient creates a new P2P client
func NewSecureP2PClient(username, storagePath string, port int) (*SecureP2PClient, error) {
	client := &SecureP2PClient{
		Username:    username,
		StoragePath: storagePath,
		Port:        port,
		Contacts:    make(map[string]ContactInfo),
		Files:       make(map[string]string),
		FileSources: make(map[string][]string),
		SessionKeys: make(map[string][]byte),
	}

	// Create storage directories
	os.MkdirAll(storagePath, 0755)
	os.MkdirAll(filepath.Join(storagePath, "shared"), 0755)
	os.MkdirAll(filepath.Join(storagePath, "received"), 0755)
	os.MkdirAll(filepath.Join(storagePath, "private"), 0755)

	// Load or generate keys
	err := client.loadOrGenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("error with keys: %v", err)
	}

	// Start server
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start server: %v", err)
	}
	client.Server = listener

	// Register mDNS service
	err = client.registerMDNSService()
	if err != nil {
		client.Server.Close()
		return nil, fmt.Errorf("failed to register mDNS service: %v", err)
	}

	// Index shared files
	client.indexSharedFiles()

	// Start listening for connections
	go client.listenForConnections()

	fmt.Printf("P2P Client for %s started on port %d\n", username, port)
	return client, nil
}

// loadOrGenerateKeys loads existing keys or generates new ones
func (c *SecureP2PClient) loadOrGenerateKeys() error {
	keyPath := filepath.Join(c.StoragePath, "private", c.Username+"_key.pem")

	if _, err := os.Stat(keyPath); err == nil {
		// Load existing key
		fmt.Print("Enter password to decrypt your private key: ")
		password, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}

		keyData, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file: %v", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block")
		}

		privateKey, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %v", err)
		}

		c.PrivateKey, err = x509.ParsePKCS1PrivateKey(privateKey)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}
	} else {
		// Generate new key pair
		fmt.Print("Create a password to encrypt your private key: ")
		password, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}

		fmt.Print("Confirm password: ")
		confirmPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}

		if !bytes.Equal(password, confirmPassword) {
			return fmt.Errorf("passwords do not match")
		}

		// Generate key
		c.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate key: %v", err)
		}

		// Save private key
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(c.PrivateKey)
		block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privateKeyBytes, password, x509.PEMCipherAES256)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %v", err)
		}

		keyPEM := pem.EncodeToMemory(block)
		err = ioutil.WriteFile(keyPath, keyPEM, 0600)
		if err != nil {
			return fmt.Errorf("failed to save private key: %v", err)
		}
	}

	// Extract public key
	c.PublicKey = &c.PrivateKey.PublicKey

	// Save public key
	publicKeyDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM := pem.EncodeToMemory(publicKeyBlock)

	pubKeyPath := filepath.Join(c.StoragePath, "public_"+c.Username+"_key.pem")
	err = ioutil.WriteFile(pubKeyPath, publicKeyPEM, 0644)
	if err != nil {
		return fmt.Errorf("failed to save public key: %v", err)
	}

	return nil
}

// registerMDNSService registers the mDNS service for peer discovery
func (c *SecureP2PClient) registerMDNSService() error {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	server, err := zeroconf.Register(
		c.Username,        // service instance name
		"_securep2p._tcp", // service type
		"local.",          // domain
		c.Port,            // port
		map[string]string{ // metadata
			"username": c.Username,
			"pubkey":   base64.StdEncoding.EncodeToString(pubKeyDER),
		},
		nil, // interfaces
	)
	if err != nil {
		return fmt.Errorf("failed to register mDNS service: %v", err)
	}

	c.Zeroconf = server
	fmt.Printf("mDNS service registered: %s._securep2p._tcp.local.\n", c.Username)
	return nil
}

// discoverPeers discovers other peers on the network
func (c *SecureP2PClient) discoverPeers() {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		fmt.Printf("Failed to create resolver: %v\n", err)
		return
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if entry.Instance == c.Username {
				continue // Skip self
			}

			username := entry.Instance
			address := entry.AddrIPv4[0].String()
			port := entry.Port

			// Extract the public key from the TXT record
			var pubkeyB64 string
			for _, txt := range entry.Text {
				if strings.HasPrefix(txt, "pubkey=") {
					pubkeyB64 = strings.TrimPrefix(txt, "pubkey=")
					break
				}
			}

			// Connect to the discovered peer
			if pubkeyB64 != "" {
				fmt.Printf("Discovered peer: %s at %s:%d\n", username, address, port)
				go c.connectToPeer(username, address, port)
			}
		}
	}(entries)

	// Lookup for 10 seconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err = resolver.Browse(ctx, "_securep2p._tcp", "local.", entries)
	if err != nil {
		fmt.Printf("Failed to browse: %v\n", err)
	}
}

// listenForConnections listens for incoming connections
func (c *SecureP2PClient) listenForConnections() {
	for {
		conn, err := c.Server.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}
		go c.handleConnection(conn)
	}
}

// handleConnection handles an incoming connection
func (c *SecureP2PClient) handleConnection(conn net.Conn) {
	defer conn.Close()

	message, err := c.receiveMessage(conn)
	if err != nil {
		fmt.Printf("Error receiving message: %v\n", err)
		return
	}

	messageType := message.Type
	sender := message.Sender

	switch messageType {
	case "handshake":
		c.handleHandshake(conn, message)
	case "file_list_request":
		c.handleFileListRequest(conn, sender)
	case "file_request":
		c.handleFileRequest(conn, message)
	case "file_transfer":
		c.handleFileTransfer(conn, message)
	case "key_rotation":
		c.handleKeyRotation(conn, message)
	default:
		fmt.Printf("Unknown message type: %s\n", messageType)
	}
}

// sendMessage sends a message to a peer
func (c *SecureP2PClient) sendMessage(conn net.Conn, message Message, encryptFor string) error {
	var data []byte
	var err error

	if encryptFor != "" && c.SessionKeys[encryptFor] != nil {
		// Encrypt with session key
		plaintext, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %v", err)
		}

		sessionKey := c.SessionKeys[encryptFor]
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return fmt.Errorf("failed to generate IV: %v", err)
		}

		// Pad the plaintext
		plaintext = c.pkcs7Pad(plaintext, aes.BlockSize)

		// Create cipher
		block, err := aes.NewCipher(sessionKey)
		if err != nil {
			return fmt.Errorf("failed to create cipher: %v", err)
		}

		ciphertext := make([]byte, len(plaintext))
		mode := cipher.NewCBCEncryptor(block, iv)
		mode.CryptBlocks(ciphertext, plaintext)

		// Sign the encrypted data
		hash := sha256.Sum256(ciphertext)
		signature, err := rsa.SignPKCS1v15(rand.Reader, c.PrivateKey, crypto.SHA256, hash[:])
		if err != nil {
			return fmt.Errorf("failed to sign message: %v", err)
		}

		// Create encrypted message
		encryptedMsg := Message{
			Encrypted: true,
			Sender:    c.Username,
			IV:        base64.StdEncoding.EncodeToString(iv),
			Data:      base64.StdEncoding.EncodeToString(ciphertext),
			Signature: base64.StdEncoding.EncodeToString(signature),
		}

		data, err = json.Marshal(encryptedMsg)
		if err != nil {
			return fmt.Errorf("failed to marshal encrypted message: %v", err)
		}
	} else {
		data, err = json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %v", err)
		}
	}

	// Send the length first, then the data
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	_, err = conn.Write(lenBuf)
	if err != nil {
		return fmt.Errorf("failed to send message length: %v", err)
	}

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send message data: %v", err)
	}

	return nil
}

// receiveMessage receives a message from a peer
func (c *SecureP2PClient) receiveMessage(conn net.Conn) (Message, error) {
	// Read message length
	lenBuf := make([]byte, 4)
	_, err := io.ReadFull(conn, lenBuf)
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message length: %v", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)

	// Read the message
	data := make([]byte, length)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message data: %v", err)
	}

	var message Message
	err = json.Unmarshal(data, &message)
	if err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message: %v", err)
	}

	// Check if the message is encrypted
	if message.Encrypted {
		sender := message.Sender
		if _, ok := c.SessionKeys[sender]; !ok {
			return Message{}, fmt.Errorf("no session key for %s", sender)
		}

		sessionKey := c.SessionKeys[sender]
		iv, err := base64.StdEncoding.DecodeString(message.IV)
		if err != nil {
			return Message{}, fmt.Errorf("failed to decode IV: %v", err)
		}

		encryptedData, err := base64.StdEncoding.DecodeString(message.Data)
		if err != nil {
			return Message{}, fmt.Errorf("failed to decode encrypted data: %v", err)
		}

		signature, err := base64.StdEncoding.DecodeString(message.Signature)
		if err != nil {
			return Message{}, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Verify the signature
		hash := sha256.Sum256(encryptedData)
		err = rsa.VerifyPKCS1v15(c.Contacts[sender].PublicKey, crypto.SHA256, hash[:], signature)
		if err != nil {
			return Message{}, fmt.Errorf("signature verification failed: %v", err)
		}

		// Decrypt the data
		block, err := aes.NewCipher(sessionKey)
		if err != nil {
			return Message{}, fmt.Errorf("failed to create cipher: %v", err)
		}

		if len(encryptedData)%aes.BlockSize != 0 {
			return Message{}, fmt.Errorf("encrypted data is not a multiple of the block size")
		}

		decrypted := make([]byte, len(encryptedData))
		mode := cipher.NewCBCDecryptor(block, iv)
		mode.CryptBlocks(decrypted, encryptedData)

		// Remove padding
		decrypted, err = c.pkcs7Unpad(decrypted, aes.BlockSize)
		if err != nil {
			return Message{}, fmt.Errorf("failed to unpad: %v", err)
		}

		var decryptedMsg Message
		err = json.Unmarshal(decrypted, &decryptedMsg)
		if err != nil {
			return Message{}, fmt.Errorf("failed to unmarshal decrypted message: %v", err)
		}

		return decryptedMsg, nil
	}

	return message, nil
}

// pkcs7Pad adds PKCS#7 padding to a byte slice
func (c *SecureP2PClient) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS#7 padding from a byte slice
func (c *SecureP2PClient) pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("data is not a multiple of the block size")
	}

	padding := int(data[length-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Check that all padding bytes have the correct value
	for i := length - padding; i < length; i++ {
		if int(data[i]) != padding {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-padding], nil
}

// handleHandshake handles a handshake message
func (c *SecureP2PClient) handleHandshake(conn net.Conn, message Message) {
	sender := message.Sender
	senderPubKeyBytes, err := base64.StdEncoding.DecodeString(message.PublicKey)
	if err != nil {
		fmt.Printf("Failed to decode public key: %v\n", err)
		return
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(senderPubKeyBytes)
	if err != nil {
		fmt.Printf("Failed to parse public key: %v\n", err)
		return
	}

	senderPublicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		fmt.Printf("Public key is not an RSA key\n")
		return
	}

	// Generate a session key
	sessionKey := make([]byte, 32) // 256-bit key for AES-256
	_, err = rand.Read(sessionKey)
	if err != nil {
		fmt.Printf("Failed to generate session key: %v\n", err)
		return
	}

	// Encrypt the session key with the sender's public key
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		senderPublicKey,
		sessionKey,
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to encrypt session key: %v\n", err)
		return
	}

	// Store the contact information
	c.mu.Lock()
	c.Contacts[sender] = ContactInfo{
		Address:   message.Address,
		Port:      message.Port,
		PublicKey: senderPublicKey,
	}
	c.SessionKeys[sender] = sessionKey
	c.mu.Unlock()

	// Send response
	pubKeyDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %v\n", err)
		return
	}

	response := Message{
		Type:       "handshake_response",
		Sender:     c.Username,
		PublicKey:  base64.StdEncoding.EncodeToString(pubKeyDER),
		SessionKey: base64.StdEncoding.EncodeToString(encryptedSessionKey),
	}

	err = c.sendMessage(conn, response, "")
	if err != nil {
		fmt.Printf("Failed to send handshake response: %v\n", err)
		return
	}

	fmt.Printf("Handshake completed with %s\n", sender)
}

// connectToPeer connects to a peer
func (c *SecureP2PClient) connectToPeer(username, address string, port int) bool {
	c.mu.Lock()
	_, exists := c.Contacts[username]
	c.mu.Unlock()

	if exists {
		fmt.Printf("Already connected to %s\n", username)
		return true
	}

	// Connect to the peer
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", username, err)
		return false
	}
	defer conn.Close()

	// Get local IP
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	localIP := localAddr.IP.String()

	// Send handshake
	pubKeyDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %v\n", err)
		return false
	}

	handshake := Message{
		Type:      "handshake",
		Sender:    c.Username,
		Address:   localIP,
		Port:      c.Port,
		PublicKey: base64.StdEncoding.EncodeToString(pubKeyDER),
	}

	err = c.sendMessage(conn, handshake, "")
	if err != nil {
		fmt.Printf("Failed to send handshake: %v\n", err)
		return false
	}

	// Receive response
	response, err := c.receiveMessage(conn)
	if err != nil {
		fmt.Printf("Failed to receive handshake response: %v\n", err)
		return false
	}

	if response.Type == "handshake_response" {
		// Parse peer's public key
		peerPubKeyBytes, err := base64.StdEncoding.DecodeString(response.PublicKey)
		if err != nil {
			fmt.Printf("Failed to decode peer's public key: %v\n", err)
			return false
		}

		pubKeyInterface, err := x509.ParsePKIXPublicKey(peerPubKeyBytes)
		if err != nil {
			fmt.Printf("Failed to parse peer's public key: %v\n", err)
			return false
		}

		peerPublicKey, ok := pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			fmt.Printf("Peer's public key is not an RSA key\n")
			return false
		}

		// Decrypt the session key
		encryptedSessionKey, err := base64.StdEncoding.DecodeString(response.SessionKey)
		if err != nil {
			fmt.Printf("Failed to decode session key: %v\n", err)
			return false
		}

		sessionKey, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			c.PrivateKey,
			encryptedSessionKey,
			nil,
		)
		if err != nil {
			fmt.Printf("Failed to decrypt session key: %v\n", err)
			return false
		}

		// Store the contact information
		c.mu.Lock()
		c.Contacts[username] = ContactInfo{
			Address:   address,
			Port:      port,
			PublicKey: peerPublicKey,
		}
		c.SessionKeys[username] = sessionKey
		c.mu.Unlock()

		fmt.Printf("Connected to %s\n", username)
		return true
	}

	return false
}

// indexSharedFiles indexes files in the shared directory
func (c *SecureP2PClient) indexSharedFiles() {
	sharedDir := filepath.Join(c.StoragePath, "shared")
	files, err := ioutil.ReadDir(sharedDir)
	if err != nil {
		fmt.Printf("Failed to read shared directory: %v\n", err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(sharedDir, file.Name())
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Failed to read file %s: %v\n", file.Name(), err)
			continue
		}

		fileHash := sha256.Sum256(data)
		hashStr := fmt.Sprintf("%x", fileHash)

		c.Files[file.Name()] = hashStr

		if _, ok := c.FileSources[hashStr]; !ok {
			c.FileSources[hashStr] = []string{}
		}

		// Add self as source if not already there
		sourceExists := false
		for _, source := range c.FileSources[hashStr] {
			if source == c.Username {
				sourceExists = true
				break
			}
		}

		if !sourceExists {
			c.FileSources[hashStr] = append(c.FileSources[hashStr], c.Username)
		}
	}

	fmt.Printf("Indexed %d shared files\n", len(c.Files))
}

// handleFileListRequest handles a file list request
func (c *SecureP2PClient) handleFileListRequest(conn net.Conn, sender string) {
	c.mu.Lock()
	files := make(map[string]string)
	for filename, hash := range c.Files {
		files[filename] = hash
	}
	c.mu.Unlock()

	response := Message{
		Type:   "file_list_response",
		Sender: c.Username,
		Files:  files,
	}

	err := c.sendMessage(conn, response, sender)
	if err != nil {
		fmt.Printf("Failed to send file list: %v\n", err)
		return
	}

	fmt.Printf("Sent file list to %s\n", sender)
}

// requestFileList requests a file list from a peer
func (c *SecureP2PClient) requestFileList(username string) (map[string]string, error) {
	c.mu.Lock()
	contact, exists := c.Contacts[username]
	c.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("not connected to %s", username)
	}

	// Connect to the peer
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", contact.Address, contact.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", username, err)
	}
	defer conn.Close()

	// Send file list request
	request := Message{
		Type:   "file_list_request",
		Sender: c.Username,
	}

	err = c.sendMessage(conn, request, username)
	if err != nil {
		return nil, fmt.Errorf("failed to send file list request: %v", err)
	}

	// Receive response
	response, err := c.receiveMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive file list: %v", err)
	}

	if response.Type == "file_list_response" {
		fmt.Printf("Received file list from %s\n", username)

		// Update file sources
		c.mu.Lock()
		for filename, fileHash := range response.Files {
			if _, ok := c.FileSources[fileHash]; !ok {
				c.FileSources[fileHash] = []string{}
			}

			// Add sender as source if not already there
			sourceExists := false
			for _, source := range c.FileSources[fileHash] {
				if source == username {
					sourceExists = true
					break
				}
			}

			if !sourceExists {
				c.FileSources[fileHash] = append(c.FileSources[fileHash], username)
			}
		}
		c.mu.Unlock()

		return response.Files, nil
	}

	return nil, fmt.Errorf("unexpected response type: %s", response.Type)
}

// handleFileRequest handles a file request
func (c *SecureP2PClient) handleFileRequest(conn net.Conn, message Message) {
	sender := message.Sender
	filename := message.Filename
	fileHash := message.FileHash

	fmt.Printf("File request from %s for %s\n", sender, filename)

	// Check if we have the file
	c.mu.Lock()
	hash, exists := c.Files[filename]
	c.mu.Unlock()

	if !exists || hash != fileHash {
		// We don't have the file or hash doesn't match
		response := Message{
			Type:   "file_response",
			Sender: c.Username,
			Status: "error",
		}
		c.sendMessage(conn, response, sender)
		return
	}

	// Ask for consent
	fmt.Printf("%s is requesting file %s. Allow? (y/n): ", sender, filename)
	reader := bufio.NewReader(os.Stdin)
	consent, _ := reader.ReadString('\n')
	consent = strings.TrimSpace(consent)

	if consent != "y" && consent != "Y" {
		response := Message{
			Type:   "file_response",
			Sender: c.Username,
			Status: "denied",
		}
		c.sendMessage(conn, response, sender)
		fmt.Printf("File request denied\n")
		return
	}

	// Send the file
	sharedDir := filepath.Join(c.StoragePath, "shared")
	filePath := filepath.Join(sharedDir, filename)

	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file %s: %v\n", filename, err)
		response := Message{
			Type:   "file_response",
			Sender: c.Username,
			Status: "error",
		}
		c.sendMessage(conn, response, sender)
		return
	}

	// Verify the hash
	calculatedHash := sha256.Sum256(fileData)
	calculatedHashStr := fmt.Sprintf("%x", calculatedHash)

	if calculatedHashStr != fileHash {
		fmt.Printf("File hash mismatch\n")
		response := Message{
			Type:   "file_response",
			Sender: c.Username,
			Status: "error",
		}
		c.sendMessage(conn, response, sender)
		return
	}

	// Send the file
	response := Message{
		Type:     "file_transfer",
		Sender:   c.Username,
		Filename: filename,
		FileHash: fileHash,
		FileData: base64.StdEncoding.EncodeToString(fileData),
		Status:   "success",
	}

	err = c.sendMessage(conn, response, sender)
	if err != nil {
		fmt.Printf("Failed to send file: %v\n", err)
		return
	}

	fmt.Printf("File %s sent to %s\n", filename, sender)
}

// handleFileTransfer handles a file transfer
func (c *SecureP2PClient) handleFileTransfer(conn net.Conn, message Message) {
	sender := message.Sender
	filename := message.Filename
	fileHash := message.FileHash
	fileDataBase64 := message.FileData

	fmt.Printf("Receiving file %s from %s\n", filename, sender)

	// Decode the file data
	fileData, err := base64.StdEncoding.DecodeString(fileDataBase64)
	if err != nil {
		fmt.Printf("Failed to decode file data: %v\n", err)
		return
	}

	// Verify the hash
	calculatedHash := sha256.Sum256(fileData)
	calculatedHashStr := fmt.Sprintf("%x", calculatedHash)

	if calculatedHashStr != fileHash {
		fmt.Printf("File hash mismatch\n")
		return
	}

	// Save the file
	receivedDir := filepath.Join(c.StoragePath, "received")
	filePath := filepath.Join(receivedDir, filename)

	err = ioutil.WriteFile(filePath, fileData, 0644)
	if err != nil {
		fmt.Printf("Failed to save file: %v\n", err)
		return
	}

	// Update file sources
	c.mu.Lock()
	c.Files[filename] = fileHash

	if _, ok := c.FileSources[fileHash]; !ok {
		c.FileSources[fileHash] = []string{}
	}

	// Add sender as source if not already there
	sourceExists := false
	for _, source := range c.FileSources[fileHash] {
		if source == sender {
			sourceExists = true
			break
		}
	}

	if !sourceExists {
		c.FileSources[fileHash] = append(c.FileSources[fileHash], sender)
	}
	c.mu.Unlock()

	fmt.Printf("File %s received and verified from %s\n", filename, sender)
}

// requestFile requests a file from a peer
func (c *SecureP2PClient) requestFile(username, filename string) error {
	c.mu.Lock()
	contact, exists := c.Contacts[username]
	c.mu.Unlock()

	if !exists {
		return fmt.Errorf("not connected to %s", username)
	}

	// Get file hash
	fileHash := ""
	sources := []string{}

	// First check if we already know about this file
	c.mu.Lock()
	for knownFilename, hash := range c.Files {
		if knownFilename == filename {
			fileHash = hash
			sources = c.FileSources[hash]
			break
		}
	}
	c.mu.Unlock()

	// If we don't know the file, request file list first
	if fileHash == "" {
		fileList, err := c.requestFileList(username)
		if err != nil {
			return fmt.Errorf("failed to get file list: %v", err)
		}

		var ok bool
		fileHash, ok = fileList[filename]
		if !ok {
			return fmt.Errorf("%s doesn't have file %s", username, filename)
		}

		c.mu.Lock()
		sources = c.FileSources[fileHash]
		c.mu.Unlock()
	}

	// Check if user is a source for this file
	isSource := false
	for _, source := range sources {
		if source == username {
			isSource = true
			break
		}
	}

	if !isSource {
		return fmt.Errorf("%s is not a source for %s", username, filename)
	}

	// Connect to the peer
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", contact.Address, contact.Port))
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", username, err)
	}
	defer conn.Close()

	// Send file request
	request := Message{
		Type:     "file_request",
		Sender:   c.Username,
		Filename: filename,
		FileHash: fileHash,
	}

	err = c.sendMessage(conn, request, username)
	if err != nil {
		return fmt.Errorf("failed to send file request: %v", err)
	}

	// Receive response
	response, err := c.receiveMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to receive file response: %v", err)
	}

	if response.Type == "file_response" && response.Status == "denied" {
		return fmt.Errorf("file request denied by %s", username)
	} else if response.Type == "file_response" && response.Status == "error" {
		return fmt.Errorf("error getting file from %s", username)
	} else if response.Type == "file_transfer" && response.Status == "success" {
		// Handle file transfer
		c.handleFileTransfer(conn, response)
		return nil
	}

	return fmt.Errorf("unexpected response type: %s", response.Type)
}

// sendFile sends a file to a peer
func (c *SecureP2PClient) sendFile(username, filename string) error {
	c.mu.Lock()
	contact, exists := c.Contacts[username]
	hash, fileExists := c.Files[filename]
	c.mu.Unlock()

	if !exists {
		return fmt.Errorf("not connected to %s", username)
	}

	if !fileExists {
		return fmt.Errorf("file %s not found in shared files", filename)
	}

	// Connect to the peer
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", contact.Address, contact.Port))
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", username, err)
	}
	defer conn.Close()

	// Read the file
	sharedDir := filepath.Join(c.StoragePath, "shared")
	filePath := filepath.Join(sharedDir, filename)

	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	// Verify the hash
	calculatedHash := sha256.Sum256(fileData)
	calculatedHashStr := fmt.Sprintf("%x", calculatedHash)

	if calculatedHashStr != hash {
		return fmt.Errorf("file hash mismatch")
	}

	// Send the file
	message := Message{
		Type:     "file_transfer",
		Sender:   c.Username,
		Filename: filename,
		FileHash: hash,
		FileData: base64.StdEncoding.EncodeToString(fileData),
		Status:   "success",
	}

	err = c.sendMessage(conn, message, username)
	if err != nil {
		return fmt.Errorf("failed to send file: %v", err)
	}

	fmt.Printf("File %s sent to %s\n", filename, username)
	return nil
}

// handleKeyRotation handles a key rotation message
func (c *SecureP2PClient) handleKeyRotation(conn net.Conn, message Message) {
	sender := message.Sender

	fmt.Printf("Key rotation request from %s\n", sender)

	senderPubKeyBytes, err := base64.StdEncoding.DecodeString(message.PublicKey)
	if err != nil {
		fmt.Printf("Failed to decode public key: %v\n", err)
		return
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(senderPubKeyBytes)
	if err != nil {
		fmt.Printf("Failed to parse public key: %v\n", err)
		return
	}

	senderPublicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		fmt.Printf("Public key is not an RSA key\n")
		return
	}

	// Generate a new session key
	sessionKey := make([]byte, 32) // 256-bit key for AES-256
	_, err = rand.Read(sessionKey)
	if err != nil {
		fmt.Printf("Failed to generate session key: %v\n", err)
		return
	}

	// Encrypt the session key with the sender's new public key
	encryptedSessionKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		senderPublicKey,
		sessionKey,
		nil,
	)
	if err != nil {
		fmt.Printf("Failed to encrypt session key: %v\n", err)
		return
	}

	// Update the contact information
	c.mu.Lock()
	if _, ok := c.Contacts[sender]; ok {
		c.Contacts[sender].PublicKey = senderPublicKey
		c.SessionKeys[sender] = sessionKey
	} else {
		c.Contacts[sender] = ContactInfo{
			Address:   message.Address,
			Port:      message.Port,
			PublicKey: senderPublicKey,
		}
		c.SessionKeys[sender] = sessionKey
	}
	c.mu.Unlock()

	// Send response
	response := Message{
		Type:       "key_rotation_response",
		Sender:     c.Username,
		SessionKey: base64.StdEncoding.EncodeToString(encryptedSessionKey),
		Status:     "success",
	}

	err = c.sendMessage(conn, response, "") // Send unencrypted
	if err != nil {
		fmt.Printf("Failed to send key rotation response: %v\n", err)
		return
	}

	fmt.Printf("Key rotation completed for %s\n", sender)
}

// rotateKeys generates a new key pair and notifies all contacts
func (c *SecureP2PClient) rotateKeys() error {
	fmt.Println("Rotating keys...")

	// Generate new key pair
	fmt.Print("Create a password to encrypt your new private key: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	fmt.Print("Confirm password: ")
	confirmPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	if !bytes.Equal(password, confirmPassword) {
		return fmt.Errorf("passwords do not match")
	}

	// Generate key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(newPrivateKey)
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privateKeyBytes, password, x509.PEMCipherAES256)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %v", err)
	}

	keyPath := filepath.Join(c.StoragePath, "private", c.Username+"_key.pem")
	keyPEM := pem.EncodeToMemory(block)
	err = ioutil.WriteFile(keyPath, keyPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	// Extract public key
	newPublicKey := &newPrivateKey.PublicKey

	// Save public key
	publicKeyDER, err := x509.MarshalPKIXPublicKey(newPublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	publicKeyPEM := pem.EncodeToMemory(publicKeyBlock)

	pubKeyPath := filepath.Join(c.StoragePath, "public_"+c.Username+"_key.pem")
	err = ioutil.WriteFile(pubKeyPath, publicKeyPEM, 0644)
	if err != nil {
		return fmt.Errorf("failed to save public key: %v", err)
	}

	// Update client's keys
	oldPrivateKey := c.PrivateKey
	c.PrivateKey = newPrivateKey
	c.PublicKey = newPublicKey

	// Get local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return fmt.Errorf("failed to get local IP: %v", err)
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP.String()
	conn.Close()

	// Notify all contacts
	c.mu.Lock()
	contacts := make(map[string]ContactInfo)
	for username, contact := range c.Contacts {
		contacts[username] = contact
	}
	c.mu.Unlock()

	for username, contact := range contacts {
		// Connect to the contact
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", contact.Address, contact.Port))
		if err != nil {
			fmt.Printf("Failed to connect to %s: %v\n", username, err)
			continue
		}

		// Send key rotation message
		message := Message{
			Type:      "key_rotation",
			Sender:    c.Username,
			Address:   localIP,
			Port:      c.Port,
			PublicKey: base64.StdEncoding.EncodeToString(publicKeyDER),
		}

		// Use old key to sign the message
		data, err := json.Marshal(message)
		if err != nil {
			fmt.Printf("Failed to marshal message: %v\n", err)
			conn.Close()
			continue
		}

		hash := sha256.Sum256(data)
		signature, err := rsa.SignPKCS1v15(rand.Reader, oldPrivateKey, crypto.SHA256, hash[:])
		if err != nil {
			fmt.Printf("Failed to sign message: %v\n", err)
			conn.Close()
			continue
		}

		message.Signature = base64.StdEncoding.EncodeToString(signature)

		// Send the message
		err = c.sendMessage(conn, message, "") // Send unencrypted
		if err != nil {
			fmt.Printf("Failed to send key rotation message to %s: %v\n", username, err)
			conn.Close()
			continue
		}

		// Receive response
		response, err := c.receiveMessage(conn)
		if err != nil {
			fmt.Printf("Failed to receive key rotation response from %s: %v\n", username, err)
			conn.Close()
			continue
		}

		if response.Type == "key_rotation_response" && response.Status == "success" {
			// Decrypt the new session key
			encryptedSessionKey, err := base64.StdEncoding.DecodeString(response.SessionKey)
			if err != nil {
				fmt.Printf("Failed to decode session key from %s: %v\n", username, err)
				conn.Close()
				continue
			}

			sessionKey, err := rsa.DecryptOAEP(
				sha256.New(),
				rand.Reader,
				c.PrivateKey,
				encryptedSessionKey,
				nil,
			)
			if err != nil {
				fmt.Printf("Failed to decrypt session key from %s: %v\n", username, err)
				conn.Close()
				continue
			}

			// Update session key
			c.mu.Lock()
			c.SessionKeys[username] = sessionKey
			c.mu.Unlock()

			fmt.Printf("Key rotation completed with %s\n", username)
		} else {
			fmt.Printf("Key rotation failed with %s\n", username)
		}

		conn.Close()
	}

	// Update mDNS service
	c.Zeroconf.Shutdown()
	err = c.registerMDNSService()
	if err != nil {
		return fmt.Errorf("failed to update mDNS service: %v", err)
	}

	fmt.Println("Key rotation completed")
	return nil
}

// CLI runs a simple command-line interface
func (c *SecureP2PClient) CLI() {
	fmt.Println("Welcome to Secure P2P File Sharing")
	fmt.Println("Available commands:")
	fmt.Println("  discover - Discover peers on the network")
	fmt.Println("  contacts - List known contacts")
	fmt.Println("  files - List shared files")
	fmt.Println("  list <username> - List files available from a contact")
	fmt.Println("  get <username> <filename> - Request a file from a contact")
	fmt.Println("  send <username> <filename> - Send a file to a contact")
	fmt.Println("  rotate - Rotate your keys and update contacts")
	fmt.Println("  exit - Exit the program")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		switch command {
		case "discover":
			fmt.Println("Discovering peers...")
			c.discoverPeers()

		case "contacts":
			c.mu.Lock()
			if len(c.Contacts) == 0 {
				fmt.Println("No contacts")
			} else {
				for username, contact := range c.Contacts {
					fmt.Printf("%s at %s:%d\n", username, contact.Address, contact.Port)
				}
			}
			c.mu.Unlock()

		case "files":
			c.mu.Lock()
			if len(c.Files) == 0 {
				fmt.Println("No shared files")
			} else {
				for filename, hash := range c.Files {
					sources := c.FileSources[hash]
					fmt.Printf("%s (hash: %s) - Sources: %s\n", filename, hash, strings.Join(sources, ", "))
				}
			}
			c.mu.Unlock()

		case "list":
			if len(parts) < 2 {
				fmt.Println("Usage: list <username>")
				continue
			}
			username := parts[1]
			files, err := c.requestFileList(username)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

			if len(files) == 0 {
				fmt.Printf("%s has no shared files\n", username)
			} else {
				fmt.Printf("Files shared by %s:\n", username)
				for filename, hash := range files {
					fmt.Printf("  %s (hash: %s)\n", filename, hash)
				}
			}

		case "get":
			if len(parts) < 3 {
				fmt.Println("Usage: get <username> <filename>")
				continue
			}
			username := parts[1]
			filename := parts[2]
			err := c.requestFile(username, filename)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("File %s from %s received and saved\n", filename, username)

		case "send":
			if len(parts) < 3 {
				fmt.Println("Usage: send <username> <filename>")
				continue
			}
			username := parts[1]
			filename := parts[2]
			err := c.sendFile(username, filename)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("File %s sent to %s\n", filename, username)

		case "rotate":
			err := c.rotateKeys()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

		case "exit":
			fmt.Println("Exiting...")
			c.Zeroconf.Shutdown()
			c.Server.Close()
			return

		default:
			fmt.Println("Unknown command")
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <username> <port>")
		return
	}

	username := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid port: %v\n", err)
		return
	}

	storagePath := filepath.Join(".", "storage", username)
	client, err := NewSecureP2PClient(username, storagePath, port)
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	client.CLI()
}
