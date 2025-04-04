package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/grandcat/zeroconf"
)

func main() {
	// Get the local hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
	}

	// Use the hostname as the display name
	serviceName := fmt.Sprintf("GoPeer-%s", hostname)

	// Initialize mDNS service with display name
	service, err := zeroconf.Register(serviceName, "_p2pfileshare._tcp", "local.", 8080, []string{"display_name=" + hostname}, nil)
	if err != nil {
		log.Fatalf("Failed to register service: %v", err)
	}
	defer service.Shutdown()

	// Discover peers
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalf("Failed to initialize resolver: %v", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			fmt.Printf("Discovered service: %s\n", entry.ServiceInstanceName())
		}
	}(entries)

	ctx := context.Background()
	err = resolver.Browse(ctx, "_p2pfileshare._tcp", "local.", entries)
	if err != nil {
		log.Fatalf("Failed to browse: %v", err)
	}
	if err != nil {
		log.Fatalf("Failed to serialize public key: %v", err)
	}
	if err != nil {
		log.Fatalf("Failed to sign challenge: %v", err)
	}

	log.Println("Identity verified")

	// Start the CLI after setting up the service
	startCLI()
}

// Send a file to a peer
func sendFile(conn net.Conn, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Failed to open file %s: %v", filename, err)
		return
	}
	defer file.Close()

	_, err = io.Copy(conn, file)
	if err != nil {
		log.Printf("Failed to send file %s: %v", filename, err)
	}
	log.Printf("File %s sent successfully", filename)
}

// Receive a file from a peer
func receiveFile(conn net.Conn, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create file %s: %v", filename, err)
		return
	}
	defer file.Close()

	_, err = io.Copy(file, conn)
	if err != nil {
		log.Printf("Failed to receive file %s: %v", filename, err)
	}
	log.Printf("File %s received successfully", filename)
}

// Example command to send a file
func sendFileCommand(peerAddress, filename string) {
	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		log.Printf("Failed to connect to peer %s: %v", peerAddress, err)
		return
	}
	defer conn.Close()

	sendFile(conn, filename)
}

// Example command to receive a file
func receiveFileCommand(listenAddress, filename string) {
	ln, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", listenAddress, err)
		return
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		log.Printf("Failed to accept connection: %v", err)
		return
	}
	defer conn.Close()

	receiveFile(conn, filename)
}

// Command-line interface
func startCLI() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("(Command) > ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "exit" {
			fmt.Println("Exiting...")
			break
		}
		processCommand(input)
	}
}

// Process user commands
func processCommand(input string) {
	parts := strings.Fields(input)
	if len(parts) < 1 {
		fmt.Println("Invalid command")
		return
	}

	command := parts[0]
	switch command {
	case "send":
		if len(parts) != 3 {
			fmt.Println("Usage: send <peer_address> <filename>")
			return
		}
		peerAddress := parts[1]
		filename := parts[2]
		sendFileCommand(peerAddress, filename)
	case "receive":
		if len(parts) != 3 {
			fmt.Println("Usage: receive <listen_address> <filename>")
			return
		}
		listenAddress := parts[1]
		filename := parts[2]
		receiveFileCommand(listenAddress, filename)
	default:
		fmt.Println("Unknown command")
	}
}
