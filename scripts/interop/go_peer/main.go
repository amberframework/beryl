// Go crypto/tls peer for Beryl's interop matrix.
//
//	go_peer server -addr 127.0.0.1:0 -cert chain.pem -key server.key [-groups P256] [-alpn h2,http/1.1]
//	go_peer client -addr 127.0.0.1:8443 -servername localhost -ca ca.pem [-groups P256] [-alpn http/1.1] [-connections 2] [-cert client-chain.pem -key client.key]
//
// The server prints "listening on ADDRESS" once it accepts connections and
// answers every HTTP request with "hello from go". The client sends one GET
// per connection and prints one line per connection (with -cert and -key it
// presents that client certificate when the server asks for one):
//
//	negotiated: TLS_AES_128_GCM_SHA256 X25519 alpn=http/1.1 resumed=false body=hello from beryl
//
// TLS 1.3 only. Go chooses the TLS 1.3 suite itself and cannot be told to
// use one, so the matrix varies suites from the Beryl side.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func curvePreferences(names string) []tls.CurveID {
	if names == "" {
		return nil
	}
	var list []tls.CurveID
	for _, name := range strings.Split(names, ",") {
		switch name {
		case "X25519":
			list = append(list, tls.X25519)
		case "P256":
			list = append(list, tls.CurveP256)
		default:
			fmt.Fprintf(os.Stderr, "unknown group %q\n", name)
			os.Exit(2)
		}
	}
	return list
}

func protocols(names string) []string {
	if names == "" {
		return nil
	}
	return strings.Split(names, ",")
}

func runServer(arguments []string) {
	flags := flag.NewFlagSet("server", flag.ExitOnError)
	address := flags.String("addr", "127.0.0.1:0", "address to listen on")
	certificatePath := flags.String("cert", "chain.pem", "PEM chain, leaf first")
	keyPath := flags.String("key", "server.key", "PEM private key")
	groups := flags.String("groups", "", "comma-separated groups: X25519, P256")
	alpn := flags.String("alpn", "", "comma-separated ALPN protocols")
	flags.Parse(arguments)

	certificate, err := tls.LoadX509KeyPair(*certificatePath, *keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	config := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curvePreferences(*groups),
		NextProtos:       protocols(*alpn),
	}
	listener, err := tls.Listen("tcp", *address, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("listening on %s\n", listener.Addr())
	os.Stdout.Sync()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, "hello from go\n")
	})
	server := &http.Server{Handler: handler, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	server.Serve(listener)
}

func runClient(arguments []string) {
	flags := flag.NewFlagSet("client", flag.ExitOnError)
	address := flags.String("addr", "127.0.0.1:8443", "address to connect to")
	serverName := flags.String("servername", "localhost", "name to verify and send as SNI")
	caPath := flags.String("ca", "ca.pem", "PEM roots to trust")
	groups := flags.String("groups", "", "comma-separated groups: X25519, P256")
	alpn := flags.String("alpn", "", "comma-separated ALPN protocols")
	connections := flags.Int("connections", 1, "connections to make in a row")
	clientCertificatePath := flags.String("cert", "", "PEM client chain, leaf first, presented when the server asks")
	clientKeyPath := flags.String("key", "", "PEM private key of the client certificate")
	flags.Parse(arguments)

	roots := x509.NewCertPool()
	pem, err := os.ReadFile(*caPath)
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		fmt.Fprintln(os.Stderr, "could not read the roots", err)
		os.Exit(1)
	}
	config := &tls.Config{
		RootCAs:            roots,
		ServerName:         *serverName,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   curvePreferences(*groups),
		NextProtos:         protocols(*alpn),
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}
	if *clientCertificatePath != "" {
		clientCertificate, err := tls.LoadX509KeyPair(*clientCertificatePath, *clientKeyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "client certificate:", err)
			os.Exit(1)
		}
		config.Certificates = []tls.Certificate{clientCertificate}
	}
	for count := 0; count < *connections; count++ {
		connection, err := tls.Dial("tcp", *address, config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "handshake:", err)
			os.Exit(1)
		}
		fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *serverName)
		response, err := io.ReadAll(bufio.NewReader(connection))
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		state := connection.ConnectionState()
		body := string(response)
		if index := strings.Index(body, "\r\n\r\n"); index >= 0 {
			body = strings.TrimSpace(body[index+4:])
		}
		alpnProtocol := state.NegotiatedProtocol
		if alpnProtocol == "" {
			alpnProtocol = "-"
		}
		fmt.Printf("negotiated: %s %s alpn=%s resumed=%t body=%s\n",
			tls.CipherSuiteName(state.CipherSuite), state.CurveID, alpnProtocol, state.DidResume, body)
		connection.Close()
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_peer server|client [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: go_peer server|client [flags]")
		os.Exit(2)
	}
}
