# A small HTTPS server on Beryl's TLS 1.3, with no OpenSSL underneath.
#
#     crystal-alpha build --release -Dwithout_openssl examples/https_server.cr -o https_server
#     ./https_server --certificate-chain chain.pem --private-key server.key --port 8443
#
# The interop scripts read what was negotiated from each client tool's own
# report (curl -v, openssl s_client, the Go client's ConnectionState).
#
# `--client-verify required --client-ca clients-ca.pem` asks every client
# for a certificate from that authority, and the response then names the
# client's subject (`client=CN=alice`). `--client-verify optional` asks
# without requiring one; `--any-client-chain` accepts a chain from any
# issuer (the CertificateVerify signature is still checked), for test
# tools that bring their own self-signed client certificates.
require "http/server"
require "option_parser"
require "../src/beryl"

# Accepts TLS connections as `Beryl::TLS::Server` does, and keeps each open
# connection by its client's address so the HTTP handler can read the
# client certificate of the connection a request came on.
class ClientCertificateServer
  include ::Socket::Server

  @socket_by_address = {} of String => Beryl::TLS::Socket::Server
  @mutex = Mutex.new

  def initialize(@tcp_server : TCPServer, @context : Beryl::TLS::Context::Server)
  end

  def accept : Beryl::TLS::Socket::Server
    wrap(@tcp_server.accept)
  end

  def accept? : Beryl::TLS::Socket::Server?
    if tcp = @tcp_server.accept?
      wrap(tcp)
    end
  end

  # The handshake runs on the connection's first read, in its own fiber.
  private def wrap(tcp : TCPSocket) : Beryl::TLS::Socket::Server
    socket = Beryl::TLS::Socket::Server.new(tcp, @context, sync_close: true, accept: false)
    socket.is_raising_io_errors = true
    @mutex.synchronize do
      @socket_by_address.reject! { |_, open_socket| open_socket.closed? }
      @socket_by_address[tcp.remote_address.to_s] = socket
    end
    socket
  end

  def close : Nil
    @tcp_server.close
  end

  def local_address : ::Socket::IPAddress
    @tcp_server.local_address
  end

  # The subject of the client certificate on the connection from
  # *address*, or "-" when it sent none.
  def client_subject(address : ::Socket::Address?) : String
    socket = @mutex.synchronize { @socket_by_address[address.to_s]? }
    socket.try(&.peer_certificate).try(&.subject.to_s) || "-"
  end
end

port = 8443
host = "127.0.0.1"
certificate_chain_path = "chain.pem"
private_key_path = "server.key"
list_of_alpn_protocols = [] of String
list_of_groups = [] of Beryl::TLS::NamedGroup
list_of_cipher_suites = [] of Beryl::TLS::CipherSuite
client_verify_mode = Beryl::TLS::ClientVerifyMode::None
client_ca_path = nil
is_accepting_any_client_chain = false

OptionParser.parse do |parser|
  parser.banner = "Usage: https_server [options]"
  parser.on("--host HOST", "Address to listen on (127.0.0.1)") { |value| host = value }
  parser.on("--port PORT", "Port to listen on (8443; 0 picks a free port)") { |value| port = value.to_i }
  parser.on("--certificate-chain PATH", "PEM chain, leaf first") { |value| certificate_chain_path = value }
  parser.on("--private-key PATH", "PEM private key") { |value| private_key_path = value }
  parser.on("--alpn LIST", "Comma-separated ALPN protocols, in preference order") { |value| list_of_alpn_protocols = value.split(',') }
  parser.on("--groups LIST", "Comma-separated groups: X25519, Secp256r1") do |value|
    list_of_groups = value.split(',').map { |name| Beryl::TLS::NamedGroup.parse(name) }
  end
  parser.on("--cipher-suites LIST", "Comma-separated TLS 1.3 suites") do |value|
    list_of_cipher_suites = value.split(',').map { |name| Beryl::TLS::CipherSuite.parse(name) }
  end
  parser.on("--client-verify MODE", "Ask clients for a certificate: none, optional or required (none)") do |value|
    client_verify_mode = Beryl::TLS::ClientVerifyMode.parse(value)
  end
  parser.on("--client-ca PATH", "PEM roots that issue client certificates") { |value| client_ca_path = value }
  parser.on("--any-client-chain", "Accept a client chain from any issuer; still check its CertificateVerify") do
    is_accepting_any_client_chain = true
  end
  parser.on("-h", "--help", "Show this help") do
    STDOUT.puts parser
    exit
  end
end

context = Beryl::TLS::Context::Server.new
context.certificate_chain = certificate_chain_path
context.private_key = private_key_path
context.alpn_protocols = list_of_alpn_protocols unless list_of_alpn_protocols.empty?
context.list_of_groups = list_of_groups unless list_of_groups.empty?
context.list_of_cipher_suites = list_of_cipher_suites unless list_of_cipher_suites.empty?
context.client_verify_mode = client_verify_mode
if path = client_ca_path
  context.client_ca_certificates = path
end
context.client_certificate_verifier = Beryl::TLS::InsecureVerifier.new if is_accepting_any_client_chain

tcp_server = TCPServer.new(host, port)
tls_server = ClientCertificateServer.new(tcp_server, context)
server = HTTP::Server.new do |http_context|
  http_context.response.content_type = "text/plain"
  http_context.response.print "hello from beryl\n"
  if client_verify_mode.requests_certificate?
    http_context.response.print "client=#{tls_server.client_subject(http_context.request.remote_address)}\n"
  end
end
server.bind(tls_server)
STDOUT.puts "listening on https://#{host}:#{tcp_server.local_address.port}"
STDOUT.flush
server.listen
