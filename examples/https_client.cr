# A small HTTPS client on Beryl's TLS 1.3, with no OpenSSL underneath.
#
#     crystal-alpha build --release -Dwithout_openssl examples/https_client.cr -o https_client
#     ./https_client --host example.com --port 443
#
# It sends one GET, prints the response, then one line that states what
# was negotiated:
#
#     negotiated: TLSv1.3 TLS_AES_128_GCM_SHA256 X25519 alpn=h2 resumed=false
#
# `--connections 2` connects twice with the same context, so the second
# connection can resume the first's session; `--key-update` sends a
# KeyUpdate that asks the server to update too, before the request.
# `--certificate-chain` and `--private-key` set the certificate the client
# presents when the server asks for one.
require "option_parser"
require "socket"
require "../src/beryl"

host = "localhost"
connect_address = ""
port = 443
path = "/"
trust_store_path = nil
certificate_chain_path = nil
private_key_path = nil
is_insecure = false
connection_count = 1
is_sending_key_update = false
list_of_alpn_protocols = [] of String
list_of_groups = [] of Beryl::TLS::NamedGroup
list_of_cipher_suites = [] of Beryl::TLS::CipherSuite

OptionParser.parse do |parser|
  parser.banner = "Usage: https_client [options]"
  parser.on("--host NAME", "Server name to verify and send as SNI (localhost)") { |value| host = value }
  parser.on("--connect ADDRESS", "Address to connect to, when it differs from --host") { |value| connect_address = value }
  parser.on("--port PORT", "Port (443)") { |value| port = value.to_i }
  parser.on("--path PATH", "Path to GET (/)") { |value| path = value }
  parser.on("--ca-certificates PATH", "Trust the PEM roots in PATH instead of the Mozilla roots") { |value| trust_store_path = value }
  parser.on("--certificate-chain PATH", "PEM chain (leaf first) to present when the server asks for a certificate") do |value|
    certificate_chain_path = value
  end
  parser.on("--private-key PATH", "PEM private key of that certificate") { |value| private_key_path = value }
  parser.on("--insecure", "Skip certificate verification") { is_insecure = true }
  parser.on("--connections COUNT", "Connections to make in a row (1)") { |value| connection_count = value.to_i }
  parser.on("--key-update", "Send a KeyUpdate before the request") { is_sending_key_update = true }
  parser.on("--alpn LIST", "Comma-separated ALPN protocols") { |value| list_of_alpn_protocols = value.split(',') }
  parser.on("--groups LIST", "Comma-separated groups to send key shares for: X25519, Secp256r1") do |value|
    list_of_groups = value.split(',').map { |name| Beryl::TLS::NamedGroup.parse(name) }
  end
  parser.on("--cipher-suites LIST", "Comma-separated TLS 1.3 suites") do |value|
    list_of_cipher_suites = value.split(',').map { |name| Beryl::TLS::CipherSuite.parse(name) }
  end
  parser.on("-h", "--help", "Show this help") do
    STDOUT.puts parser
    exit
  end
end

context = is_insecure ? Beryl::TLS::Context::Client.insecure : Beryl::TLS::Context::Client.new
if store_path = trust_store_path
  context.ca_certificates = store_path
end
if chain_path = certificate_chain_path
  context.certificate_chain = chain_path
end
if key_path = private_key_path
  context.private_key = key_path
end
context.alpn_protocols = list_of_alpn_protocols unless list_of_alpn_protocols.empty?
unless list_of_groups.empty?
  context.list_of_groups = list_of_groups
  context.list_of_key_share_groups = [list_of_groups.first]
end
context.list_of_cipher_suites = list_of_cipher_suites unless list_of_cipher_suites.empty?

connection_count.times do
  tcp_socket = TCPSocket.new(connect_address.empty? ? host : connect_address, port)
  socket = Beryl::TLS::Socket::Client.new(tcp_socket, context, sync_close: true, hostname: host)
  socket.update_keys(request_peer_update: true) if is_sending_key_update
  socket << "GET " << path << " HTTP/1.1\r\nHost: " << host << "\r\nConnection: close\r\n\r\n"
  socket.flush
  STDOUT.print socket.gets_to_end
  STDOUT.puts "negotiated: #{socket.tls_version} #{socket.cipher} #{socket.group} alpn=#{socket.alpn_protocol || "-"} resumed=#{socket.resumed?}"
  socket.close
end
