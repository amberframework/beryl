# A small HTTPS server on Beryl's TLS 1.3, with no OpenSSL underneath.
#
#     crystal-alpha build --release -Dwithout_openssl examples/https_server.cr -o https_server
#     ./https_server --certificate-chain chain.pem --private-key server.key --port 8443
#
# The interop scripts read what was negotiated from each client tool's own
# report (curl -v, openssl s_client, the Go client's ConnectionState).
require "http/server"
require "option_parser"
require "../src/beryl"

port = 8443
host = "127.0.0.1"
certificate_chain_path = "chain.pem"
private_key_path = "server.key"
list_of_alpn_protocols = [] of String
list_of_groups = [] of Beryl::TLS::NamedGroup
list_of_cipher_suites = [] of Beryl::TLS::CipherSuite

OptionParser.parse do |parser|
  parser.banner = "Usage: https_server [options]"
  parser.on("--host HOST", "Address to listen on (127.0.0.1)") { |value| host = value }
  parser.on("--port PORT", "Port to listen on (8443)") { |value| port = value.to_i }
  parser.on("--certificate-chain PATH", "PEM chain, leaf first") { |value| certificate_chain_path = value }
  parser.on("--private-key PATH", "PEM private key") { |value| private_key_path = value }
  parser.on("--alpn LIST", "Comma-separated ALPN protocols, in preference order") { |value| list_of_alpn_protocols = value.split(',') }
  parser.on("--groups LIST", "Comma-separated groups: X25519, Secp256r1") do |value|
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

context = Beryl::TLS::Context::Server.new
context.certificate_chain = certificate_chain_path
context.private_key = private_key_path
context.alpn_protocols = list_of_alpn_protocols unless list_of_alpn_protocols.empty?
context.list_of_groups = list_of_groups unless list_of_groups.empty?
context.list_of_cipher_suites = list_of_cipher_suites unless list_of_cipher_suites.empty?

server = HTTP::Server.new do |http_context|
  http_context.response.content_type = "text/plain"
  http_context.response.print "hello from beryl\n"
end
server.bind(Beryl::TLS::Server.new(TCPServer.new(host, port), context))
STDOUT.puts "listening on https://#{host}:#{port}"
STDOUT.flush
server.listen
