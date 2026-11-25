#!/usr/bin/ruby
# frozen_string_literal: true

# Runs Beryl's TLS 1.3 interop matrix: the example server against OpenSSL
# s_client, curl and Go's crypto/tls, and the example client against
# OpenSSL s_server and Go, over every suite, both groups, HelloRetryRequest,
# ALPN, resumption, KeyUpdate and the three key types; and OpenSSL s_client
# and the Go client presenting client certificates to the example server
# in required mode, which answers with the client's subject.
#
#   /usr/bin/ruby scripts/interop/install_tools.rb TOOLS
#   /usr/bin/ruby scripts/interop/run_matrix.rb TOOLS [--crystal crystal-alpha] [--report matrix.md]
#
# TOOLS is the prefix install_tools.rb filled (OpenSSL 4.1.0, curl 8.23.0
# built against it, Go 1.27.4, each checked by sha256). Certificates and
# keys are made fresh in a scratch folder by that OpenSSL, so none is kept
# in the repository. Each cell prints `ok` or `FAILED` with the line it
# looked for; the run exits 1 when any cell fails.

require "fileutils"
require "open3"
require "optparse"
require "socket"
require "timeout"
require "tmpdir"
require_relative "test_certificates"

REPOSITORY_ROOT = File.expand_path("../..", __dir__)

options = { crystal: "crystal-alpha", report: nil }
OptionParser.new do |parser|
  parser.banner = "usage: run_matrix.rb TOOLS [options]"
  parser.on("--crystal COMMAND", "Crystal compiler (crystal-alpha)") { |value| options[:crystal] = value }
  parser.on("--report PATH", "Write the matrix as Markdown to PATH") { |value| options[:report] = value }
end.parse!
tools = File.expand_path(ARGV[0] || abort("usage: run_matrix.rb TOOLS [options]"))

OPENSSL = File.join(tools, "openssl", "bin", "openssl")
CURL = File.join(tools, "curl", "bin", "curl")
GO = File.join(tools, "go", "bin", "go")
TOOL_ENVIRONMENT = {
  "LD_LIBRARY_PATH" => File.join(tools, "openssl", "lib"),
  "DYLD_LIBRARY_PATH" => File.join(tools, "openssl", "lib"),
}.freeze

def run_checked(environment, *command, chdir: Dir.pwd)
  output, status = Open3.capture2e(environment, *command, chdir: chdir)
  raise "failed (#{status.exitstatus}): #{command.join(" ")}\n#{output}" unless status.success?

  output
end

def free_port
  server = TCPServer.new("127.0.0.1", 0)
  port = server.addr[1]
  server.close
  port
end

# Starts a server process and waits until *ready* appears in its output or
# the port accepts connections. Returns the pid, the port and the output
# reader.
def start_server(command, port: nil, ready: nil)
  reader, writer = IO.pipe
  pid = Process.spawn(TOOL_ENVIRONMENT, *command, out: writer, err: writer, pgroup: true)
  writer.close
  output = +""
  Timeout.timeout(20) do
    loop do
      if ready
        line = reader.gets or raise "the server exited: #{output}"
        output << line
        if (match = line.match(ready))
          port ||= match[1].to_i
          break
        end
      else
        begin
          TCPSocket.new("127.0.0.1", port).close
          break
        rescue Errno::ECONNREFUSED
          sleep 0.05
        end
      end
    end
  end
  [pid, port, reader]
end

def stop_server(pid)
  Process.kill("TERM", -pid)
rescue Errno::ESRCH
ensure
  begin
    Process.wait(pid)
  rescue Errno::ECHILD
  end
end

# Runs a client to its end. *stdin_data* is a string, or a list of strings
# written one second apart and followed by two seconds of open input, for an
# interactive s_client that reads its commands only after the handshake.
def client_output(command, stdin_data: "")
  Timeout.timeout(30) do
    Open3.popen2e(TOOL_ENVIRONMENT, *command) do |stdin, output, _|
      reader = Thread.new { output.read }
      if stdin_data.is_a?(Array)
        stdin_data.each do |piece|
          sleep 1
          stdin.write(piece)
          stdin.flush
        end
        sleep 2
      else
        stdin.write(stdin_data)
      end
      stdin.close
      reader.value
    end
  end
rescue Timeout::Error
  "TIMEOUT"
end

Dir.mktmpdir("beryl-interop") do |work|
  # Certificates: one root, a leaf per key type for localhost and 127.0.0.1,
  # and a client certificate from the same root.
  TestCertificates.generate(OPENSSL, TOOL_ENVIRONMENT, work)
  TestCertificates.generate_client(OPENSSL, TOOL_ENVIRONMENT, work)

  # The Beryl examples, linked without OpenSSL, and the Go peer.
  %w(https_server https_client).each do |name|
    run_checked({}, options[:crystal], "build", "-Dwithout_openssl", File.join(REPOSITORY_ROOT, "examples", "#{name}.cr"),
                "-o", File.join(work, name), chdir: REPOSITORY_ROOT)
  end
  go_environment = { "GOTOOLCHAIN" => "local", "GOFLAGS" => "-mod=mod -modcacherw", "CGO_ENABLED" => "0",
                     "GOPATH" => File.join(work, "gopath"), "GOCACHE" => File.join(work, "gocache") }
  run_checked(go_environment, GO, "build", "-o", File.join(work, "go_peer"), ".", chdir: File.join(__dir__, "go_peer"))

  beryl_server = File.join(work, "https_server")
  beryl_client = File.join(work, "https_client")
  go_peer = File.join(work, "go_peer")
  ca = File.join(work, "ca.pem")
  chain = ->(kind) { File.join(work, "#{kind}-chain.pem") }
  key = ->(kind) { File.join(work, "#{kind}.key") }
  suites = %w(TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_256_GCM_SHA384)

  results = []
  record = lambda do |peer, case_name, output, list_of_expected|
    missing = list_of_expected.reject { |pattern| output.match?(pattern) }
    results << { peer: peer, case_name: case_name, ok: missing.empty?, missing: missing.map(&:source) }
    status = missing.empty? ? "ok" : "FAILED (looked for #{missing.map(&:source).join(", ")})"
    puts format("%-34s %-46s %s", peer, case_name, status)
    puts output.lines.last(15).map { |line| "    | #{line}" }.join unless missing.empty?
  end

  with_beryl_server = lambda do |kind, extra, &block|
    pid, port, = start_server([beryl_server, "--port", "0", "--certificate-chain", chain.(kind), "--private-key", key.(kind), *extra],
                              ready: %r{listening on https://127\.0\.0\.1:(\d+)})
    begin
      block.call(port)
    ensure
      stop_server(pid)
    end
  end

  # Beryl server, OpenSSL s_client.
  s_client = ->(port, *arguments) { [OPENSSL, "s_client", "-connect", "127.0.0.1:#{port}", "-servername", "localhost", "-CAfile", ca, "-verify_return_error", *arguments] }
  get = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
  suites.each do |suite|
    with_beryl_server.call("p256", []) do |port|
      output = client_output(s_client.(port, "-ciphersuites", suite, "-ign_eof"), stdin_data: get)
      record.call("openssl s_client -> Beryl server", "#{suite}, P-256 certificate", output, [/Ciphersuite: #{suite}|Cipher is #{suite}/, /hello from beryl/])
    end
  end
  { "rsa" => /rsa_pss_rsae_sha256|RSA-PSS/, "ed25519" => /ed25519|Ed25519/ }.each do |kind, signature|
    with_beryl_server.call(kind, []) do |port|
      output = client_output(s_client.(port, "-ign_eof"), stdin_data: get)
      record.call("openssl s_client -> Beryl server", "#{kind} certificate", output, [signature, /hello from beryl/])
    end
  end
  with_beryl_server.call("p256", []) do |port|
    output = client_output(s_client.(port, "-groups", "P-256", "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "secp256r1 key share", output, [/P-256|prime256v1|secp256r1/, /hello from beryl/])
  end
  with_beryl_server.call("p256", ["--groups", "Secp256r1"]) do |port|
    output = client_output(s_client.(port, "-groups", "X25519:P-256", "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "HelloRetryRequest to secp256r1", output, [/P-256|prime256v1|secp256r1/, /hello from beryl/])
  end
  with_beryl_server.call("p256", ["--alpn", "h2,http/1.1"]) do |port|
    output = client_output(s_client.(port, "-alpn", "http/1.1", "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "ALPN http/1.1", output, [%r{ALPN protocol: http/1\.1}, /hello from beryl/])
  end
  with_beryl_server.call("p256", []) do |port|
    session = File.join(work, "session.pem")
    client_output(s_client.(port, "-sess_out", session, "-ign_eof"), stdin_data: get)
    output = client_output(s_client.(port, "-sess_in", session, "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "resumption with a ticket", output, [/Reused, TLSv1\.3/, /hello from beryl/])
  end
  with_beryl_server.call("p256", []) do |port|
    # Interactive commands work only without -ign_eof and -quiet.
    output = client_output(s_client.(port, "-msg"), stdin_data: ["K\n", get])
    record.call("openssl s_client -> Beryl server", "KeyUpdate (update requested)", output,
                [/>>> TLS 1\.3, Handshake \[length 0005\], KeyUpdate/, /<<< TLS 1\.3, Handshake \[length 0005\], KeyUpdate/, /hello from beryl/])
  end

  # Beryl server, curl.
  curl = ->(port, *arguments) { [CURL, "-sS", "-v", "--cacert", ca, "--tlsv1.3", *arguments, "https://localhost:#{port}/"] }
  suites.each do |suite|
    with_beryl_server.call("p256", []) do |port|
      output = client_output(curl.(port, "--tls13-ciphers", suite))
      record.call("curl -> Beryl server", suite, output, [/#{suite}/, /hello from beryl/])
    end
  end
  { "X25519" => /X25519|x25519/, "P-256" => /P-256|prime256v1|secp256r1/ }.each do |group, pattern|
    with_beryl_server.call("rsa", []) do |port|
      output = client_output(curl.(port, "--curves", group))
      record.call("curl -> Beryl server", "#{group}, RSA certificate", output, [pattern, /hello from beryl/])
    end
  end
  with_beryl_server.call("ed25519", ["--alpn", "http/1.1"]) do |port|
    output = client_output(curl.(port, "--http1.1"))
    record.call("curl -> Beryl server", "ALPN http/1.1, Ed25519 certificate", output, [%r{ALPN: server accepted http/1\.1}, /hello from beryl/])
  end

  # Beryl server, Go client.
  go_client = ->(port, *arguments) { [go_peer, "client", "-addr", "127.0.0.1:#{port}", "-servername", "localhost", "-ca", ca, *arguments] }
  %w(p256 rsa ed25519).each do |kind|
    with_beryl_server.call(kind, []) do |port|
      output = client_output(go_client.(port))
      record.call("Go client -> Beryl server", "#{kind} certificate, Go's default groups", output, [/negotiated: TLS_AES_128_GCM_SHA256 X25519/, /body=hello from beryl/])
    end
  end
  with_beryl_server.call("p256", ["--groups", "Secp256r1"]) do |port|
    output = client_output(go_client.(port))
    record.call("Go client -> Beryl server", "HelloRetryRequest to secp256r1", output, [/CurveP256/, /body=hello from beryl/])
  end
  with_beryl_server.call("p256", ["--cipher-suites", "TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384"]) do |port|
    output = client_output(go_client.(port, "-groups", "P256"))
    record.call("Go client -> Beryl server", "ChaCha20-Poly1305 chosen by Beryl, P-256", output, [/TLS_CHACHA20_POLY1305_SHA256 CurveP256/, /body=hello from beryl/])
  end
  with_beryl_server.call("p256", ["--alpn", "http/1.1"]) do |port|
    output = client_output(go_client.(port, "-alpn", "http/1.1", "-connections", "2"))
    record.call("Go client -> Beryl server", "ALPN and resumption", output, [%r{alpn=http/1\.1 resumed=false}, %r{alpn=http/1\.1 resumed=true}])
  end

  # Beryl server requiring a client certificate: OpenSSL s_client and the
  # Go client present one from the interop root, and Beryl answers with its
  # subject.
  client_subject = /client=#{Regexp.escape(TestCertificates::CLIENT_SUBJECT)}/
  requiring_client_certificates = ["--client-verify", "required", "--client-ca", ca]
  with_beryl_server.call("p256", requiring_client_certificates) do |port|
    output = client_output(s_client.(port, "-cert", File.join(work, "client.pem"), "-key", key.("client"), "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "client certificate, required", output, [/hello from beryl/, client_subject])
  end
  with_beryl_server.call("p256", requiring_client_certificates) do |port|
    output = client_output(s_client.(port, "-ign_eof"), stdin_data: get)
    record.call("openssl s_client -> Beryl server", "no client certificate, required (certificate_required)", output,
                [/certificate required/])
  end
  with_beryl_server.call("rsa", requiring_client_certificates) do |port|
    output = client_output(go_client.(port, "-cert", chain.("client"), "-key", key.("client"), "-connections", "2"))
    record.call("Go client -> Beryl server", "client certificate, required, then resumed", output,
                [/resumed=false body=hello from beryl\s+#{client_subject.source}/, /resumed=true body=hello from beryl\s+#{client_subject.source}/])
  end

  # Beryl client, OpenSSL s_server.
  with_s_server = lambda do |kind, extra, &block|
    port = free_port
    pid, = start_server([OPENSSL, "s_server", "-accept", port.to_s, "-cert", File.join(work, "#{kind}.pem"),
                         "-cert_chain", ca, "-key", key.(kind), "-tls1_3", "-www", *extra], port: port)
    begin
      block.call(port)
    ensure
      stop_server(pid)
    end
  end
  beryl = ->(port, *arguments) { [beryl_client, "--host", "localhost", "--connect", "127.0.0.1", "--port", port.to_s, "--ca-certificates", ca, *arguments] }
  suites.each do |suite|
    with_s_server.call("p256", ["-ciphersuites", suite]) do |port|
      output = client_output(beryl.(port))
      record.call("Beryl client -> openssl s_server", suite, output, [/negotiated: TLSv1\.3 #{suite} X25519/])
    end
  end
  %w(rsa ed25519).each do |kind|
    with_s_server.call(kind, []) do |port|
      output = client_output(beryl.(port))
      record.call("Beryl client -> openssl s_server", "#{kind} certificate", output, [/negotiated: TLSv1\.3/])
    end
  end
  with_s_server.call("p256", ["-groups", "P-256"]) do |port|
    output = client_output(beryl.(port))
    record.call("Beryl client -> openssl s_server", "HelloRetryRequest to secp256r1", output, [/negotiated: TLSv1\.3 \S+ Secp256r1/])
  end
  with_s_server.call("p256", ["-alpn", "http/1.1"]) do |port|
    output = client_output(beryl.(port, "--alpn", "h2,http/1.1"))
    record.call("Beryl client -> openssl s_server", "ALPN http/1.1", output, [%r{alpn=http/1\.1}])
  end
  with_s_server.call("p256", []) do |port|
    output = client_output(beryl.(port, "--connections", "2"))
    record.call("Beryl client -> openssl s_server", "resumption with a ticket", output, [/resumed=false/, /resumed=true/])
  end
  with_s_server.call("p256", []) do |port|
    output = client_output(beryl.(port, "--key-update"))
    record.call("Beryl client -> openssl s_server", "KeyUpdate (update requested)", output, [/negotiated: TLSv1\.3/])
  end

  # Beryl client, Go server.
  with_go_server = lambda do |kind, extra, &block|
    pid, port, = start_server([go_peer, "server", "-addr", "127.0.0.1:0", "-cert", chain.(kind), "-key", key.(kind), *extra],
                              ready: /listening on 127\.0\.0\.1:(\d+)/)
    begin
      block.call(port)
    ensure
      stop_server(pid)
    end
  end
  %w(p256 rsa ed25519).each do |kind|
    with_go_server.call(kind, []) do |port|
      output = client_output(beryl.(port))
      record.call("Beryl client -> Go server", "#{kind} certificate", output, [/hello from go/, /negotiated: TLSv1\.3/])
    end
  end
  with_go_server.call("p256", ["-groups", "P256"]) do |port|
    output = client_output(beryl.(port))
    record.call("Beryl client -> Go server", "HelloRetryRequest to secp256r1", output, [/hello from go/, /Secp256r1/])
  end
  suites.each do |suite|
    with_go_server.call("p256", []) do |port|
      output = client_output(beryl.(port, "--cipher-suites", suite))
      record.call("Beryl client -> Go server", suite, output, [/hello from go/, /negotiated: TLSv1\.3 #{suite}/])
    end
  end
  with_go_server.call("p256", ["-alpn", "http/1.1"]) do |port|
    output = client_output(beryl.(port, "--alpn", "http/1.1", "--connections", "2", "--key-update"))
    record.call("Beryl client -> Go server", "ALPN, resumption and KeyUpdate", output, [%r{alpn=http/1\.1 resumed=false}, %r{alpn=http/1\.1 resumed=true}])
  end

  failures = results.reject { |result| result[:ok] }
  versions = [run_checked(TOOL_ENVIRONMENT, OPENSSL, "version").strip, run_checked(TOOL_ENVIRONMENT, CURL, "--version").lines.first.strip,
              run_checked({}, GO, "version").strip]
  puts "interop: #{results.size} cells, #{results.size - failures.size} ok, #{failures.size} failed"
  puts "tools: #{versions.join("; ")}"
  if (report_path = options[:report])
    File.open(report_path, "w") do |report|
      report.puts "# Beryl TLS 1.3 interop matrix"
      report.puts
      report.puts "Tools: #{versions.join("; ")}. #{results.size} cells, #{failures.size} failed."
      report.puts
      report.puts "| Peers | Case | Result |"
      report.puts "|---|---|---|"
      results.each do |result|
        report.puts "| #{result[:peer]} | #{result[:case_name]} | #{result[:ok] ? "ok" : "FAILED: #{result[:missing].join(", ")}"} |"
      end
    end
  end
  exit(failures.empty? ? 0 : 1)
end
