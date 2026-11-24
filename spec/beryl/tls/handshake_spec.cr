require "../../spec_helper"

private alias TLS = Beryl::TLS
private alias KeyKind = TestCertificateAuthority::KeyKind

private def exchange_data(client : TLS::Socket::Client, server : TLS::Socket::Server) : Nil
  client.print "ping from the client\n"
  client.flush
  server.gets.should eq("ping from the client")
  server.print "pong from the server\n"
  server.flush
  client.gets.should eq("pong from the server")
end

private def expect_connected(client, server) : {TLS::Socket::Client, TLS::Socket::Server}
  raise client if client.is_a?(Exception)
  raise server if server.is_a?(Exception)
  {client, server}
end

# Wraps an IO and keeps a copy of every byte read through it.
private class RecordingIO < IO
  getter received = IO::Memory.new

  def initialize(@io : IO)
  end

  def read(slice : Bytes) : Int32
    count = @io.read(slice)
    @received.write(slice[0, count])
    count
  end

  def write(slice : Bytes) : Nil
    @io.write(slice)
  end

  def flush : Nil
    @io.flush
  end

  def close : Nil
    @io.close
  end
end

# The content type of each record in *bytes*.
private def list_of_record_types(bytes : Bytes) : Array(UInt8)
  list = [] of UInt8
  offset = 0
  while offset + 5 <= bytes.size
    list << bytes[offset]
    offset += 5 + ((bytes[offset + 3].to_i << 8) | bytes[offset + 4].to_i)
  end
  list
end

describe "Beryl::TLS handshakes over a socket pair" do
  TLS::CipherSuite.each do |suite|
    TLS::NamedGroup.each do |group|
      next unless TLS::NamedGroup.supported_value?(group.value)
      KeyKind.each do |key_kind|
        it "completes with #{suite}, #{group} and a #{key_kind} certificate, and carries data both ways" do
          server_context = TlsHarness.server_context(key_kind)
          server_context.list_of_cipher_suites = [suite]
          server_context.list_of_groups = [group]
          client_context = TlsHarness.client_context
          client_context.list_of_key_share_groups = [group]
          TlsHarness.connect(server_context, client_context) do |client_result, server_result|
            client, server = expect_connected(client_result, server_result)
            client.cipher.should eq(suite.to_s)
            server.cipher.should eq(suite.to_s)
            client.group.should eq(group)
            client.tls_version.should eq("TLSv1.3")
            client.peer_certificate.should eq(server_context.certified_key.list_of_certificates.first)
            exchange_data(client, server)
          end
        end
      end
    end
  end

  it "answers a HelloRetryRequest when the server wants another group" do
    server_context = TlsHarness.server_context
    server_context.list_of_groups = [TLS::NamedGroup::Secp256r1]
    TlsHarness.connect(server_context, TlsHarness.client_context) do |client_result, server_result|
      client, server = expect_connected(client_result, server_result)
      client.group.should eq(TLS::NamedGroup::Secp256r1)
      exchange_data(client, server)
    end
  end

  it "answers a HelloRetryRequest without middlebox compatibility mode or GREASE" do
    server_context = TlsHarness.server_context
    server_context.list_of_groups = [TLS::NamedGroup::Secp256r1]
    client_context = TlsHarness.client_context
    client_context.is_middlebox_compatible = false
    client_context.is_sending_grease = false
    TlsHarness.connect(server_context, client_context) do |client_result, server_result|
      client, server = expect_connected(client_result, server_result)
      exchange_data(client, server)
    end
  end

  it "negotiates ALPN by the server's preference" do
    server_context = TlsHarness.server_context
    server_context.alpn_protocols = ["h2", "http/1.1"]
    client_context = TlsHarness.client_context
    client_context.alpn_protocols = ["http/1.1", "h2"]
    TlsHarness.connect(server_context, client_context) do |client_result, server_result|
      client, server = expect_connected(client_result, server_result)
      client.alpn_protocol.should eq("h2")
      server.alpn_protocol.should eq("h2")
    end
  end

  it "refuses a handshake with no ALPN protocol in common (no_application_protocol)" do
    server_context = TlsHarness.server_context
    server_context.alpn_protocol = "h2"
    client_context = TlsHarness.client_context
    client_context.alpn_protocol = "http/1.1"
    TlsHarness.connect(server_context, client_context) do |client_result, server_result|
      server_result.as(TLS::Error).alert_description.should eq(TLS::AlertDescription::NoApplicationProtocol)
      client_result.as(TLS::PeerAlert).alert_description.should eq(TLS::AlertDescription::NoApplicationProtocol)
    end
  end

  it "refuses a handshake with no cipher suite in common (handshake_failure)" do
    server_context = TlsHarness.server_context
    server_context.list_of_cipher_suites = [TLS::CipherSuite::TLS_AES_256_GCM_SHA384]
    client_context = TlsHarness.client_context
    client_context.list_of_cipher_suites = [TLS::CipherSuite::TLS_AES_128_GCM_SHA256]
    TlsHarness.connect(server_context, client_context) do |client_result, server_result|
      server_result.as(TLS::Error).alert_description.should eq(TLS::AlertDescription::HandshakeFailure)
      client_result.as(TLS::PeerAlert).alert_description.should eq(TLS::AlertDescription::HandshakeFailure)
    end
  end

  context "certificate verification" do
    it "accepts the server's IP address when the client connects by address" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context, hostname: "127.0.0.1") do |client_result, server_result|
        expect_connected(client_result, server_result)
      end
    end

    it "refuses a certificate for another name (bad_certificate)" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context, hostname: "example.com") do |client_result, server_result|
        client_result.as(TLS::CertificateRejected).alert_description.should eq(TLS::AlertDescription::BadCertificate)
        server_result.as(TLS::PeerAlert).alert_description.should eq(TLS::AlertDescription::BadCertificate)
      end
    end

    it "refuses a leaf whose key usage leaves out digitalSignature, even without verification (bad_certificate)" do
      server_context = TLS::Context::Server.new
      # keyEncipherment alone.
      server_context.certified_key = TlsHarness.authority.issue(key_usage: Bytes[5, 0x20])
      TlsHarness.connect(server_context, TLS::Context::Client.insecure) do |client_result, server_result|
        client_result.as(TLS::Error).alert_description.should eq(TLS::AlertDescription::BadCertificate)
        server_result.as(TLS::PeerAlert).alert_description.should eq(TLS::AlertDescription::BadCertificate)
      end
    end

    it "sends its compatibility change_cipher_spec before an alert it raises while reading the server's flight" do
      client_io, server_io = UNIXSocket.pair
      recording = RecordingIO.new(server_io)
      server_done = Channel(Nil).new(1)
      spawn do
        TLS::Socket::Server.new(recording, TlsHarness.server_context, sync_close: true)
      rescue TLS::Error
      ensure
        server_done.send(nil)
      end
      expect_raises(TLS::CertificateRejected) do
        TLS::Socket::Client.new(client_io, TlsHarness.client_context, sync_close: true, hostname: "example.com")
      end
      server_done.receive
      # ClientHello, change_cipher_spec, then the protected alert.
      list_of_record_types(recording.received.to_slice).should eq([22_u8, 20_u8, 23_u8])
    end

    it "refuses a chain to a root the client does not trust (unknown_ca)" do
      client_context = TLS::Context::Client.new
      client_context.trust_store = TestCertificateAuthority::Authority.new("Another Root").trust_store
      TlsHarness.connect(TlsHarness.server_context, client_context) do |client_result, _|
        client_result.as(TLS::CertificateRejected).alert_description.should eq(TLS::AlertDescription::UnknownCa)
      end
    end

    it "refuses an expired certificate (certificate_expired)" do
      server_context = TLS::Context::Server.new
      server_context.certified_key = TlsHarness.authority.issue(not_before: Time.utc - 30.days, not_after: Time.utc - 1.day)
      TlsHarness.connect(server_context, TlsHarness.client_context) do |client_result, _|
        client_result.as(TLS::CertificateRejected).alert_description.should eq(TLS::AlertDescription::CertificateExpired)
      end
    end

    it "with verify_mode None accepts an untrusted chain but still checks the CertificateVerify" do
      TlsHarness.connect(TlsHarness.server_context, TLS::Context::Client.insecure, hostname: "example.com") do |client_result, server_result|
        expect_connected(client_result, server_result)
      end
    end

    it "refuses a CertificateVerify that does not verify (decrypt_error)" do
      server_context = TlsHarness.server_context
      other_key = TlsHarness.authority.issue
      # The chain of one key, the private key of another.
      server_context.certified_key = TLS::CertifiedKey.new(server_context.certified_key.list_of_certificates, other_key.private_key)
      TlsHarness.connect(server_context, TlsHarness.client_context) do |client_result, server_result|
        client_result.as(TLS::Error).alert_description.should eq(TLS::AlertDescription::DecryptError)
        server_result.as(TLS::PeerAlert).alert_description.should eq(TLS::AlertDescription::DecryptError)
      end
    end
  end

  context "session resumption" do
    it "resumes with a ticket, then again after a HelloRetryRequest, with a fresh key exchange each time" do
      server_context = TlsHarness.server_context
      client_context = TlsHarness.client_context
      TlsHarness.connect(server_context, client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        client.resumed?.should be_false
        exchange_data(client, server)
      end
      client_context.session_cache.size.should eq(1)

      TlsHarness.connect(server_context, client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        client.resumed?.should be_true
        server.resumed?.should be_true
        client.peer_certificate.should be_nil
        exchange_data(client, server)
      end

      server_context.list_of_groups = [TLS::NamedGroup::Secp256r1]
      TlsHarness.connect(server_context, client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        client.resumed?.should be_true
        client.group.should eq(TLS::NamedGroup::Secp256r1)
        exchange_data(client, server)
      end
    end

    it "falls back to a full handshake for a ticket another server sealed" do
      client_context = TlsHarness.client_context
      TlsHarness.connect(TlsHarness.server_context, client_context) do |client_result, server_result|
        exchange_data(*expect_connected(client_result, server_result))
      end
      TlsHarness.connect(TlsHarness.server_context, client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        client.resumed?.should be_false
        exchange_data(client, server)
      end
    end

    it "never resumes a ticket under another server name" do
      server_context = TlsHarness.server_context
      client_context = TlsHarness.client_context
      TlsHarness.connect(server_context, client_context) do |client_result, server_result|
        exchange_data(*expect_connected(client_result, server_result))
      end
      TlsHarness.connect(server_context, client_context, hostname: "127.0.0.1") do |client_result, server_result|
        client, _ = expect_connected(client_result, server_result)
        client.resumed?.should be_false
      end
    end
  end

  context "after the handshake" do
    it "updates keys both ways on request (KeyUpdate)" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        exchange_data(client, server)
        client.update_keys(request_peer_update: true)
        exchange_data(client, server)
        server.update_keys
        exchange_data(client, server)
      end
    end

    it "answers several requested KeyUpdates with one, sent before its next data" do
      client_context = TlsHarness.client_context
      # More than one KeyUpdate from the server would exceed this limit.
      client_context.limits = TLS::Limits.new(largest_key_update_count_per_minute: 1)
      TlsHarness.connect(TlsHarness.server_context, client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        3.times { client.update_keys(request_peer_update: true) }
        exchange_data(client, server)
        exchange_data(client, server)
      end
    end

    it "refuses more than 32 KeyUpdates in a minute" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        33.times { client.update_keys }
        client.print "x"
        client.flush
        error = expect_raises(TLS::Error) { server.read_byte }
        error.alert_description.should eq(TLS::AlertDescription::UnexpectedMessage)
      end
    end

    it "reads the end of the stream at close_notify" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        server.print "last words"
        server.close
        client.gets_to_end.should eq("last words")
      end
    end

    it "exports the same keying material on both ends" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        client.export_keying_material("EXPERIMENTAL beryl", "context".to_slice, 32)
          .should eq(server.export_keying_material("EXPERIMENTAL beryl", "context".to_slice, 32))
      end
    end

    it "carries a large write in several records" do
      TlsHarness.connect(TlsHarness.server_context, TlsHarness.client_context) do |client_result, server_result|
        client, server = expect_connected(client_result, server_result)
        payload = Bytes.new(100_000) { |index| (index % 251).to_u8 }
        spawn do
          client.write(payload)
          client.flush
        end
        received = Bytes.new(payload.size)
        server.read_fully(received)
        received.should eq(payload)
      end
    end
  end

  describe Beryl::TLS::Socket::Server do
    it "with accept: false runs the handshake on the first read" do
      client_io, server_io = UNIXSocket.pair
      server = TLS::Socket::Server.new(server_io, TlsHarness.server_context, sync_close: true, accept: false)
      spawn do
        client = TLS::Socket::Client.new(client_io, TlsHarness.client_context, sync_close: true, hostname: "localhost")
        client.print "lazy\n"
        client.flush
        client.gets
        client.close
      end
      server.gets.should eq("lazy")
      server.hostname.should eq("localhost")
      server.print "ok\n"
      server.flush
      server.close
    end

    it "closes a connection whose handshake passes the deadline" do
      client_io, server_io = UNIXSocket.pair
      server_context = TlsHarness.server_context
      server_context.limits = TLS::Limits.new(handshake_timeout: 200.milliseconds)
      started = Time.instant
      expect_raises(TLS::HandshakeTimeout) do
        TLS::Socket::Server.new(server_io, server_context, sync_close: true)
      end
      (Time.instant - started).should be < 5.seconds
      client_io.close
    end

    it "refuses data after the first ClientHello in its record when it asks for another group (unexpected_message)" do
      client_output = TlsHarness::ScriptedIO.new(Bytes.empty)
      expect_raises(IO::EOFError) do
        TLS::Socket::Client.new(client_output, TlsHarness.client_context, hostname: "localhost")
      end
      first_record = client_output.output.to_slice
      # The start of another handshake message in the same record.
      extra = Bytes[1, 0, 0]
      length = first_record.size - 5 + extra.size
      record = Bytes[22, 3, 1, (length >> 8).to_u8, (length & 0xFF).to_u8] + first_record[5..] + extra
      server_context = TlsHarness.server_context
      server_context.list_of_groups = [TLS::NamedGroup::Secp256r1]
      error = expect_raises(TLS::Error) { TLS::Socket::Server.new(TlsHarness::ScriptedIO.new(record), server_context) }
      error.alert_description.should eq(TLS::AlertDescription::UnexpectedMessage)
    end

    it "ends a handshake at its deadline even when the client trickles bytes" do
      client_io, server_io = UNIXSocket.pair
      server_context = TlsHarness.server_context
      server_context.limits = TLS::Limits.new(handshake_timeout: 300.milliseconds)
      spawn do
        20.times do
          client_io.write(Bytes[22])
          client_io.flush
          sleep 100.milliseconds
        end
      rescue IO::Error
      end
      started = Time.instant
      expect_raises(TLS::HandshakeTimeout) do
        TLS::Socket::Server.new(server_io, server_context, sync_close: true)
      end
      (Time.instant - started).should be < 1.5.seconds
      client_io.close
    end

    it "refuses a ClientHello whose legacy_version is SSL 3.0 or older (protocol_version)" do
      client_output = TlsHarness::ScriptedIO.new(Bytes.empty)
      expect_raises(IO::EOFError) do
        TLS::Socket::Client.new(client_output, TlsHarness.client_context, hostname: "localhost")
      end
      record = client_output.output.to_slice.dup
      # The ClientHello's legacy_version follows the record header and the
      # handshake header.
      record[9] = 0x03
      record[10] = 0x00
      error = expect_raises(TLS::Error) { TLS::Socket::Server.new(TlsHarness::ScriptedIO.new(record), TlsHarness.server_context) }
      error.alert_description.should eq(TLS::AlertDescription::ProtocolVersion)
    end

    it "refuses a client that offers none of its key's signature schemes before any ServerHello (handshake_failure)" do
      client_context = TlsHarness.client_context
      client_context.list_of_signature_schemes = [TLS::SignatureScheme::Ed25519]
      client_output = TlsHarness::ScriptedIO.new(Bytes.empty)
      expect_raises(IO::EOFError) do
        TLS::Socket::Client.new(client_output, client_context, hostname: "localhost")
      end
      server_io = TlsHarness::ScriptedIO.new(client_output.output.to_slice)
      error = expect_raises(TLS::Error) { TLS::Socket::Server.new(server_io, TlsHarness.server_context(KeyKind::P256)) }
      error.alert_description.should eq(TLS::AlertDescription::HandshakeFailure)
      server_io.output.to_slice.should eq(Bytes[21, 3, 3, 0, 2, 2, 40])
    end

    it "refuses a ClientHello without TLS 1.3 (protocol_version)" do
      client_hello = TLS::Messages::ClientHello.new(Bytes.new(32, 1), Bytes.empty, [0x1301_u16], [] of TLS::Messages::Extension).encode
      record = Bytes[22, 3, 1, 0, client_hello.size.to_u8] + client_hello
      io = TlsHarness::ScriptedIO.new(record)
      error = expect_raises(TLS::Error) { TLS::Socket::Server.new(io, TlsHarness.server_context) }
      error.alert_description.should eq(TLS::AlertDescription::ProtocolVersion)
      io.output.to_slice.should eq(Bytes[21, 3, 3, 0, 2, 2, 70])
    end
  end

  describe Beryl::TLS::Server do
    it "accepts TLS connections from a TCP server" do
      tcp_server = TCPServer.new("127.0.0.1", 0)
      server = TLS::Server.new(tcp_server, TlsHarness.server_context)
      port = server.local_address.as(Socket::IPAddress).port
      spawn do
        if connection = server.accept?
          connection.puts(connection.gets)
          connection.close
        end
      end
      client = TLS::Socket::Client.new(TCPSocket.new("127.0.0.1", port), TlsHarness.client_context, sync_close: true, hostname: "localhost")
      client.puts "echo"
      client.flush
      client.gets.should eq("echo")
      client.close
      server.close
    end
  end
end
