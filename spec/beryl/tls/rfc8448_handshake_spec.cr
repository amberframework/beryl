require "../../spec_helper"

private alias TLS = Beryl::TLS
private alias Trace = Rfc8448Trace

# RFC 8448's server key is RSA-1024, below the 2,048 bits Beryl's RSA
# accepts by design. This verifier checks the trace's RSA-PSS signature in
# spec code (BigInt, RFC 8017 §8.1.2) and accepts the trace's self-signed
# certificate; everything else the client does is Beryl's own code.
private class TraceVerifier < TLS::CertificateVerifier
  getter list_of_verified_contents = [] of Bytes

  def verify_chain(chain : Array(Beryl::Certificates::Certificate), hostname : String?) : Nil
    chain.size.should eq(1)
  end

  def verify_signature(leaf : Beryl::Certificates::Certificate, scheme : TLS::SignatureScheme, content : Bytes, signature : Bytes) : Bool
    return false unless scheme.rsa_pss_rsae_sha256?
    modulus_bytes, _ = Beryl::Certificates::SubjectPublicKeyInfo.read_rsa_public_key(leaf.subject_public_key_info.key_bytes)
    modulus = BigInt.new(modulus_bytes.hexstring, 16)
    encoded = RsaKeyComponents.power_modulo(BigInt.new(signature.hexstring, 16), 65_537, modulus)
    encoded_bytes = RsaKeyComponents.bytes_of(encoded)
    encoded_bytes = Bytes.new(128 - encoded_bytes.size) + encoded_bytes if encoded_bytes.size < 128
    verified = Beryl::Crypto::V1::RSA::MessageEncoding.pss_encoding_matches?(Beryl::Crypto::V1::SHA256,
      Beryl::Crypto::V1::SHA256.digest(content), encoded_bytes, 1023, 32)
    @list_of_verified_contents << content if verified
    verified
  end
end

private def trace_record(section : Int32, actor : String, title : String, occurrence : Int32 = 1) : Bytes
  Trace.field(section, actor, title, "complete record", occurrence)
end

private def trace_offer(client_hello_message : Bytes, list_of_key_exchanges : Array(TLS::KeyExchange)) : TLS::ClientHandshake::Offer
  client_hello = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(client_hello_message)[1])
  TLS::ClientHandshake::Offer.new(client_hello, client_hello_message, list_of_key_exchanges, nil)
end

describe "RFC 8448, reproduced by Beryl's handshake engines" do
  context "§3 simple 1-RTT handshake, client side" do
    it "verifies the server's flight and sends the trace's Finished, application data and close_notify, byte for byte" do
      server_records = trace_record(3, "server", "send handshake record", 1) + trace_record(3, "server", "send handshake record", 2) +
                       trace_record(3, "server", "send handshake record", 3) + trace_record(3, "server", "send application_data record") +
                       trace_record(3, "server", "send alert record")
      io = TlsHarness::ScriptedIO.new(server_records)
      layer = TLS::RecordLayer.new(io)
      context = TLS::Context::Client.new
      context.list_of_cipher_suites = [TLS::CipherSuite::TLS_AES_128_GCM_SHA256, TLS::CipherSuite::TLS_AES_256_GCM_SHA384,
                                       TLS::CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
      verifier = TraceVerifier.new
      context.certificate_verifier = verifier
      client_key = Beryl::Crypto::V1::X25519::PrivateKey.new(Trace.field(3, "client", "create an ephemeral x25519 key pair", "private key"))
      offer = trace_offer(Trace.field(3, "client", "send handshake record", "payload"), [TLS::X25519Exchange.new(client_key)] of TLS::KeyExchange)

      outcome = TLS::ClientHandshake.new(layer, context, "server").complete(offer)
      outcome.cipher_suite.should eq(TLS::CipherSuite::TLS_AES_128_GCM_SHA256)
      outcome.server_application_traffic_secret.should eq(Trace.field(3, "server", "derive secret \"tls13 s ap traffic\"", "expanded"))
      outcome.resumption_master_secret.should eq(Trace.field(3, "client", "derive secret \"tls13 res master\"", "expanded"))
      verifier.list_of_verified_contents.size.should eq(1)
      io.output.to_slice.should eq(trace_record(3, "client", "send handshake record", 2))

      io.output.clear
      layer.write_application_data(Trace.field(3, "client", "send application_data record", "payload"))
      io.output.to_slice.should eq(trace_record(3, "client", "send application_data record"))

      ticket_message = layer.read_after_handshake || fail "no NewSessionTicket"
      ticket_message.should eq({TLS::ContentType::Handshake, Trace.field(3, "server", "construct a NewSessionTicket", "NewSessionTicket")})
      ticket = TLS::Messages::NewSessionTicket.decode(TLS::Messages.unwrap(ticket_message[1])[1])
      TLS::KeySchedule.resumption_pre_shared_key(TLS::HashAlgorithm::SHA256, outcome.resumption_master_secret, ticket.ticket_nonce)
        .should eq(Trace.field(3, "server", "generate resumption secret \"tls13 resumption\"", "expanded"))
      layer.read_after_handshake.should eq({TLS::ContentType::ApplicationData, Trace.field(3, "server", "send application_data record", "payload")})
      layer.read_after_handshake.should be_nil

      io.output.clear
      layer.write_alert(TLS::AlertLevel::Warning, TLS::AlertDescription::CloseNotify)
      io.output.to_slice.should eq(trace_record(3, "client", "send alert record"))
    end
  end

  context "§3 simple 1-RTT handshake, server side" do
    it "answers the trace's ClientHello with the trace's ServerHello and handshake secrets" do
      randomness = TlsHarness::FixedRandomness.new
      randomness.list_of_x25519_keys << Beryl::Crypto::V1::X25519::PrivateKey.new(Trace.field(3, "server", "create an ephemeral x25519 key pair", "private key"))
      server_hello = Trace.field(3, "server", "construct a ServerHello", "ServerHello")
      randomness.list_of_byte_strings << server_hello[6, 32]
      context = TlsHarness.server_context
      context.randomness = randomness
      context.list_of_cipher_suites = [TLS::CipherSuite::TLS_AES_128_GCM_SHA256]
      io = TlsHarness::ScriptedIO.new(trace_record(3, "client", "send handshake record", 1))
      expect_raises(IO::EOFError) { TLS::ServerHandshake.new(TLS::RecordLayer.new(io), context).perform }

      output = io.output.to_slice
      expected_server_hello_record = trace_record(3, "server", "send handshake record", 1)
      output[0, expected_server_hello_record.size].should eq(expected_server_hello_record)

      # The rest is protected under the trace's server handshake secret.
      # Its EncryptedExtensions differ from the trace's by design: the trace
      # server (NSS) lists groups Beryl does not implement.
      reader = TLS::RecordLayer.new(IO::Memory.new(output[expected_server_hello_record.size..]))
      reader.read_protection = TLS::RecordProtection.new(TLS::CipherSuite::TLS_AES_128_GCM_SHA256,
        Trace.field(3, "server", "derive secret \"tls13 s hs traffic\"", "expanded"))
      encrypted_extensions = TLS::Messages::EncryptedExtensions.decode(TLS::Messages.unwrap(reader.read_handshake_message)[1])
      encrypted_extensions.extension(TLS::ExtensionType::ServerName).should eq(Bytes.empty)
      encrypted_extensions.extension(TLS::ExtensionType::RecordSizeLimit).should eq(Bytes[0x40, 0x01])
      TLS::Messages.unwrap(reader.read_handshake_message)[0].should eq(TLS::HandshakeType::Certificate)
    end
  end

  context "§5 HelloRetryRequest" do
    it "client: answers the trace's HelloRetryRequest with the cookie and a P-256 share, keeping the random" do
      randomness = TlsHarness::FixedRandomness.new
      client_p256 = Beryl::Crypto::V1::P256::PrivateKey.new(Trace.field(5, "client", "create an ephemeral P-256 key pair", "private key"))
      randomness.list_of_p256_keys << client_p256
      context = TLS::Context::Client.new
      context.randomness = randomness
      context.certificate_verifier = TraceVerifier.new
      first_hello = Trace.field(5, "client", "send handshake record", "payload", 1)
      client_x25519 = Beryl::Crypto::V1::X25519::PrivateKey.new(Trace.field(5, "client", "create an ephemeral x25519 key pair", "private key"))
      offer = trace_offer(first_hello, [TLS::X25519Exchange.new(client_x25519)] of TLS::KeyExchange)
      io = TlsHarness::ScriptedIO.new(trace_record(5, "server", "send handshake record", 1))
      expect_raises(IO::EOFError) { TLS::ClientHandshake.new(TLS::RecordLayer.new(io), context, "server").complete(offer) }

      written = io.output.to_slice
      written[0].should eq(TLS::ContentType::Handshake.value)
      second_hello = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(written[5..])[1])
      first = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(first_hello)[1])
      second_hello.random.should eq(first.random)
      shares = TLS::Messages::ExtensionCodec.decode_client_key_shares(second_hello.extension(TLS::ExtensionType::KeyShare) || fail "no key_share")
      shares.should eq([TLS::Messages::ExtensionCodec::KeyShareEntry.new(0x0017_u16, client_p256.public_key.to_uncompressed)])
      trace_second_hello = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(Trace.field(5, "client", "send handshake record", "payload", 2))[1])
      second_hello.extension(TLS::ExtensionType::Cookie).should eq(trace_second_hello.extension(TLS::ExtensionType::Cookie))
      second_hello.extension(TLS::ExtensionType::KeyShare).should eq(trace_second_hello.extension(TLS::ExtensionType::KeyShare))
    end

    it "server: asks the trace's ClientHello for P-256 with the trace's HelloRetryRequest, less its cookie" do
      context = TlsHarness.server_context
      context.list_of_groups = [TLS::NamedGroup::Secp256r1]
      context.list_of_cipher_suites = [TLS::CipherSuite::TLS_AES_128_GCM_SHA256]
      io = TlsHarness::ScriptedIO.new(trace_record(5, "client", "send handshake record", 1))
      expect_raises(IO::EOFError) { TLS::ServerHandshake.new(TLS::RecordLayer.new(io), context).perform }

      trace_retry = TLS::Messages::ServerHello.decode(TLS::Messages.unwrap(Trace.field(5, "server", "construct a ServerHello", "ServerHello", 1))[1])
      trace_retry.list_of_extensions.reject! { |extension| extension.type_value == TLS::ExtensionType::Cookie.value }
      written = io.output.to_slice
      TLS::Messages.unwrap(written[5..])[1].should eq(TLS::Messages.unwrap(trace_retry.encode)[1])
    end
  end

  context "the message codec" do
    (3..7).each do |section|
      Trace.section(section).each do |step|
        message_match = step.title.match(/\Aconstruct an? (\w+) handshake message\z/)
        next unless message_match
        message = step.field(message_match[1])
        declared = (message[1].to_i << 16) | (message[2].to_i << 8) | message[3].to_i
        next unless declared == message.size - 4 # §4's ClientHello step prints the prefix

        it "decodes and re-encodes the §#{section} #{step.actor} #{message_match[1]} byte for byte" do
          handshake_type, body = TLS::Messages.unwrap(message)
          reencoded = case handshake_type
                      when TLS::HandshakeType::ClientHello         then TLS::Messages::ClientHello.decode(body).encode
                      when TLS::HandshakeType::ServerHello         then TLS::Messages::ServerHello.decode(body).encode
                      when TLS::HandshakeType::EncryptedExtensions then TLS::Messages::EncryptedExtensions.decode(body).encode
                      when TLS::HandshakeType::Certificate         then TLS::Messages::CertificateMessage.decode(body).encode
                      when TLS::HandshakeType::CertificateRequest  then TLS::Messages::CertificateRequest.decode(body).encode
                      when TLS::HandshakeType::CertificateVerify   then TLS::Messages::CertificateVerify.decode(body).encode
                      when TLS::HandshakeType::Finished            then TLS::Messages::Finished.decode(body, body.size).encode
                      when TLS::HandshakeType::NewSessionTicket    then TLS::Messages::NewSessionTicket.decode(body).encode
                      when TLS::HandshakeType::EndOfEarlyData      then message
                      else                                              fail "an unexpected message type #{message[0]}"
                      end
          reencoded.should eq(message)
        end
      end
    end

    it "decodes and re-encodes every extension of the §3 ClientHello" do
      codec = TLS::Messages::ExtensionCodec
      client_hello = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(Trace.field(3, "client", "construct a ClientHello", "ClientHello"))[1])
      server_name = client_hello.extension(TLS::ExtensionType::ServerName) || fail "no server_name"
      codec.decode_server_name(server_name).should eq("server")
      codec.encode_server_name("server").should eq(server_name)
      groups = client_hello.extension(TLS::ExtensionType::SupportedGroups) || fail "no supported_groups"
      codec.encode_u16_list(codec.decode_u16_list(groups)).should eq(groups)
      shares = client_hello.extension(TLS::ExtensionType::KeyShare) || fail "no key_share"
      codec.encode_client_key_shares(codec.decode_client_key_shares(shares)).should eq(shares)
      versions = client_hello.extension(TLS::ExtensionType::SupportedVersions) || fail "no supported_versions"
      codec.decode_client_supported_versions(versions).should eq([0x0304_u16])
      codec.encode_client_supported_versions([0x0304_u16]).should eq(versions)
      modes = client_hello.extension(TLS::ExtensionType::PskKeyExchangeModes) || fail "no psk_key_exchange_modes"
      codec.encode_psk_modes(codec.decode_psk_modes(modes)).should eq(modes)
      codec.decode_record_size_limit(client_hello.extension(TLS::ExtensionType::RecordSizeLimit) || fail "no record_size_limit").should eq(16_385)
    end

    it "decodes and re-encodes the §4 pre_shared_key extension" do
      codec = TLS::Messages::ExtensionCodec
      client_hello = TLS::Messages::ClientHello.decode(TLS::Messages.unwrap(Trace.field(4, "client", "send handshake record", "payload"))[1])
      contents = client_hello.extension(TLS::ExtensionType::PreSharedKey) || fail "no pre_shared_key"
      identities, binders = codec.decode_client_pre_shared_key(contents)
      identities.size.should eq(1)
      binders.first.should eq(Trace.field(4, "client", "calculate PSK binder", "finished"))
      codec.encode_client_pre_shared_key(identities, binders).should eq(contents)
    end
  end
end
