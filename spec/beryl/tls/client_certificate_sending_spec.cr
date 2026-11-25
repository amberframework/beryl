require "../../spec_helper"
require "base64"
require "file_utils"

private alias TLS = Beryl::TLS
private alias Messages = Beryl::TLS::Messages
private alias ExtensionCodec = Beryl::TLS::Messages::ExtensionCodec
private alias KeyKind = TestCertificateAuthority::KeyKind

# What the requesting server saw of the client's answer to its
# CertificateRequest.
private record ClientAnswer,
  list_of_certificates : Array(Bytes),
  signature_scheme_value : UInt16?,
  is_signature_valid : Bool,
  is_finished_valid : Bool,
  resumption_master_secret : Bytes

# A minimal TLS 1.3 server, enough to drive Beryl's client through a full
# handshake with a CertificateRequest: X25519, TLS_AES_128_GCM_SHA256, a
# P-256 server certificate. It checks the client's Certificate,
# CertificateVerify and Finished against its own transcript.
private class CertificateRequestingServer
  HASH  = TLS::HashAlgorithm::SHA256
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  @transcript = TLS::TranscriptHash.new

  def initialize(io : IO, @list_of_requested_scheme_values : Array(UInt16),
                 @certificate_authorities : Bytes? = nil)
    @record_layer = TLS::RecordLayer.new(io)
    @certified_key = TlsHarness.authority.issue(KeyKind::P256)
    @randomness = TLS::HandshakeRandomness.new
  end

  def perform : ClientAnswer
    client_hello_message = @record_layer.read_handshake_message
    client_hello = Messages::ClientHello.decode(Messages.unwrap(client_hello_message)[1])
    @transcript.add(client_hello_message)
    list_of_shares = ExtensionCodec.decode_client_key_shares(client_hello.extension(TLS::ExtensionType::KeyShare) || raise "no key_share")
    client_share = list_of_shares.find { |entry| entry.group_value == TLS::NamedGroup::X25519.value } || raise "no X25519 share"
    key_exchange = TLS::KeyExchange.generate(TLS::NamedGroup::X25519, @randomness)

    server_hello = Messages::ServerHello.new(@randomness.random_bytes(32), client_hello.legacy_session_id, SUITE.value, [
      Messages::Extension.new(TLS::ExtensionType::KeyShare.value,
        ExtensionCodec.encode_server_key_share(ExtensionCodec::KeyShareEntry.new(key_exchange.group.value, key_exchange.public_key_bytes))),
      Messages::Extension.new(TLS::ExtensionType::SupportedVersions.value, ExtensionCodec.encode_selected_version(TLS::ProtocolVersion::TLS_1_3)),
    ]).encode
    @record_layer.write_handshake(server_hello)
    @transcript.add(server_hello)

    schedule = TLS::KeySchedule.new(HASH)
    schedule.enter_handshake_stage(key_exchange.shared_secret(client_share.key_exchange))
    handshake_digest = @transcript.digest(HASH)
    client_handshake_secret = schedule.client_handshake_traffic_secret(handshake_digest)
    server_handshake_secret = schedule.server_handshake_traffic_secret(handshake_digest)
    @record_layer.write_protection = TLS::RecordProtection.new(SUITE, server_handshake_secret)
    @record_layer.read_protection = TLS::RecordProtection.new(SUITE, client_handshake_secret)

    write_and_record(Messages::EncryptedExtensions.new([] of Messages::Extension).encode)
    write_and_record(Messages::CertificateRequest.new(Bytes.empty, list_of_request_extensions).encode)
    list_of_entries = @certified_key.list_of_certificates.map { |certificate| Messages::CertificateEntry.new(certificate.encoded, [] of Messages::Extension) }
    write_and_record(Messages::CertificateMessage.new(Bytes.empty, list_of_entries).encode)
    content = Messages::CertificateVerify.signed_content(@transcript.digest(HASH), is_server: true)
    scheme = TLS::SignatureScheme::EcdsaSecp256r1Sha256
    write_and_record(Messages::CertificateVerify.new(scheme.value, @certified_key.sign(scheme, content, @randomness)).encode)
    write_and_record(Messages::Finished.new(TLS::KeySchedule.finished_verify_data(HASH, server_handshake_secret, @transcript.digest(HASH))).encode)
    @record_layer.flush
    schedule.enter_master_stage

    read_client_answer(schedule, client_handshake_secret)
  end

  private def read_client_answer(schedule : TLS::KeySchedule, client_handshake_secret : Bytes) : ClientAnswer
    certificate_message = read_message(TLS::HandshakeType::Certificate)
    certificate = Messages::CertificateMessage.decode(Messages.unwrap(certificate_message)[1])
    @transcript.add(certificate_message)
    list_of_certificates = certificate.list_of_entries.map(&.certificate_data)

    signature_scheme_value = nil
    is_signature_valid = false
    unless list_of_certificates.empty?
      verify_message = read_message(TLS::HandshakeType::CertificateVerify)
      certificate_verify = Messages::CertificateVerify.decode(Messages.unwrap(verify_message)[1])
      signature_scheme_value = certificate_verify.signature_scheme_value
      content = Messages::CertificateVerify.signed_content(@transcript.digest(HASH), is_server: false)
      leaf = Beryl::Certificates::Certificate.new(list_of_certificates.first)
      scheme = TLS::SignatureScheme.from_value(signature_scheme_value)
      is_signature_valid = TLS::InsecureVerifier.new.verify_signature(leaf, scheme, content, certificate_verify.signature)
      @transcript.add(verify_message)
    end

    finished_message = read_message(TLS::HandshakeType::Finished)
    finished = Messages::Finished.decode(Messages.unwrap(finished_message)[1], HASH.bytesize)
    is_finished_valid = TLS::KeySchedule.finished_matches?(HASH, client_handshake_secret, @transcript.digest(HASH), finished.verify_data)
    @transcript.add(finished_message)

    ClientAnswer.new(list_of_certificates, signature_scheme_value, is_signature_valid, is_finished_valid,
      schedule.resumption_master_secret(@transcript.digest(HASH)))
  end

  private def list_of_request_extensions : Array(Messages::Extension)
    list_of_extensions = [Messages::Extension.new(TLS::ExtensionType::SignatureAlgorithms.value,
      ExtensionCodec.encode_u16_list(@list_of_requested_scheme_values))]
    if certificate_authorities = @certificate_authorities
      list_of_extensions << Messages::Extension.new(TLS::ExtensionType::CertificateAuthorities.value, certificate_authorities)
    end
    list_of_extensions
  end

  private def read_message(expected : TLS::HandshakeType) : Bytes
    message = @record_layer.read_handshake_message
    actual = Messages.unwrap(message)[0]
    raise "#{actual} arrived where #{expected} was expected" unless actual == expected
    message
  end

  private def write_and_record(message : Bytes) : Nil
    @record_layer.write_handshake(message)
    @transcript.add(message)
  end
end

# Runs Beryl's client handshake against a `CertificateRequestingServer`.
# Returns the client's outcome (or the error it raised) and what the
# server saw (or the error it raised).
private def request_client_certificate(client_context : TLS::Context::Client, list_of_requested_schemes : Array(TLS::SignatureScheme),
                                       certificate_authorities : Bytes? = nil) : {TLS::HandshakeOutcome | Exception, ClientAnswer | Exception}
  client_io, server_io = UNIXSocket.pair
  server_result = Channel(ClientAnswer | Exception).new(1)
  spawn do
    server_result.send(CertificateRequestingServer.new(server_io, list_of_requested_schemes.map(&.value), certificate_authorities).perform)
  rescue error
    server_result.send(error)
  ensure
    server_io.close
  end
  client_result = begin
    TLS::ClientHandshake.new(TLS::RecordLayer.new(client_io), client_context, "localhost").perform
  rescue error
    error
  ensure
    client_io.close
  end
  {client_result, server_result.receive}
end

private def expect_completed(client_result, server_result) : {TLS::HandshakeOutcome, ClientAnswer}
  raise client_result if client_result.is_a?(Exception)
  raise server_result if server_result.is_a?(Exception)
  {client_result, server_result}
end

private def client_context_presenting(key_kind : KeyKind) : {TLS::Context::Client, TLS::CertifiedKey}
  context = TlsHarness.client_context
  certified_key = TlsHarness.authority.issue(key_kind)
  context.certified_key = certified_key
  {context, certified_key}
end

private def with_temporary_directory(&)
  directory = File.tempname("beryl-client-certificate")
  Dir.mkdir(directory)
  begin
    yield directory
  ensure
    FileUtils.rm_rf(directory)
  end
end

private def pem_block(label : String, der : Bytes) : String
  "-----BEGIN #{label}-----\n#{Base64.encode(der)}-----END #{label}-----\n"
end

describe "Beryl::TLS client certificates" do
  all_schemes = [TLS::SignatureScheme::EcdsaSecp256r1Sha256, TLS::SignatureScheme::RsaPssRsaeSha256, TLS::SignatureScheme::Ed25519]

  {
    {KeyKind::P256, TLS::SignatureScheme::EcdsaSecp256r1Sha256},
    {KeyKind::Rsa2048, TLS::SignatureScheme::RsaPssRsaeSha256},
    {KeyKind::Ed25519, TLS::SignatureScheme::Ed25519},
  }.each do |(key_kind, expected_scheme)|
    it "sends a #{key_kind} certificate and a CertificateVerify the server verifies" do
      context, certified_key = client_context_presenting(key_kind)
      outcome, answer = expect_completed(*request_client_certificate(context, all_schemes))

      answer.list_of_certificates.should eq(certified_key.list_of_certificates.map(&.encoded))
      answer.signature_scheme_value.should eq(expected_scheme.value)
      answer.is_signature_valid.should be_true
      answer.is_finished_valid.should be_true
      # The resumption master secret covers the client's Certificate and
      # CertificateVerify, so both ends computing the same one shows they
      # entered the transcript in the same order.
      outcome.resumption_master_secret.should eq(answer.resumption_master_secret)
    end
  end

  it "answers with an empty Certificate and no CertificateVerify when no certificate is configured" do
    outcome, answer = expect_completed(*request_client_certificate(TlsHarness.client_context, all_schemes))

    answer.list_of_certificates.should be_empty
    answer.signature_scheme_value.should be_nil
    answer.is_finished_valid.should be_true
    outcome.resumption_master_secret.should eq(answer.resumption_master_secret)
  end

  it "signs with the scheme of the key that the server's list names" do
    context, _ = client_context_presenting(KeyKind::Rsa2048)
    list_of_requested_schemes = [TLS::SignatureScheme::Ed25519, TLS::SignatureScheme::RsaPssRsaeSha384, TLS::SignatureScheme::EcdsaSecp256r1Sha256]
    _, answer = expect_completed(*request_client_certificate(context, list_of_requested_schemes))

    answer.signature_scheme_value.should eq(TLS::SignatureScheme::RsaPssRsaeSha384.value)
    answer.is_signature_valid.should be_true
    answer.is_finished_valid.should be_true
  end

  it "answers with an empty Certificate when its key signs none of the server's schemes" do
    context, _ = client_context_presenting(KeyKind::P256)
    outcome, answer = expect_completed(*request_client_certificate(context, [TLS::SignatureScheme::Ed25519]))

    answer.list_of_certificates.should be_empty
    answer.is_finished_valid.should be_true
    outcome.resumption_master_secret.should eq(answer.resumption_master_secret)
  end

  it "presents its certificate whatever authorities the server names" do
    context, certified_key = client_context_presenting(KeyKind::P256)
    unrelated_name = TestCertificateAuthority.name("Some Other Root")
    certificate_authorities = DerWriter.concat([Bytes[0, unrelated_name.size + 2], Bytes[0, unrelated_name.size], unrelated_name])
    _, answer = expect_completed(*request_client_certificate(context, all_schemes, certificate_authorities))

    answer.list_of_certificates.should eq(certified_key.list_of_certificates.map(&.encoded))
    answer.is_signature_valid.should be_true
  end

  it "refuses an empty certificate_authorities list with decode_error" do
    context, _ = client_context_presenting(KeyKind::P256)
    client_result, _ = request_client_certificate(context, all_schemes, Bytes[0, 0])

    error = client_result.should be_a(TLS::Error)
    error.alert_description.should eq(TLS::AlertDescription::DecodeError)
  end

  it "reads the chain and key from PEM files, as OpenSSL's context does" do
    seed = Bytes.new(32) { |index| (index * 7 + 1).to_u8 }
    signing_key = Beryl::Crypto::V1::Ed25519::SigningKey.new(seed)
    certified_key = TlsHarness.authority.issue(KeyKind::Ed25519)
    # A PKCS #8 Ed25519 key for the same seed as *signing_key*; the
    # certificate is issued for another key, which is fine here because
    # the context only pairs them.
    pkcs8 = DerWriter.sequence(DerWriter.small_integer(0), DerWriter.sequence(DerWriter.object_identifier("1.3.101.112")),
      DerWriter.octet_string(DerWriter.octet_string(seed)))
    with_temporary_directory do |directory|
      chain_path = File.join(directory, "chain.pem")
      key_path = File.join(directory, "client.key")
      File.write(chain_path, certified_key.list_of_certificates.map(&.to_pem).join)
      File.write(key_path, pem_block("PRIVATE KEY", pkcs8))

      context = TLS::Context::Client.new
      context.certified_key?.should be_nil
      context.certificate_chain = chain_path
      context.private_key = key_path
      loaded = context.certified_key?.should_not be_nil
      loaded.list_of_certificates.map(&.encoded).should eq(certified_key.list_of_certificates.map(&.encoded))
      loaded.list_of_signature_schemes.should eq([TLS::SignatureScheme::Ed25519])
      private_key = loaded.private_key.should be_a(Beryl::Crypto::V1::Ed25519::SigningKey)
      private_key.verification_key.to_slice.should eq(signing_key.verification_key.to_slice)
    end
  end

  it "names what is missing when only the chain or only the key is set" do
    certified_key = TlsHarness.authority.issue(KeyKind::P256)
    with_temporary_directory do |directory|
      chain_path = File.join(directory, "chain.pem")
      File.write(chain_path, certified_key.list_of_certificates.map(&.to_pem).join)
      context = TlsHarness.client_context
      context.certificate_chain = chain_path

      expect_raises(TLS::Error, "the client context has a certificate chain but no private key") { context.certified_key? }
      client_result, _ = request_client_certificate(context, all_schemes)
      error = client_result.should be_a(TLS::Error)
      error.message.should eq("the client context has a certificate chain but no private key")

      key_only_context = TlsHarness.client_context
      key_path = File.join(directory, "client.key")
      seed = Bytes.new(32, 7_u8)
      File.write(key_path, pem_block("PRIVATE KEY", DerWriter.sequence(DerWriter.small_integer(0),
        DerWriter.sequence(DerWriter.object_identifier("1.3.101.112")), DerWriter.octet_string(DerWriter.octet_string(seed)))))
      key_only_context.private_key = key_path
      expect_raises(TLS::Error, "the client context has a private key but no certificate chain") { key_only_context.certified_key? }
    end
  end
end
