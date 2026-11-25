# A minimal TLS 1.3 client for the server's client-certificate specs. It
# offers TLS_AES_128_GCM_SHA256 over x25519, skips checking the server
# (the handshake specs cover that), answers a CertificateRequest with the
# certificate it holds, and can break its own CertificateVerify or offer a
# ticket it read from an earlier connection.
class ClientCertificatePeer
  alias TLS = Beryl::TLS
  alias Messages = Beryl::TLS::Messages
  alias ExtensionCodec = Beryl::TLS::Messages::ExtensionCodec

  CIPHER_SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  # A ticket and the pre-shared key it stands for.
  record Ticket, ticket : Bytes, resumption_pre_shared_key : Bytes, ticket_age_add : UInt32

  # The chain and key sent when the server asks; nil sends an empty
  # Certificate.
  property certified_key : TLS::CertifiedKey? = nil
  # Whether the CertificateVerify signature is altered before it is sent.
  property? is_corrupting_certificate_verify : Bool = false
  # The scheme the CertificateVerify names; when nil, the first the key
  # supports. The signature is always made with that first scheme.
  property declared_signature_scheme : TLS::SignatureScheme? = nil
  # Whether the CertificateVerify carries an empty signature.
  property? is_sending_empty_signature : Bool = false
  getter certificate_request : Messages::CertificateRequest? = nil
  getter? resumed : Bool = false

  @record_layer : TLS::RecordLayer
  @transcript = TLS::TranscriptHash.new
  @resumption_master_secret = Bytes.empty

  def initialize(io : IO)
    @record_layer = TLS::RecordLayer.new(io)
  end

  # Runs the handshake, offering *ticket* when given.
  def handshake(ticket : Ticket? = nil) : Nil
    hash = CIPHER_SUITE.hash_algorithm
    key_exchange = TLS::KeyExchange.generate(TLS::NamedGroup::X25519, TLS::HandshakeRandomness.new)
    list_of_extensions = [
      Messages::Extension.new(TLS::ExtensionType::ServerName.value, ExtensionCodec.encode_server_name("localhost")),
      Messages::Extension.new(TLS::ExtensionType::SupportedGroups.value, ExtensionCodec.encode_u16_list([TLS::NamedGroup::X25519.value])),
      Messages::Extension.new(TLS::ExtensionType::SignatureAlgorithms.value,
        ExtensionCodec.encode_u16_list(TLS::CertificateVerifier::LIST_OF_VERIFIED_SIGNATURE_SCHEMES.map(&.value))),
      Messages::Extension.new(TLS::ExtensionType::KeyShare.value, ExtensionCodec.encode_client_key_shares(
        [ExtensionCodec::KeyShareEntry.new(TLS::NamedGroup::X25519.value, key_exchange.public_key_bytes)])),
      Messages::Extension.new(TLS::ExtensionType::SupportedVersions.value, ExtensionCodec.encode_client_supported_versions([TLS::ProtocolVersion::TLS_1_3])),
      Messages::Extension.new(TLS::ExtensionType::PskKeyExchangeModes.value, ExtensionCodec.encode_psk_modes(Bytes[TLS::PskKeyExchangeMode::PskDheKe.value])),
    ]
    client_hello = Messages::ClientHello.new(Random::Secure.random_bytes(32), Bytes.empty, [CIPHER_SUITE.value], list_of_extensions)
    client_hello_message = encode_with_binder(client_hello, ticket)
    @record_layer.write_handshake(client_hello_message, legacy_record_version: TLS::ProtocolVersion::TLS_1_0)
    @record_layer.flush
    @transcript.add(client_hello_message)

    server_hello_message = @record_layer.read_handshake_message
    server_hello = Messages::ServerHello.decode(Messages.unwrap(server_hello_message)[1])
    raise "a HelloRetryRequest, which this peer does not answer" if server_hello.hello_retry_request?
    @resumed = server_hello.has_extension?(TLS::ExtensionType::PreSharedKey)
    server_share = ExtensionCodec.decode_server_key_share(server_hello.extension(TLS::ExtensionType::KeyShare) || raise "no key_share")
    @transcript.add(server_hello_message)

    schedule = TLS::KeySchedule.new(hash, @resumed ? ticket.try(&.resumption_pre_shared_key) : nil)
    schedule.enter_handshake_stage(key_exchange.shared_secret(server_share.key_exchange))
    handshake_digest = @transcript.digest(hash)
    client_handshake_secret = schedule.client_handshake_traffic_secret(handshake_digest)
    server_handshake_secret = schedule.server_handshake_traffic_secret(handshake_digest)
    @record_layer.read_protection = TLS::RecordProtection.new(CIPHER_SUITE, server_handshake_secret)
    @record_layer.write_protection = TLS::RecordProtection.new(CIPHER_SUITE, client_handshake_secret)

    loop do
      message = @record_layer.read_handshake_message
      handshake_type, body = Messages.unwrap(message)
      @certificate_request = Messages::CertificateRequest.decode(body) if handshake_type == TLS::HandshakeType::CertificateRequest
      @transcript.add(message)
      break if handshake_type == TLS::HandshakeType::Finished
    end

    schedule.enter_master_stage
    application_digest = @transcript.digest(hash)
    client_application_secret = schedule.client_application_traffic_secret(application_digest)
    server_application_secret = schedule.server_application_traffic_secret(application_digest)
    @record_layer.read_protection = TLS::RecordProtection.new(CIPHER_SUITE, server_application_secret)

    if @certificate_request
      write_and_record(certificate_message)
      if certified_key = @certified_key
        write_and_record(certificate_verify_message(certified_key, hash))
      end
    end
    write_and_record(Messages::Finished.new(TLS::KeySchedule.finished_verify_data(hash, client_handshake_secret, @transcript.digest(hash))).encode)
    @record_layer.write_protection = TLS::RecordProtection.new(CIPHER_SUITE, client_application_secret)
    @record_layer.flush
    @resumption_master_secret = schedule.resumption_master_secret(@transcript.digest(hash))
  end

  # Reads the server's first NewSessionTicket. Raises the server's alert
  # (`Beryl::TLS::PeerAlert`) when the server ended the handshake instead.
  def read_ticket : Ticket
    loop do
      record = @record_layer.read_after_handshake || raise "the server closed without a ticket"
      content_type, content = record
      next unless content_type.handshake?
      handshake_type, body = Messages.unwrap(content)
      next unless handshake_type == TLS::HandshakeType::NewSessionTicket
      ticket = Messages::NewSessionTicket.decode(body)
      pre_shared_key = TLS::KeySchedule.resumption_pre_shared_key(CIPHER_SUITE.hash_algorithm, @resumption_master_secret, ticket.ticket_nonce)
      return Ticket.new(ticket.ticket, pre_shared_key, ticket.ticket_age_add)
    end
  end

  private def write_and_record(message : Bytes) : Nil
    @record_layer.write_handshake(message)
    @transcript.add(message)
  end

  private def certificate_message : Bytes
    list_of_entries = (@certified_key.try(&.list_of_certificates) || [] of Beryl::Certificates::Certificate).map do |certificate|
      Messages::CertificateEntry.new(certificate.encoded, [] of Messages::Extension)
    end
    Messages::CertificateMessage.new(Bytes.empty, list_of_entries).encode
  end

  private def certificate_verify_message(certified_key : TLS::CertifiedKey, hash : TLS::HashAlgorithm) : Bytes
    scheme = certified_key.list_of_signature_schemes.first
    content = Messages::CertificateVerify.signed_content(@transcript.digest(hash), is_server: false)
    signature = @is_sending_empty_signature ? Bytes.empty : certified_key.sign(scheme, content, TLS::HandshakeRandomness.new)
    signature[signature.size - 1] ^= 0x01_u8 if @is_corrupting_certificate_verify
    Messages::CertificateVerify.new((@declared_signature_scheme || scheme).value, signature).encode
  end

  private def encode_with_binder(client_hello : Messages::ClientHello, ticket : Ticket?) : Bytes
    return client_hello.encode unless ticket
    hash = CIPHER_SUITE.hash_algorithm
    identity = ExtensionCodec::PskIdentity.new(ticket.ticket, ticket.ticket_age_add)
    placeholder = Bytes.new(hash.bytesize)
    client_hello.list_of_extensions << Messages::Extension.new(TLS::ExtensionType::PreSharedKey.value,
      ExtensionCodec.encode_client_pre_shared_key([identity], [placeholder]))
    message = client_hello.encode
    prefix = message[0, Messages::ClientHello.binder_prefix_bytesize(message, [placeholder])]
    binder_key = TLS::KeySchedule.new(hash, ticket.resumption_pre_shared_key).resumption_binder_key
    binder = TLS::KeySchedule.finished_verify_data(hash, binder_key, @transcript.digest_with(prefix, hash))
    binder.copy_to(message + (message.size - binder.size))
    message
  end
end
