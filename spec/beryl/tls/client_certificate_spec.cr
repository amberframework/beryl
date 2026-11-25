require "../../spec_helper"

private alias TLS = Beryl::TLS
private alias KeyKind = TestCertificateAuthority::KeyKind

# What one connection between a `ClientCertificatePeer` and a Beryl server
# ended with.
private record PeerConnection,
  peer : ClientCertificatePeer,
  server : TLS::Socket::Server | Exception,
  ticket : ClientCertificatePeer::Ticket?

# A server context that asks for client certificates in *mode* and trusts
# the shared test authority to issue them.
private def client_authenticating_context(mode : TLS::ClientVerifyMode = TLS::ClientVerifyMode::Required) : TLS::Context::Server
  context = TlsHarness.server_context
  context.client_verify_mode = mode
  context.client_trust_store = TlsHarness.authority.trust_store
  context
end

# Runs the server in a fiber and the peer here, presenting *certified_key*
# when asked. Reads the server's first ticket when its handshake passed.
private def connect_peer(context : TLS::Context::Server, certified_key : TLS::CertifiedKey? = nil, *,
                         ticket : ClientCertificatePeer::Ticket? = nil, is_corrupting_certificate_verify : Bool = false,
                         declared_signature_scheme : TLS::SignatureScheme? = nil, is_sending_empty_signature : Bool = false) : PeerConnection
  client_io, server_io = UNIXSocket.pair
  server_result = Channel(TLS::Socket::Server | Exception).new(1)
  spawn do
    server_result.send(TLS::Socket::Server.new(server_io, context, sync_close: true))
  rescue error
    server_io.close
    server_result.send(error)
  end
  peer = ClientCertificatePeer.new(client_io)
  peer.certified_key = certified_key
  peer.is_corrupting_certificate_verify = is_corrupting_certificate_verify
  peer.declared_signature_scheme = declared_signature_scheme
  peer.is_sending_empty_signature = is_sending_empty_signature
  begin
    peer.handshake(ticket)
  rescue TLS::Error
    # The server's alert; its own error says why.
  end
  server = server_result.receive
  next_ticket = server.is_a?(TLS::Socket::Server) && context.session_tickets_enabled? ? peer.read_ticket : nil
  client_io.close
  server.close if server.is_a?(TLS::Socket::Server)
  PeerConnection.new(peer, server, next_ticket)
end

private def expect_server(connection : PeerConnection) : TLS::Socket::Server
  server = connection.server
  raise server if server.is_a?(Exception)
  server
end

private def expect_alert(connection : PeerConnection, description : TLS::AlertDescription) : Nil
  server = connection.server
  fail "the server's handshake passed" unless server.is_a?(TLS::Error)
  server.alert_description.should eq(description)
end

describe "Beryl::TLS server client certificates" do
  describe "ClientVerifyMode::Required" do
    {% for key_kind in %w(P256 Ed25519 Rsa2048) %}
      it "accepts a {{key_kind.id}} client chain from a trusted authority and exposes the peer" do
        certified_key = TlsHarness.authority.issue_client(KeyKind::{{key_kind.id}}, common_name: "alice")
        connection = connect_peer(client_authenticating_context, certified_key)
        server = expect_server(connection)
        server.peer_certificate.try(&.subject.to_s).should eq("CN=alice")
        server.list_of_peer_certificates.size.should eq(2)
        server.peer_certificate_chain.should eq(server.list_of_peer_certificates)
      end
    {% end %}

    it "sends a CertificateRequest with an empty context, the schemes it verifies and its authorities' names" do
      connection = connect_peer(client_authenticating_context, TlsHarness.authority.issue_client)
      expect_server(connection)
      request = connection.peer.certificate_request || fail "no CertificateRequest"
      request.certificate_request_context.should be_empty
      schemes = Beryl::TLS::Messages::ExtensionCodec.decode_u16_list(request.extension(TLS::ExtensionType::SignatureAlgorithms) || fail "no signature_algorithms")
      schemes.should eq(TLS::CertificateVerifier::LIST_OF_VERIFIED_SIGNATURE_SCHEMES.map(&.value))
      authorities = request.extension(TLS::ExtensionType::CertificateAuthorities) || fail "no certificate_authorities"
      subject = TlsHarness.authority.certificate.subject.encoded
      authorities.hexstring.should contain(subject.hexstring)
    end

    it "refuses an empty Certificate (certificate_required)" do
      expect_alert(connect_peer(client_authenticating_context, nil), TLS::AlertDescription::CertificateRequired)
    end

    it "refuses a chain from an authority it does not trust (unknown_ca)" do
      stranger = TestCertificateAuthority::Authority.new("Stranger Root")
      expect_alert(connect_peer(client_authenticating_context, stranger.issue_client), TLS::AlertDescription::UnknownCa)
    end

    it "refuses a leaf whose extended key usage is serverAuth only (bad_certificate)" do
      certified_key = TlsHarness.authority.issue_client(list_of_extended_key_usages: [TestCertificateAuthority::SERVER_AUTHENTICATION])
      expect_alert(connect_peer(client_authenticating_context, certified_key), TLS::AlertDescription::BadCertificate)
    end

    it "refuses a CertificateVerify whose signature does not verify (decrypt_error)" do
      connection = connect_peer(client_authenticating_context, TlsHarness.authority.issue_client, is_corrupting_certificate_verify: true)
      expect_alert(connection, TLS::AlertDescription::DecryptError)
    end

    it "refuses an empty CertificateVerify signature (decrypt_error)" do
      connection = connect_peer(client_authenticating_context, TlsHarness.authority.issue_client, is_sending_empty_signature: true)
      expect_alert(connection, TLS::AlertDescription::DecryptError)
    end

    it "refuses a CertificateVerify scheme for another curve or key type (illegal_parameter)" do
      {TLS::SignatureScheme::EcdsaSecp384r1Sha384, TLS::SignatureScheme::Ed25519, TLS::SignatureScheme::RsaPssRsaeSha256}.each do |scheme|
        connection = connect_peer(client_authenticating_context, TlsHarness.authority.issue_client, declared_signature_scheme: scheme)
        expect_alert(connection, TLS::AlertDescription::IllegalParameter)
      end
    end

    it "refuses a CertificateVerify scheme it did not request (illegal_parameter)" do
      connection = connect_peer(client_authenticating_context, TlsHarness.authority.issue_client(KeyKind::Rsa2048),
        declared_signature_scheme: TLS::SignatureScheme::RsaPkcs1Sha256)
      expect_alert(connection, TLS::AlertDescription::IllegalParameter)
    end

    it "refuses to start without a client trust store or verifier (internal_error)" do
      context = TlsHarness.server_context
      context.client_verify_mode = TLS::ClientVerifyMode::Required
      expect_alert(connect_peer(context, TlsHarness.authority.issue_client), TLS::AlertDescription::InternalError)
    end

    it "resumes a session with the client certificate of the handshake that issued its ticket" do
      context = client_authenticating_context
      first = connect_peer(context, TlsHarness.authority.issue_client(common_name: "bob"))
      expect_server(first)
      ticket = first.ticket || fail "no ticket"
      resumed = connect_peer(context, nil, ticket: ticket)
      server = expect_server(resumed)
      resumed.peer.resumed?.should be_true
      resumed.peer.certificate_request.should be_nil
      server.peer_certificate.try(&.subject.to_s).should eq("CN=bob")
    end

    it "gives a full handshake to a ticket from a session that had no client certificate" do
      context = client_authenticating_context(TLS::ClientVerifyMode::Optional)
      first = connect_peer(context, nil)
      expect_server(first).peer_certificate.should be_nil
      ticket = first.ticket || fail "no ticket"
      context.client_verify_mode = TLS::ClientVerifyMode::Required
      second = connect_peer(context, TlsHarness.authority.issue_client(common_name: "carol"), ticket: ticket)
      server = expect_server(second)
      second.peer.resumed?.should be_false
      server.peer_certificate.try(&.subject.to_s).should eq("CN=carol")
    end

    it "gives a full handshake to a ticket whose chain no longer verifies" do
      context = client_authenticating_context
      first = connect_peer(context, TlsHarness.authority.issue_client)
      ticket = first.ticket || fail "no ticket"
      context.client_trust_store = TestCertificateAuthority::Authority.new("Replacement Root").trust_store
      second = connect_peer(context, TlsHarness.authority.issue_client, ticket: ticket)
      second.peer.resumed?.should be_false
      expect_alert(second, TLS::AlertDescription::UnknownCa)
    end
  end

  describe "ClientVerifyMode::Optional" do
    it "accepts an empty Certificate and has no peer certificate" do
      connection = connect_peer(client_authenticating_context(TLS::ClientVerifyMode::Optional), nil)
      server = expect_server(connection)
      connection.peer.certificate_request.should_not be_nil
      server.peer_certificate.should be_nil
      server.list_of_peer_certificates.should be_empty
    end

    it "verifies a chain the client sends" do
      context = client_authenticating_context(TLS::ClientVerifyMode::Optional)
      expect_server(connect_peer(context, TlsHarness.authority.issue_client(common_name: "dave"))).peer_certificate.try(&.subject.to_s).should eq("CN=dave")
      stranger = TestCertificateAuthority::Authority.new("Stranger Root")
      expect_alert(connect_peer(context, stranger.issue_client), TLS::AlertDescription::UnknownCa)
    end

    it "completes with Beryl's own client, which answers with an empty Certificate" do
      TlsHarness.connect(client_authenticating_context(TLS::ClientVerifyMode::Optional), TlsHarness.client_context) do |client, server|
        raise client if client.is_a?(Exception)
        raise server if server.is_a?(Exception)
        server.peer_certificate.should be_nil
        client.print "ping\n"
        client.flush
        server.gets.should eq("ping")
      end
    end
  end

  describe "ClientVerifyMode::None" do
    it "sends no CertificateRequest" do
      connection = connect_peer(TlsHarness.server_context, TlsHarness.authority.issue_client)
      expect_server(connection).peer_certificate.should be_nil
      connection.peer.certificate_request.should be_nil
    end
  end

  describe TLS::Context::Server do
    it "maps verify_mode= Peer to Required and None to None, as OpenSSL's server context takes it" do
      context = TLS::Context::Server.new
      context.client_verify_mode.should eq(TLS::ClientVerifyMode::None)
      context.verify_mode = TLS::VerifyMode::Peer
      context.client_verify_mode.should eq(TLS::ClientVerifyMode::Required)
      context.verify_mode.should eq(TLS::VerifyMode::Peer)
      context.verify_mode = TLS::VerifyMode::None
      context.client_verify_mode.should eq(TLS::ClientVerifyMode::None)
    end

    it "reads a client trust store from a PEM file" do
      File.tempfile("clients-ca", ".pem") do |file|
        file.print "-----BEGIN CERTIFICATE-----\n"
        file.print Base64.encode(TlsHarness.authority.certificate.encoded)
        file.print "-----END CERTIFICATE-----\n"
      end.tap do |file|
        context = TLS::Context::Server.new
        context.client_ca_certificates = file.path
        context.client_trust_store.try(&.size).should eq(1)
        context.client_certificate_verifier.should be_a(TLS::ClientCertificateVerifier)
      ensure
        file.delete
      end
    end
  end

  describe TLS::ClientCertificateVerifier do
    it "verifies a clientAuth leaf with no subject alternative name, which a server leaf would need" do
      chain = TlsHarness.authority.issue_client.list_of_certificates
      chain.first.extension(Beryl::Certificates::ObjectIdentifiers::SUBJECT_ALTERNATIVE_NAME).should be_nil
      TLS::ClientCertificateVerifier.new(TlsHarness.authority.trust_store).verify_chain(chain, nil)
      expect_raises(TLS::CertificateRejected) { TLS::WebPkiVerifier.new(TlsHarness.authority.trust_store).verify_chain(chain, nil) }
    end

    it "refuses an expired client leaf (certificate_expired)" do
      chain = TlsHarness.authority.issue_client.list_of_certificates
      verifier = TLS::ClientCertificateVerifier.new(TlsHarness.authority.trust_store, time_source: -> { Time.utc + 60.days })
      error = expect_raises(TLS::CertificateRejected) { verifier.verify_chain(chain, nil) }
      error.alert_description.should eq(TLS::AlertDescription::CertificateExpired)
    end
  end
end
