require "../../spec_helper"

private alias KeySchedule = Beryl::TLS::KeySchedule
private alias HashAlgorithm = Beryl::TLS::HashAlgorithm
private alias Trace = Rfc8448Trace

# The handshake message a trace step constructs, by its message name.
private def trace_message(section : Int32, actor : String, message_name : String, occurrence : Int32 = 1) : Bytes
  Trace.field(section, actor, "construct a#{message_name.starts_with?('E') ? "n" : ""} #{message_name} handshake message", message_name, occurrence)
end

private def transcript_of(list_of_messages : Array(Bytes)) : Beryl::TLS::TranscriptHash
  transcript = Beryl::TLS::TranscriptHash.new
  list_of_messages.each { |message| transcript.add(message) }
  transcript
end

private def expanded(section : Int32, actor : String, title : String, occurrence : Int32 = 1) : Bytes
  Trace.field(section, actor, title, "expanded", occurrence)
end

describe Beryl::TLS::KeySchedule do
  describe ".expand_label" do
    it "builds the HkdfLabel of RFC 9846 §7.1 (RFC 8448 §3, the server handshake key and IV)" do
      secret = expanded(3, "server", "derive secret \"tls13 s hs traffic\"")
      key, iv = KeySchedule.traffic_key_and_iv(HashAlgorithm::SHA256, secret, 16)
      step = Trace.step(3, "server", "derive write traffic keys for handshake data")
      key.should eq(step.field("key expanded"))
      iv.should eq(step.field("iv expanded"))
    end
  end

  context "RFC 8448 §3, simple 1-RTT handshake" do
    client_hello = trace_message(3, "client", "ClientHello")
    server_hello = trace_message(3, "server", "ServerHello")
    encrypted_extensions = trace_message(3, "server", "EncryptedExtensions")
    certificate = trace_message(3, "server", "Certificate")
    certificate_verify = trace_message(3, "server", "CertificateVerify")
    server_finished = trace_message(3, "server", "Finished")
    client_finished = trace_message(3, "client", "Finished")
    hash = HashAlgorithm::SHA256

    it "computes the X25519 shared secret both sides feed the schedule" do
      client_key = Beryl::Crypto::V1::X25519::PrivateKey.new(Trace.field(3, "client", "create an ephemeral x25519 key pair", "private key"))
      server_key = Beryl::Crypto::V1::X25519::PrivateKey.new(Trace.field(3, "server", "create an ephemeral x25519 key pair", "private key"))
      client_key.public_key.to_slice.should eq(Trace.field(3, "client", "create an ephemeral x25519 key pair", "public key"))
      shared_secret = client_key.shared_secret(server_key.public_key) || fail "a small-order point"
      shared_secret.should eq(Trace.field(3, "server", "extract secret \"handshake\"", "IKM"))
    end

    it "derives every secret, key, IV and Finished value of the trace" do
      schedule = KeySchedule.new(hash)
      schedule.early_secret.should eq(Trace.field(3, "server", "extract secret \"early\"", "secret"))

      transcript = transcript_of([client_hello, server_hello])
      transcript.digest(hash).should eq(Trace.field(3, "server", "derive secret \"tls13 c hs traffic\"", "hash"))
      schedule.enter_handshake_stage(Trace.field(3, "server", "extract secret \"handshake\"", "IKM"))
      client_handshake_secret = schedule.client_handshake_traffic_secret(transcript.digest(hash))
      server_handshake_secret = schedule.server_handshake_traffic_secret(transcript.digest(hash))
      client_handshake_secret.should eq(expanded(3, "server", "derive secret \"tls13 c hs traffic\""))
      server_handshake_secret.should eq(expanded(3, "server", "derive secret \"tls13 s hs traffic\""))

      [encrypted_extensions, certificate, certificate_verify].each { |message| transcript.add(message) }
      finished_step = Trace.step(3, "server", "calculate finished")
      KeySchedule.finished_key(hash, server_handshake_secret).should eq(finished_step.field("expanded"))
      verify_data = KeySchedule.finished_verify_data(hash, server_handshake_secret, transcript.digest(hash))
      verify_data.should eq(finished_step.field("finished"))
      server_finished[4, 32].should eq(verify_data)
      transcript.add(server_finished)

      schedule.enter_master_stage
      digest_through_server_finished = transcript.digest(hash)
      schedule.client_application_traffic_secret(digest_through_server_finished).should eq(expanded(3, "server", "derive secret \"tls13 c ap traffic\""))
      server_application_secret = schedule.server_application_traffic_secret(digest_through_server_finished)
      server_application_secret.should eq(expanded(3, "server", "derive secret \"tls13 s ap traffic\""))
      schedule.exporter_master_secret(digest_through_server_finished).should eq(expanded(3, "server", "derive secret \"tls13 exp master\""))
      key, iv = KeySchedule.traffic_key_and_iv(hash, server_application_secret, 16)
      application_step = Trace.step(3, "server", "derive write traffic keys for application data")
      key.should eq(application_step.field("key expanded"))
      iv.should eq(application_step.field("iv expanded"))

      client_finished_step = Trace.step(3, "client", "calculate finished")
      client_verify_data = KeySchedule.finished_verify_data(hash, client_handshake_secret, digest_through_server_finished)
      client_verify_data.should eq(client_finished_step.field("finished"))
      KeySchedule.finished_matches?(hash, client_handshake_secret, digest_through_server_finished, client_verify_data).should be_true
      tampered = client_verify_data.dup
      tampered[0] ^= 1
      KeySchedule.finished_matches?(hash, client_handshake_secret, digest_through_server_finished, tampered).should be_false
      transcript.add(client_finished)

      resumption_master_secret = schedule.resumption_master_secret(transcript.digest(hash))
      resumption_master_secret.should eq(expanded(3, "client", "derive secret \"tls13 res master\""))
      KeySchedule.resumption_pre_shared_key(hash, resumption_master_secret, Bytes[0, 0])
        .should eq(expanded(3, "server", "generate resumption secret \"tls13 resumption\""))
    end
  end

  context "RFC 8448 §4, resumed handshake (the PSK binder and early secrets)" do
    hash = HashAlgorithm::SHA256
    pre_shared_key = expanded(3, "server", "generate resumption secret \"tls13 resumption\"")

    it "extracts the early secret from the resumption PSK" do
      Trace.field(4, "client", "extract secret \"early\"", "IKM").should eq(pre_shared_key)
      KeySchedule.new(hash, pre_shared_key).early_secret.should eq(Trace.field(4, "client", "extract secret \"early\"", "secret"))
    end

    # The trace's "construct a ClientHello" step prints the prefix (477
    # octets); the whole message (512) is the payload of the record sent.
    it "computes the binder over the ClientHello cut before its binders" do
      schedule = KeySchedule.new(hash, pre_shared_key)
      binder_step = Trace.step(4, "client", "calculate PSK binder")
      client_hello = Trace.field(4, "client", "send handshake record", "payload")
      prefix = binder_step.field("ClientHello prefix")
      # The binders list (2 bytes of length, 1 of binder length, 32 of
      # binder) is what the prefix leaves out.
      prefix.should eq(client_hello[0, client_hello.size - 35])
      binder_digest = Beryl::TLS::TranscriptHash.new.digest_with(prefix, hash)
      binder_digest.should eq(binder_step.field("binder hash"))
      binder_key = schedule.resumption_binder_key
      binder_key.should eq(binder_step.field("PRK"))
      binder = KeySchedule.finished_verify_data(hash, binder_key, binder_digest)
      binder.should eq(binder_step.field("finished"))
      client_hello[client_hello.size - 32, 32].should eq(binder)
    end

    it "derives the client early traffic secret (computed, never used: Beryl refuses 0-RTT)" do
      schedule = KeySchedule.new(hash, pre_shared_key)
      client_hello = Trace.field(4, "client", "send handshake record", "payload")
      digest = Beryl::TLS::TranscriptHash.new.tap(&.add(client_hello)).digest(hash)
      digest.should eq(Trace.field(4, "client", "derive secret \"tls13 c e traffic\"", "hash"))
      schedule.client_early_traffic_secret(digest).should eq(expanded(4, "client", "derive secret \"tls13 c e traffic\""))
    end
  end

  context "RFC 8448 §5, HelloRetryRequest" do
    hash = HashAlgorithm::SHA256

    it "replaces the first ClientHello by its message_hash and derives the trace's secrets" do
      first_client_hello = trace_message(5, "client", "ClientHello", 1)
      hello_retry_request = trace_message(5, "server", "ServerHello", 1)
      second_client_hello = trace_message(5, "client", "ClientHello", 2)
      server_hello = trace_message(5, "server", "ServerHello", 2)

      transcript = transcript_of([first_client_hello])
      transcript.replace_with_message_hash(hash)
      [hello_retry_request, second_client_hello, server_hello].each { |message| transcript.add(message) }
      transcript.digest(hash).should eq(Trace.field(5, "server", "derive secret \"tls13 c hs traffic\"", "hash"))

      client_key = Beryl::Crypto::V1::P256::PrivateKey.new(Trace.field(5, "client", "create an ephemeral P-256 key pair", "private key"))
      server_key = Beryl::Crypto::V1::P256::PrivateKey.new(Trace.field(5, "server", "create an ephemeral P-256 key pair", "private key"))
      client_key.public_key.to_uncompressed.should eq(Trace.field(5, "client", "create an ephemeral P-256 key pair", "public key"))
      shared_secret = client_key.shared_secret(server_key.public_key)
      shared_secret.should eq(Trace.field(5, "server", "extract secret \"handshake\"", "IKM"))

      schedule = KeySchedule.new(hash)
      schedule.enter_handshake_stage(shared_secret)
      schedule.client_handshake_traffic_secret(transcript.digest(hash)).should eq(expanded(5, "server", "derive secret \"tls13 c hs traffic\""))
      server_handshake_secret = schedule.server_handshake_traffic_secret(transcript.digest(hash))
      server_handshake_secret.should eq(expanded(5, "server", "derive secret \"tls13 s hs traffic\""))

      %w(EncryptedExtensions Certificate CertificateVerify).each { |name| transcript.add(trace_message(5, "server", name)) }
      KeySchedule.finished_verify_data(hash, server_handshake_secret, transcript.digest(hash))
        .should eq(Trace.field(5, "server", "calculate finished", "finished"))
      transcript.add(trace_message(5, "server", "Finished"))
      schedule.enter_master_stage
      schedule.server_application_traffic_secret(transcript.digest(hash)).should eq(expanded(5, "server", "derive secret \"tls13 s ap traffic\""))
    end
  end

  describe ".next_application_traffic_secret" do
    it "derives the KeyUpdate secret with the label `traffic upd` (RFC 9846 §7.2)" do
      secret = Bytes.new(32) { |index| index.to_u8 }
      KeySchedule.next_application_traffic_secret(HashAlgorithm::SHA256, secret)
        .should eq(KeySchedule.expand_label(HashAlgorithm::SHA256, secret, "traffic upd", Bytes.empty, 32))
    end
  end

  describe "#client_handshake_traffic_secret" do
    it "raises before the handshake stage" do
      expect_raises(Beryl::TLS::Error, /handshake stage/) do
        KeySchedule.new(HashAlgorithm::SHA384).client_handshake_traffic_secret(Bytes.new(48))
      end
    end
  end
end
