require "../../spec_helper"

private alias TLS = Beryl::TLS
private alias Trace = Rfc8448Trace

private SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

private def secret(section : Int32, label : String) : Bytes
  Trace.field(section, "server", "derive secret \"tls13 #{label}\"", "expanded")
end

# Returns a protection that has already used *count* sequence numbers.
private def protection_at(traffic_secret : Bytes, count : Int32) : TLS::RecordProtection
  protection = TLS::RecordProtection.new(SUITE, traffic_secret)
  count.times { protection.seal(TLS::ContentType::ApplicationData, Bytes.empty) }
  protection
end

private def record_step(section : Int32, actor : String, title : String, occurrence : Int32 = 1) : {Bytes, Bytes}
  step = Trace.step(section, actor, title, occurrence)
  {step.field("payload"), step.field("complete record")}
end

private def plaintext_record(content_type : TLS::ContentType, content : Bytes) : Bytes
  Bytes[content_type.value, 3, 3, (content.size >> 8).to_u8, (content.size & 0xFF).to_u8] + content
end

private def layer_reading(bytes : Bytes, limits : TLS::Limits = TLS::Limits.new) : TLS::RecordLayer
  TLS::RecordLayer.new(IO::Memory.new(bytes), limits)
end

private def expect_alert(description : TLS::AlertDescription, &)
  error = expect_raises(TLS::Error) { yield }
  error.alert_description.should eq(description)
end

describe Beryl::TLS::RecordProtection do
  context "RFC 8448 §3, every protected record" do
    list_of_cases = [
      {"server", "send handshake record", 2, "s hs traffic", 0, TLS::ContentType::Handshake},
      {"client", "send handshake record", 2, "c hs traffic", 0, TLS::ContentType::Handshake},
      {"server", "send handshake record", 3, "s ap traffic", 0, TLS::ContentType::Handshake},
      {"client", "send application_data record", 1, "c ap traffic", 0, TLS::ContentType::ApplicationData},
      {"server", "send application_data record", 1, "s ap traffic", 1, TLS::ContentType::ApplicationData},
      {"client", "send alert record", 1, "c ap traffic", 1, TLS::ContentType::Alert},
      {"server", "send alert record", 1, "s ap traffic", 2, TLS::ContentType::Alert},
    ]
    list_of_cases.each do |(actor, title, occurrence, label, sequence_number, content_type)|
      it "seals and opens the #{actor}'s \"#{title}\" (#{label}, sequence number #{sequence_number})" do
        # The first "send handshake record" of each side is plaintext.
        payload, complete_record = record_step(3, actor, title, occurrence)
        protection_at(secret(3, label), sequence_number).seal(content_type, payload).should eq(complete_record)
        opened = protection_at(secret(3, label), sequence_number).open(complete_record[0, 5], complete_record[5..]) || fail "the record did not open"
        opened.should eq({content_type, payload})
      end
    end
  end

  context "RFC 8448 §5, the protected handshake records after a HelloRetryRequest" do
    it "seals and opens the server's flight and the client's Finished" do
      payload, complete_record = record_step(5, "server", "send handshake record", 3)
      protection_at(secret(5, "s hs traffic"), 0).seal(TLS::ContentType::Handshake, payload).should eq(complete_record)
      payload, complete_record = record_step(5, "client", "send handshake record", 3)
      protection_at(secret(5, "c hs traffic"), 0).seal(TLS::ContentType::Handshake, payload).should eq(complete_record)
    end
  end

  describe "#open" do
    it "returns nil for a record whose tag does not match, and keeps its sequence number" do
      payload, complete_record = record_step(3, "client", "send application_data record")
      tampered = complete_record.dup
      tampered[-1] ^= 1
      protection = protection_at(secret(3, "c ap traffic"), 0)
      protection.open(tampered[0, 5], tampered[5..]).should be_nil
      protection.sequence_number.should eq(0)
      protection.open(complete_record[0, 5], complete_record[5..]).should eq({TLS::ContentType::ApplicationData, payload})
    end

    it "reads the content type before the zero padding" do
      sealing = TLS::RecordProtection.new(SUITE, Bytes.new(32, 7))
      record = sealing.seal(TLS::ContentType::ApplicationData, "padded".to_slice, padding_bytesize: 100)
      record.size.should eq(5 + 6 + 1 + 100 + 16)
      TLS::RecordProtection.new(SUITE, Bytes.new(32, 7)).open(record[0, 5], record[5..])
        .should eq({TLS::ContentType::ApplicationData, "padded".to_slice})
    end

    it "refuses an inner plaintext that is all padding" do
      key, iv = TLS::KeySchedule.traffic_key_and_iv(SUITE.hash_algorithm, Bytes.new(32, 7), 16)
      header = Bytes[23, 3, 3, 0, 20]
      ciphertext = Beryl::Crypto::V1::AESGCM.new(key).encrypt(Bytes.new(4), nonce: iv, associated_data: header)
      expect_alert(TLS::AlertDescription::UnexpectedMessage) do
        TLS::RecordProtection.new(SUITE, Bytes.new(32, 7)).open(header, ciphertext)
      end
    end
  end

  it "works for every suite" do
    TLS::CipherSuite.each do |suite|
      traffic_secret = Bytes.new(suite.hash_algorithm.bytesize, 9)
      record = TLS::RecordProtection.new(suite, traffic_secret).seal(TLS::ContentType::ApplicationData, "every suite".to_slice)
      TLS::RecordProtection.new(suite, traffic_secret).open(record[0, 5], record[5..])
        .should eq({TLS::ContentType::ApplicationData, "every suite".to_slice})
    end
  end
end

describe Beryl::TLS::RecordLayer do
  describe "#read_handshake_message" do
    it "splits the server's protected flight of RFC 8448 §3 into its four messages" do
      _, complete_record = record_step(3, "server", "send handshake record", 2)
      layer = layer_reading(complete_record)
      layer.read_protection = protection_at(secret(3, "s hs traffic"), 0)
      %w(EncryptedExtensions Certificate CertificateVerify Finished).each do |message_name|
        article = message_name.starts_with?('E') ? "an" : "a"
        layer.read_handshake_message.should eq(Trace.field(3, "server", "construct #{article} #{message_name} handshake message", message_name))
      end
      layer.handshake_buffer_empty?.should be_true
    end

    it "reassembles a message split over records and skips one compatibility change_cipher_spec before it" do
      message = Bytes[1, 0, 0, 5, 1, 2, 3, 4, 5]
      bytes = plaintext_record(TLS::ContentType::ChangeCipherSpec, Bytes[1]) +
              plaintext_record(TLS::ContentType::Handshake, message[0, 3]) +
              plaintext_record(TLS::ContentType::Handshake, message[3..])
      layer_reading(bytes).read_handshake_message.should eq(message)
    end

    it "refuses a change_cipher_spec between the fragments of a handshake message (unexpected_message)" do
      message = Bytes[1, 0, 0, 5, 1, 2, 3, 4, 5]
      bytes = plaintext_record(TLS::ContentType::Handshake, message[0, 3]) +
              plaintext_record(TLS::ContentType::ChangeCipherSpec, Bytes[1]) +
              plaintext_record(TLS::ContentType::Handshake, message[3..])
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer_reading(bytes).read_handshake_message }
    end

    it "refuses a change_cipher_spec while they are turned off (unexpected_message)" do
      layer = layer_reading(plaintext_record(TLS::ContentType::ChangeCipherSpec, Bytes[1]))
      layer.is_change_cipher_spec_allowed = false
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_handshake_message }
    end

    it "refuses a second change_cipher_spec, or one that is not the single byte 1" do
      ccs = plaintext_record(TLS::ContentType::ChangeCipherSpec, Bytes[1])
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer_reading(ccs + ccs).read_handshake_message }
      expect_alert(TLS::AlertDescription::UnexpectedMessage) do
        layer_reading(plaintext_record(TLS::ContentType::ChangeCipherSpec, Bytes[2])).read_handshake_message
      end
    end

    it "refuses a plaintext record over 2^14 bytes" do
      expect_alert(TLS::AlertDescription::RecordOverflow) do
        layer_reading(plaintext_record(TLS::ContentType::Handshake, Bytes.new(16_385, 1))).read_handshake_message
      end
    end

    it "refuses a ciphertext record over 16,640 bytes before reading it" do
      header = Bytes[23, 3, 3, (16_641 >> 8).to_u8, (16_641 & 0xFF).to_u8]
      layer = layer_reading(header)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32))
      expect_alert(TLS::AlertDescription::RecordOverflow) { layer.read_handshake_message }
    end

    it "refuses a protected record whose plaintext is over 2^14 bytes" do
      key, iv = TLS::KeySchedule.traffic_key_and_iv(SUITE.hash_algorithm, Bytes.new(32, 3), 16)
      inner = Bytes.new(16_386, 1)
      inner[-1] = TLS::ContentType::Handshake.value
      length = inner.size + 16
      header = Bytes[23, 3, 3, (length >> 8).to_u8, (length & 0xFF).to_u8]
      record = header + Beryl::Crypto::V1::AESGCM.new(key).encrypt(inner, nonce: iv, associated_data: header)
      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 3))
      expect_alert(TLS::AlertDescription::RecordOverflow) { layer.read_handshake_message }
    end

    it "refuses a protected record whose inner plaintext, padding included, is over 2^14 + 1 bytes" do
      key, iv = TLS::KeySchedule.traffic_key_and_iv(SUITE.hash_algorithm, Bytes.new(32, 3), 16)
      # 16,384 bytes of content, its type, then one byte of padding.
      inner = Bytes.new(16_386, 1)
      inner[16_384] = TLS::ContentType::ApplicationData.value
      inner[16_385] = 0
      length = inner.size + 16
      header = Bytes[23, 3, 3, (length >> 8).to_u8, (length & 0xFF).to_u8]
      record = header + Beryl::Crypto::V1::AESGCM.new(key).encrypt(inner, nonce: iv, associated_data: header)
      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 3))
      expect_alert(TLS::AlertDescription::RecordOverflow) { layer.read_after_handshake }
    end

    it "refuses a record that fails authentication" do
      _, complete_record = record_step(3, "server", "send handshake record", 2)
      tampered = complete_record.dup
      tampered[40] ^= 0x80
      layer = layer_reading(tampered)
      layer.read_protection = protection_at(secret(3, "s hs traffic"), 0)
      expect_alert(TLS::AlertDescription::BadRecordMac) { layer.read_handshake_message }
    end

    it "refuses a protected record whose outer type is not application_data" do
      _, complete_record = record_step(3, "server", "send handshake record", 2)
      relabeled = complete_record.dup
      relabeled[0] = TLS::ContentType::Handshake.value
      layer = layer_reading(relabeled)
      layer.read_protection = protection_at(secret(3, "s hs traffic"), 0)
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_handshake_message }
    end

    it "refuses plaintext application data and a zero-length handshake fragment" do
      expect_alert(TLS::AlertDescription::UnexpectedMessage) do
        layer_reading(plaintext_record(TLS::ContentType::ApplicationData, Bytes[1])).read_handshake_message
      end
      expect_alert(TLS::AlertDescription::UnexpectedMessage) do
        layer_reading(plaintext_record(TLS::ContentType::Handshake, Bytes.empty)).read_handshake_message
      end
    end

    it "refuses a handshake message longer than the limit as soon as its header arrives" do
      header = Bytes[1, 0x01, 0x11, 0x71] # 70,001 bytes declared
      expect_alert(TLS::AlertDescription::IllegalParameter) do
        layer_reading(plaintext_record(TLS::ContentType::Handshake, header)).read_handshake_message
      end
    end

    it "refuses an alert inside a handshake message, and an alert that is not two bytes" do
      bytes = plaintext_record(TLS::ContentType::Handshake, Bytes[1, 0, 0, 9]) + plaintext_record(TLS::ContentType::Alert, Bytes[2, 40])
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer_reading(bytes).read_handshake_message }
      expect_alert(TLS::AlertDescription::DecodeError) do
        layer_reading(plaintext_record(TLS::ContentType::Alert, Bytes[2, 40, 0])).read_handshake_message
      end
    end

    it "refuses a record of an unknown type from its header, before reading its body (unexpected_message)" do
      # An SSL 2.0 ClientHello header: its length is never waited for.
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer_reading(Bytes[0x80, 0x2e, 1, 3, 4]).read_handshake_message }
    end

    it "reassembles a large handshake message sent one byte per record in linear time" do
      message = Bytes.new(4 + 60_000, 7_u8)
      message[0] = 1_u8
      message[1] = 0_u8
      message[2] = (60_000 >> 8).to_u8
      message[3] = (60_000 & 0xFF).to_u8
      input = IO::Memory.new
      message.each { |byte| input.write(plaintext_record(TLS::ContentType::Handshake, Bytes[byte])) }
      started = Time.instant
      layer_reading(input.to_slice).read_handshake_message.should eq(message)
      (Time.instant - started).should be < 2.seconds
    end

    it "refuses an empty alert record (unexpected_message)" do
      expect_alert(TLS::AlertDescription::UnexpectedMessage) do
        layer_reading(plaintext_record(TLS::ContentType::Alert, Bytes.empty)).read_handshake_message
      end
    end

    it "refuses application data during the handshake, an empty record included (unexpected_message)" do
      writer = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      layer = layer_reading(writer.seal(TLS::ContentType::ApplicationData, Bytes.empty))
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_handshake_message }
    end

    it "reads a plaintext alert under protection only while plaintext alerts are accepted" do
      record = plaintext_record(TLS::ContentType::Alert, Bytes[2, TLS::AlertDescription::BadCertificate.value])
      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_handshake_message }

      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      layer.is_accepting_plaintext_alerts = true
      error = expect_raises(TLS::UnauthenticatedAlert) { layer.read_handshake_message }
      error.alert_description.should eq(TLS::AlertDescription::BadCertificate)
    end

    it "refuses a protected record over its own record_size_limit before opening it (record_overflow)" do
      traffic_secret = Bytes.new(32, 7)
      record = TLS::RecordProtection.new(SUITE, traffic_secret).seal(TLS::ContentType::ApplicationData, Bytes.new(200, 1))
      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, traffic_secret)
      layer.largest_incoming_inner_plaintext_bytesize = 200
      expect_alert(TLS::AlertDescription::RecordOverflow) { layer.read_after_handshake }

      layer = layer_reading(record)
      layer.read_protection = TLS::RecordProtection.new(SUITE, traffic_secret)
      layer.largest_incoming_inner_plaintext_bytesize = 201
      layer.read_after_handshake.should eq({TLS::ContentType::ApplicationData, Bytes.new(200, 1)})
    end

    it "raises PeerAlert with the peer's description" do
      error = expect_raises(TLS::PeerAlert) do
        layer_reading(plaintext_record(TLS::ContentType::Alert, Bytes[2, 40])).read_handshake_message
      end
      error.alert_description.should eq(TLS::AlertDescription::HandshakeFailure)
    end

    it "lets one user_canceled warning through and refuses the second in a row" do
      warning = plaintext_record(TLS::ContentType::Alert, Bytes[1, 90])
      message = plaintext_record(TLS::ContentType::Handshake, Bytes[20, 0, 0, 0])
      layer_reading(warning + message).read_handshake_message.should eq(Bytes[20, 0, 0, 0])
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer_reading(warning + warning + message).read_handshake_message }
    end
  end

  describe "#read_after_handshake" do
    it "returns application data, then nil at close_notify" do
      sealing = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      bytes = sealing.seal(TLS::ContentType::ApplicationData, "data".to_slice) + sealing.seal(TLS::ContentType::Alert, Bytes[1, 0])
      layer = layer_reading(bytes)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      layer.read_after_handshake.should eq({TLS::ContentType::ApplicationData, "data".to_slice})
      layer.read_after_handshake.should be_nil
      layer.peer_closed?.should be_true
    end

    it "accepts 32 empty records in a row and refuses the 33rd" do
      [32, 33].each do |count|
        sealing = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
        bytes = IO::Memory.new
        count.times { bytes.write(sealing.seal(TLS::ContentType::ApplicationData, Bytes.empty)) }
        bytes.write(sealing.seal(TLS::ContentType::ApplicationData, "x".to_slice))
        layer = layer_reading(bytes.to_slice)
        layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
        if count == 32
          layer.read_after_handshake.should eq({TLS::ContentType::ApplicationData, "x".to_slice})
        else
          expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_after_handshake }
        end
      end
    end

    it "refuses application data that interrupts a handshake message" do
      sealing = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      bytes = sealing.seal(TLS::ContentType::Handshake, Bytes[4, 0, 0, 10, 0]) + sealing.seal(TLS::ContentType::ApplicationData, "x".to_slice)
      layer = layer_reading(bytes)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 5))
      expect_alert(TLS::AlertDescription::UnexpectedMessage) { layer.read_after_handshake }
    end

    it "skips refused 0-RTT records within the budget, then reads the next record that opens" do
      early = TLS::RecordProtection.new(SUITE, Bytes.new(32, 1))
      handshake = TLS::RecordProtection.new(SUITE, Bytes.new(32, 2))
      bytes = early.seal(TLS::ContentType::ApplicationData, Bytes.new(1000)) + handshake.seal(TLS::ContentType::Handshake, Bytes[20, 0, 0, 0])
      layer = layer_reading(bytes)
      layer.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 2))
      layer.early_data_skip_budget = 16_384
      layer.read_handshake_message.should eq(Bytes[20, 0, 0, 0])
      layer.early_data_skip_budget.should eq(0)

      over_budget = layer_reading(early.seal(TLS::ContentType::ApplicationData, Bytes.new(2000)))
      over_budget.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 2))
      over_budget.early_data_skip_budget = 1000
      expect_alert(TLS::AlertDescription::BadRecordMac) { over_budget.read_handshake_message }
    end
  end

  describe "#write_application_data" do
    it "splits data into records of at most 2^14 bytes, or the peer's record size limit" do
      output = IO::Memory.new
      layer = TLS::RecordLayer.new(output)
      layer.write_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 4))
      layer.write_application_data(Bytes.new(40_000, 1))
      reader = layer_reading(output.to_slice)
      reader.read_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 4))
      list_of_sizes = (1..3).map { (reader.read_after_handshake || fail "missing record")[1].size }
      list_of_sizes.should eq([16_384, 16_384, 7_232])

      output = IO::Memory.new
      layer = TLS::RecordLayer.new(output)
      layer.largest_outgoing_fragment_bytesize = 63
      layer.write_protection = TLS::RecordProtection.new(SUITE, Bytes.new(32, 4))
      layer.write_application_data(Bytes.new(100, 1))
      output.size.should eq(2 * 5 + 63 + 37 + 2 * 17)
    end

    it "writes nothing after close_notify" do
      output = IO::Memory.new
      layer = TLS::RecordLayer.new(output)
      layer.write_alert(TLS::AlertLevel::Warning, TLS::AlertDescription::CloseNotify)
      expect_raises(TLS::ConnectionClosed) { layer.write_application_data("late".to_slice) }
    end
  end
end
