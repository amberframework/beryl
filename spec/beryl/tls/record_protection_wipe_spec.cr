require "../../spec_helper"

private alias TLS = Beryl::TLS

# Returns every buffer *cipher* derived from its key.
private def key_material_of(cipher : Beryl::Crypto::V1::AuthenticatedEncryption) : Array(Bytes)
  if cipher.is_a?(Beryl::Crypto::V1::AESGCM)
    cipher.list_of_key_material_for_spec
  elsif cipher.is_a?(Beryl::Crypto::V1::ChaCha20Poly1305)
    cipher.list_of_key_material_for_spec
  else
    raise "no spec view of #{cipher.class}"
  end
end

describe Beryl::TLS::RecordProtection do
  describe "#wipe" do
    {% for suite in %w[TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256] %}
      context "under {{ suite.id }}" do
        it "zeroes the AEAD's key-derived storage" do
          suite = TLS::CipherSuite::{{ suite.id }}
          protection = TLS::RecordProtection.new(suite, Random::Secure.random_bytes(suite.hash_algorithm.bytesize))
          list_of_key_material = key_material_of(protection.authenticated_encryption_for_spec)
          list_of_key_material.any? { |buffer| buffer.any? { |byte| byte != 0 } }.should be_true

          protection.wipe

          protection.authenticated_encryption_for_spec.is_wiped?.should be_true
          list_of_key_material.each { |buffer| buffer.all?(&.zero?).should be_true }
        end

        it "raises on seal and open once wiped" do
          suite = TLS::CipherSuite::{{ suite.id }}
          traffic_secret = Random::Secure.random_bytes(suite.hash_algorithm.bytesize)
          sender = TLS::RecordProtection.new(suite, traffic_secret)
          receiver = TLS::RecordProtection.new(suite, traffic_secret)
          record = sender.seal(TLS::ContentType::ApplicationData, "hello".to_slice)
          sender.wipe
          receiver.wipe

          expect_raises(Beryl::Crypto::KeyWiped) { sender.seal(TLS::ContentType::ApplicationData, "hello".to_slice) }
          expect_raises(Beryl::Crypto::KeyWiped) do
            receiver.open(record[0, TLS::RecordProtection::HEADER_BYTESIZE], record[TLS::RecordProtection::HEADER_BYTESIZE..])
          end
        end
      end
    {% end %}
  end
end
