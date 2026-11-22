require "../../../spec_helper"

private MARKER_BYTE = 0xa5_u8

# Builds one cipher of each kind under a random key, with a nonce of the
# size it is meant to be used with.
private def each_cipher(& : String, Beryl::Crypto::V1::AuthenticatedEncryption, Bytes -> Nil) : Nil
  list_of_ciphers = [
    {"ChaCha20-Poly1305", Beryl::Crypto::V1::ChaCha20Poly1305.new(Random::Secure.random_bytes(32)).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
    {"XChaCha20-Poly1305", Beryl::Crypto::V1::XChaCha20Poly1305.new(Random::Secure.random_bytes(32)).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
    {"AES-128-GCM", Beryl::Crypto::V1::AESGCM.new(Random::Secure.random_bytes(16)).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
    {"AES-192-GCM", Beryl::Crypto::V1::AESGCM.new(Random::Secure.random_bytes(24)).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
    {"AES-256-GCM", Beryl::Crypto::V1::AESGCM.new(Random::Secure.random_bytes(32)).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
    {"AES-256-GCM with a 12-byte tag", Beryl::Crypto::V1::AESGCM.new(Random::Secure.random_bytes(32), tag_bytesize: 12).as(Beryl::Crypto::V1::AuthenticatedEncryption)},
  ]
  list_of_ciphers.each do |name, cipher|
    yield name, cipher, Random::Secure.random_bytes(cipher.nonce_bytesize)
  end
end

describe Beryl::Crypto::V1::AuthenticatedEncryption do
  describe "#encrypt and #decrypt" do
    it "return the message for every length from 0 to 300 bytes" do
      each_cipher do |name, cipher, nonce|
        (0..300).each do |bytesize|
          message = Random::Secure.random_bytes(bytesize)
          sealed = cipher.encrypt(message, nonce: nonce, associated_data: "header")
          sealed.size.should eq(bytesize + cipher.tag_bytesize)
          cipher.decrypt(sealed, nonce: nonce, associated_data: "header").should eq(message)
        end
      end
    end

    it "accept a String as the message and as the associated data" do
      each_cipher do |name, cipher, nonce|
        sealed = cipher.encrypt("a private note", nonce: nonce, associated_data: "note 42")
        cipher.decrypt(sealed, nonce: nonce, associated_data: "note 42".to_slice).should eq("a private note".to_slice)
      end
    end

    it "hide the message: the ciphertext differs from the plaintext" do
      each_cipher do |name, cipher, nonce|
        message = Bytes.new(64, 0x41_u8)
        cipher.encrypt(message, nonce: nonce)[0, 64].should_not eq(message)
      end
    end
  end

  describe "#decrypt" do
    it "refuses a message with any single bit flipped" do
      each_cipher do |name, cipher, nonce|
        sealed = cipher.encrypt("sixteen byte msg plus a little more", nonce: nonce, associated_data: "header")
        (sealed.size * 8).times do |bit|
          altered = sealed.dup
          altered[bit // 8] ^= (1_u8 << (bit % 8))
          cipher.decrypt(altered, nonce: nonce, associated_data: "header").should be_nil
        end
      end
    end

    it "refuses other associated data, another nonce and a truncated message" do
      each_cipher do |name, cipher, nonce|
        sealed = cipher.encrypt("message", nonce: nonce, associated_data: "header")
        cipher.decrypt(sealed, nonce: nonce, associated_data: "headeR").should be_nil
        cipher.decrypt(sealed, nonce: nonce).should be_nil
        other_nonce = nonce.dup
        other_nonce[0] ^= 1_u8
        cipher.decrypt(sealed, nonce: other_nonce, associated_data: "header").should be_nil
        cipher.decrypt(sealed[0, sealed.size - 1], nonce: nonce, associated_data: "header").should be_nil
        cipher.decrypt(sealed[0, cipher.tag_bytesize - 1], nonce: nonce, associated_data: "header").should be_nil
        cipher.decrypt(Bytes.empty, nonce: nonce, associated_data: "header").should be_nil
      end
    end

    it "leaves the caller's buffer untouched when the tag is wrong" do
      each_cipher do |name, cipher, nonce|
        {1, 15, 16, 17, 64, 65, 1000}.each do |bytesize|
          sealed = cipher.encrypt(Random::Secure.random_bytes(bytesize), nonce: nonce, associated_data: "header")
          # Every position of the tag, then every position of the ciphertext.
          sealed.size.times do |position|
            altered = sealed.dup
            altered[position] ^= 0x80_u8
            buffer = Bytes.new(bytesize, MARKER_BYTE)
            cipher.decrypt(altered, into: buffer, nonce: nonce, associated_data: "header").should be_false
            buffer.all?(MARKER_BYTE).should be_true
          end
        end
      end
    end

    it "fills the caller's buffer when the tag is right" do
      each_cipher do |name, cipher, nonce|
        message = Random::Secure.random_bytes(100)
        sealed = cipher.encrypt(message, nonce: nonce)
        buffer = Bytes.new(100, MARKER_BYTE)
        cipher.decrypt(sealed, into: buffer, nonce: nonce).should be_true
        buffer.should eq(message)
      end
    end

    it "raises OutputSizeMismatch for a buffer of the wrong size" do
      each_cipher do |name, cipher, nonce|
        sealed = cipher.encrypt("message", nonce: nonce)
        expect_raises(Beryl::Crypto::OutputSizeMismatch) do
          cipher.decrypt(sealed, into: Bytes.new(8), nonce: nonce)
        end
        expect_raises(Beryl::Crypto::OutputSizeMismatch) do
          cipher.encrypt("message", into: Bytes.new(7), nonce: nonce)
        end
      end
    end
  end

  describe "#authentic?" do
    it "tells a whole message from an altered one without decrypting" do
      each_cipher do |name, cipher, nonce|
        sealed = cipher.encrypt("message", nonce: nonce, associated_data: "header")
        cipher.authentic?(sealed, nonce: nonce, associated_data: "header").should be_true
        sealed[0] ^= 1_u8
        cipher.authentic?(sealed, nonce: nonce, associated_data: "header").should be_false
      end
    end
  end

  describe "key and nonce sizes" do
    it "ChaCha20-Poly1305 takes a 32-byte key and a 12-byte nonce" do
      expect_raises(Beryl::Crypto::KeySizeMismatch, "32 bytes, not 16") do
        Beryl::Crypto::V1::ChaCha20Poly1305.new(Bytes.new(16))
      end
      cipher = Beryl::Crypto::V1::ChaCha20Poly1305.new(Bytes.new(32))
      expect_raises(Beryl::Crypto::NonceSizeMismatch, "12 bytes, not 24") do
        cipher.encrypt("message", nonce: Bytes.new(24))
      end
      expect_raises(Beryl::Crypto::NonceSizeMismatch) do
        cipher.decrypt(Bytes.new(40), nonce: Bytes.new(8))
      end
    end

    it "XChaCha20-Poly1305 takes a 32-byte key and a 24-byte nonce" do
      expect_raises(Beryl::Crypto::KeySizeMismatch, "32 bytes, not 31") do
        Beryl::Crypto::V1::XChaCha20Poly1305.new(Bytes.new(31))
      end
      cipher = Beryl::Crypto::V1::XChaCha20Poly1305.new(Bytes.new(32))
      expect_raises(Beryl::Crypto::NonceSizeMismatch, "24 bytes, not 12") do
        cipher.encrypt("message", nonce: Bytes.new(12))
      end
    end

    it "AES-GCM takes a 16, 24 or 32-byte key, a nonce of at least one byte and a standard tag size" do
      expect_raises(Beryl::Crypto::KeySizeMismatch, "16, 24 or 32 bytes, not 20") do
        Beryl::Crypto::V1::AESGCM.new(Bytes.new(20))
      end
      expect_raises(Beryl::Crypto::TagSizeNotSupported, "not 10") do
        Beryl::Crypto::V1::AESGCM.new(Bytes.new(16), tag_bytesize: 10)
      end
      cipher = Beryl::Crypto::V1::AESGCM.new(Bytes.new(16))
      expect_raises(Beryl::Crypto::NonceSizeMismatch, "at least one byte") do
        cipher.encrypt("message", nonce: Bytes.empty)
      end
      sealed = cipher.encrypt("message", nonce: Bytes.new(60, 7_u8))
      cipher.decrypt(sealed, nonce: Bytes.new(60, 7_u8)).should eq("message".to_slice)
    end

    it "keeps its own copy of the key" do
      key = Random::Secure.random_bytes(32)
      {% for cipher_class in %w[ChaCha20Poly1305 XChaCha20Poly1305 AESGCM] %}
        caller_key = key.dup
        cipher = Beryl::Crypto::V1::{{ cipher_class.id }}.new(caller_key)
        nonce = Bytes.new(cipher.nonce_bytesize, 1_u8)
        sealed = cipher.encrypt("message", nonce: nonce)
        caller_key.fill(0_u8)
        cipher.decrypt(sealed, nonce: nonce).should eq("message".to_slice)
      {% end %}
    end
  end

  describe "the AES-GCM counter" do
    it "wraps at 2^32 as SP 800-38D defines, matching a keystream computed block by block" do
      key = Bytes.new(32) { |index| index.to_u8 }
      round_keys = Slice(UInt64).new(Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_WORD_COUNT, 0_u64)
      Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.expand_key(key, round_keys)

      # Counter blocks ending in ff ff ff fe, ff ff ff ff, 00 00 00 00, ...
      counter_block = Bytes.new(16, 0x11_u8)
      counter_block[12, 4].copy_from("fffffffe".hexbytes)
      keystream = Bytes.new(160)
      Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.xor_counter_keystream(round_keys, 14, counter_block, Bytes.new(160), keystream)

      10.times do |block_number|
        block = Bytes.new(16, 0x11_u8)
        IO::ByteFormat::BigEndian.encode(0xfffffffe_u32 &+ block_number, block[12, 4])
        expected = Bytes.new(16)
        Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.encrypt_blocks(round_keys, 14, block, expected)
        keystream[block_number * 16, 16].should eq(expected)
      end
    end
  end
end
