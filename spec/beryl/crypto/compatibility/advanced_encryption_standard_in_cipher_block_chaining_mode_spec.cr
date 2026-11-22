require "../../../spec_helper"

private alias AESCBC = Beryl::Crypto::Compatibility::AESCBC
private alias CipherBlockChaining = Beryl::Crypto::Compatibility::CipherBlockChaining

describe Beryl::Crypto::Compatibility::AdvancedEncryptionStandardInCipherBlockChainingMode do
  describe "#encrypt and #decrypt" do
    it "return the message for every length from 0 to 100 bytes and every key size" do
      {16, 24, 32}.each do |key_bytesize|
        cipher = AESCBC.new(Random::Secure.random_bytes(key_bytesize))
        initialization_vector = Random::Secure.random_bytes(16)
        (0..100).each do |bytesize|
          message = Random::Secure.random_bytes(bytesize)
          ciphertext = cipher.encrypt(message, initialization_vector: initialization_vector)
          ciphertext.size.should eq((bytesize // 16 + 1) * 16)
          cipher.decrypt(ciphertext, initialization_vector: initialization_vector).should eq(message)
        end
      end
    end
  end

  describe "#decrypt" do
    it "returns nil for an empty ciphertext and for one that is not whole blocks" do
      cipher = AESCBC.new(Bytes.new(32))
      cipher.decrypt(Bytes.empty, initialization_vector: Bytes.new(16)).should be_nil
      cipher.decrypt(Bytes.new(17), initialization_vector: Bytes.new(16)).should be_nil
    end

    it "returns nil under another key" do
      initialization_vector = Bytes.new(16, 3_u8)
      refused_count = 0
      200.times do
        ciphertext = AESCBC.new(Random::Secure.random_bytes(32)).encrypt("message", initialization_vector: initialization_vector)
        plaintext = AESCBC.new(Random::Secure.random_bytes(32)).decrypt(ciphertext, initialization_vector: initialization_vector)
        refused_count += 1 if plaintext.nil?
        plaintext.should_not eq("message".to_slice)
      end
      # Random bytes pass for padding about once in 255 tries.
      refused_count.should be > 190
    end

    it "raises NonceSizeMismatch for an initialization vector that is not 16 bytes" do
      cipher = AESCBC.new(Bytes.new(16))
      expect_raises(Beryl::Crypto::NonceSizeMismatch, "16 bytes, not 12") do
        cipher.encrypt("message", initialization_vector: Bytes.new(12))
      end
      expect_raises(Beryl::Crypto::NonceSizeMismatch) do
        cipher.decrypt(Bytes.new(16), initialization_vector: Bytes.new(15))
      end
    end
  end

  describe ".new" do
    it "raises KeySizeMismatch for a key that is not 16, 24 or 32 bytes" do
      expect_raises(Beryl::Crypto::KeySizeMismatch) { AESCBC.new(Bytes.new(17)) }
    end
  end
end

describe Beryl::Crypto::Compatibility::CipherBlockChaining do
  describe ".padding_bytesize" do
    it "returns the padding size for each of the sixteen well-formed paddings" do
      (1..16).each do |padding_bytesize|
        block = Random::Secure.random_bytes(16)
        block[16 - padding_bytesize, padding_bytesize].fill(padding_bytesize.to_u8)
        # A content byte that happens to equal the padding byte is still content.
        block[16 - padding_bytesize - 1] = 0xee_u8 if padding_bytesize < 16
        CipherBlockChaining.padding_bytesize(block).should eq(padding_bytesize)
      end
    end

    it "returns 0 for a last byte of 0 and for every last byte over 16" do
      block = Bytes.new(16, 0_u8)
      CipherBlockChaining.padding_bytesize(block).should eq(0)
      (17..255).each do |last_byte|
        CipherBlockChaining.padding_bytesize(Bytes.new(16, last_byte.to_u8)).should eq(0)
      end
    end

    it "returns 0 when any byte inside the padding differs" do
      (2..16).each do |padding_bytesize|
        (1...padding_bytesize).each do |distance_from_end|
          block = Bytes.new(16, padding_bytesize.to_u8)
          block[15 - distance_from_end] ^= 0x01_u8
          CipherBlockChaining.padding_bytesize(block).should eq(0)
        end
      end
    end
  end
end
