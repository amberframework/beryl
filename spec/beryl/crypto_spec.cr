require "../spec_helper"

describe Beryl::Crypto do
  describe ".digest" do
    it "is SHA-256" do
      Beryl::Crypto.digest("abc").hexstring
        .should eq("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
      Beryl::Crypto.digest("abc".to_slice).should eq(Beryl::Crypto::V1::SHA256.digest("abc"))
    end
  end

  describe ".authenticate" do
    it "is HMAC-SHA256" do
      Beryl::Crypto.authenticate("what do ya want for nothing?", key: "Jefe").hexstring
        .should eq("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    end
  end

  describe ".verify_authentication" do
    it "accepts the tag .authenticate made and refuses a changed message, tag or key" do
      tag = Beryl::Crypto.authenticate("signed cookie", key: "secret")
      Beryl::Crypto.verify_authentication("signed cookie", tag, key: "secret").should be_true
      Beryl::Crypto.verify_authentication("signed cookie!", tag, key: "secret").should be_false
      Beryl::Crypto.verify_authentication("signed cookie", tag, key: "Secret").should be_false
      Beryl::Crypto.verify_authentication("signed cookie", tag[0, 31], key: "secret").should be_false
    end
  end

  describe ".derive_key" do
    it "is HKDF-SHA256 with a 32-byte key by default" do
      input_key_material = ("0b" * 22).hexbytes
      Beryl::Crypto.derive_key(input_key_material).should eq(
        Beryl::Crypto::V1::HKDF(Beryl::Crypto::V1::SHA256).derive_key(input_key_material, bytesize: 32)
      )
      Beryl::Crypto.derive_key(
        input_key_material, salt: "000102030405060708090a0b0c".hexbytes, info: "f0f1f2f3f4f5f6f7f8f9".hexbytes, bytesize: 42
      ).hexstring.should eq("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    end
  end

  describe "errors" do
    it "descend from Beryl::Error" do
      Beryl::Crypto::Error.new.should be_a(Beryl::Error)
      Beryl::Crypto::DerivedKeyTooLong.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::DerivedKeySizeIsNegative.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::IterationCountTooSmall.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::MessageTooLong.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::OutputSizeMismatch.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::TruncatedTagTooShort.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::KeySizeMismatch.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::NonceSizeMismatch.new.should be_a(Beryl::Crypto::Error)
      Beryl::Crypto::TagSizeNotSupported.new.should be_a(Beryl::Crypto::Error)
    end
  end

  describe ".encrypt and .decrypt" do
    key = Bytes.new(32) { |index| (index * 7).to_u8 }

    it "return the message, as XChaCha20-Poly1305 behind a fresh 24-byte nonce" do
      sealed = Beryl::Crypto.encrypt("a private note", key: key, associated_data: "note 42")
      sealed.size.should eq(24 + 14 + 16)
      Beryl::Crypto.decrypt(sealed, key: key, associated_data: "note 42").should eq("a private note".to_slice)

      cipher = Beryl::Crypto::V1::XChaCha20Poly1305.new(key)
      cipher.decrypt(sealed[24, sealed.size - 24], nonce: sealed[0, 24], associated_data: "note 42").should eq("a private note".to_slice)
    end

    it "draw a new nonce for every message" do
      first = Beryl::Crypto.encrypt("same message", key: key)
      second = Beryl::Crypto.encrypt("same message", key: key)
      first[0, 24].should_not eq(second[0, 24])
      first.should_not eq(second)
    end

    it "return nil for an altered message, another key, other associated data and a message too short to hold a nonce and a tag" do
      sealed = Beryl::Crypto.encrypt("a private note", key: key, associated_data: "note 42")
      sealed.size.times do |position|
        altered = sealed.dup
        altered[position] ^= 0x01_u8
        Beryl::Crypto.decrypt(altered, key: key, associated_data: "note 42").should be_nil
      end
      Beryl::Crypto.decrypt(sealed, key: Bytes.new(32), associated_data: "note 42").should be_nil
      Beryl::Crypto.decrypt(sealed, key: key, associated_data: "note 43").should be_nil
      Beryl::Crypto.decrypt(sealed[0, 39], key: key).should be_nil
      Beryl::Crypto.decrypt(Bytes.empty, key: key).should be_nil
    end

    it "encrypt an empty message to a nonce and a tag" do
      sealed = Beryl::Crypto.encrypt("", key: key)
      sealed.size.should eq(40)
      Beryl::Crypto.decrypt(sealed, key: key).should eq(Bytes.empty)
    end

    it "raise KeySizeMismatch for a key that is not 32 bytes" do
      expect_raises(Beryl::Crypto::KeySizeMismatch) { Beryl::Crypto.encrypt("message", key: Bytes.new(16)) }
    end
  end

  it "logs under the beryl source" do
    Beryl::Log.source.should eq("beryl")
  end
end
