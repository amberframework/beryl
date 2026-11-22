require "../../../spec_helper"

private alias HKDFSHA256 = Beryl::Crypto::V1::HKDF(Beryl::Crypto::V1::SHA256)
private alias HKDFSHA384 = Beryl::Crypto::V1::HKDF(Beryl::Crypto::V1::SHA384)
private alias HKDFSHA512 = Beryl::Crypto::V1::HKDF(Beryl::Crypto::V1::SHA512)

# RFC 5869 test case 1.
private INPUT_KEY_MATERIAL = ("0b" * 22).hexbytes
private SALT               = "000102030405060708090a0b0c".hexbytes
private INFO               = "f0f1f2f3f4f5f6f7f8f9".hexbytes
private PSEUDORANDOM_KEY   = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".hexbytes
private DERIVED_KEY        = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".hexbytes

describe Beryl::Crypto::V1::HashBasedKeyDerivationFunction do
  it "is aliased as HKDF" do
    Beryl::Crypto::V1::HashBasedKeyDerivationFunction(Beryl::Crypto::V1::SecureHashWith256BitDigest)
      .derive_key(INPUT_KEY_MATERIAL, salt: SALT, info: INFO, bytesize: 42).should eq(DERIVED_KEY)
    HKDFSHA256.derive_key(INPUT_KEY_MATERIAL, salt: SALT, info: INFO, bytesize: 42).should eq(DERIVED_KEY)
  end

  describe ".extract" do
    it "returns a pseudorandom key one hash output long" do
      HKDFSHA256.extract(INPUT_KEY_MATERIAL, salt: SALT).should eq(PSEUDORANDOM_KEY)
      HKDFSHA384.extract(INPUT_KEY_MATERIAL, salt: SALT).size.should eq(48)
      HKDFSHA512.extract(INPUT_KEY_MATERIAL, salt: SALT).size.should eq(64)
    end

    it "treats a missing salt as one hash output of zeros (RFC 5869 section 2.2)" do
      HKDFSHA256.extract(INPUT_KEY_MATERIAL).should eq(HKDFSHA256.extract(INPUT_KEY_MATERIAL, salt: Bytes.new(32)))
      HKDFSHA512.extract(INPUT_KEY_MATERIAL).should eq(HKDFSHA512.extract(INPUT_KEY_MATERIAL, salt: Bytes.new(64)))
    end
  end

  describe ".expand" do
    it "returns the requested number of bytes" do
      HKDFSHA256.expand(PSEUDORANDOM_KEY, info: INFO, bytesize: 42).should eq(DERIVED_KEY)
    end

    it "returns a prefix of a longer output for a shorter request" do
      longest_key = HKDFSHA256.expand(PSEUDORANDOM_KEY, info: INFO, bytesize: 255 * 32)
      longest_key.size.should eq(8160)
      {0, 1, 31, 32, 33, 64, 100}.each do |bytesize|
        HKDFSHA256.expand(PSEUDORANDOM_KEY, info: INFO, bytesize: bytesize).should eq(longest_key[0, bytesize])
      end
    end

    it "gives unrelated keys for different info" do
      HKDFSHA256.expand(PSEUDORANDOM_KEY, info: "cookies", bytesize: 32)
        .should_not eq(HKDFSHA256.expand(PSEUDORANDOM_KEY, info: "sessions", bytesize: 32))
    end

    it "refuses more than 255 hash outputs with DerivedKeyTooLong" do
      HKDFSHA256.expand(PSEUDORANDOM_KEY, bytesize: 255 * 32).size.should eq(8160)
      expect_raises(Beryl::Crypto::DerivedKeyTooLong, "at most 8160 bytes, not 8161") do
        HKDFSHA256.expand(PSEUDORANDOM_KEY, bytesize: 255 * 32 + 1)
      end
      expect_raises(Beryl::Crypto::DerivedKeyTooLong, "at most 12240 bytes") do
        HKDFSHA384.expand(PSEUDORANDOM_KEY, bytesize: 255 * 48 + 1)
      end
      expect_raises(Beryl::Crypto::DerivedKeyTooLong, "at most 16320 bytes") do
        HKDFSHA512.expand(PSEUDORANDOM_KEY, bytesize: 255 * 64 + 1)
      end
    end

    it "refuses a negative size" do
      expect_raises(Beryl::Crypto::DerivedKeySizeIsNegative) do
        HKDFSHA256.expand(PSEUDORANDOM_KEY, bytesize: -1)
      end
    end
  end

  describe ".derive_key" do
    it "is extract followed by expand" do
      HKDFSHA256.derive_key(INPUT_KEY_MATERIAL, salt: SALT, info: INFO, bytesize: 42).should eq(DERIVED_KEY)
    end

    it "raises errors that descend from Beryl::Error" do
      expect_raises(Beryl::Error) do
        HKDFSHA256.derive_key(INPUT_KEY_MATERIAL, bytesize: 8161)
      end
    end
  end
end
