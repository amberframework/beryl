require "../../../spec_helper"

private alias PBKDF2SHA1 = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::Compatibility::SHA1)
private alias PBKDF2SHA256 = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256)
private alias PBKDF2SHA512 = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA512)

describe Beryl::Crypto::Compatibility::PasswordBasedKeyDerivationFunction2 do
  it "is aliased as PBKDF2" do
    Beryl::Crypto::Compatibility::PasswordBasedKeyDerivationFunction2(Beryl::Crypto::V1::SecureHashWith256BitDigest)
      .derive_key("password", salt: "salt", iteration_count: 2, bytesize: 32)
      .should eq(PBKDF2SHA256.derive_key("password", salt: "salt", iteration_count: 2, bytesize: 32))
  end

  describe ".derive_key" do
    it "derives the RFC 6070 key for two iterations" do
      PBKDF2SHA1.derive_key("password", salt: "salt", iteration_count: 2, bytesize: 20).hexstring
        .should eq("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
    end

    it "derives the PostgreSQL SCRAM-SHA-256 salted password of RFC 7677 section 3" do
      salt = Base64.decode("W22ZaJ0SNY7soEsUEjb6gQ==")
      salted_password = PBKDF2SHA256.derive_key("pencil", salt: salt, iteration_count: 4096, bytesize: 32)

      client_key = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256).authenticate("Client Key", key: salted_password)
      stored_key = Beryl::Crypto::V1::SHA256.digest(client_key)
      auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO," \
                     "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," \
                     "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
      client_signature = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256).authenticate(auth_message, key: stored_key)
      client_proof = Bytes.new(32) { |index| client_key[index] ^ client_signature[index] }
      Base64.strict_encode(client_proof).should eq("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
    end

    it "returns a prefix of a longer key for a shorter request, across block boundaries" do
      longest_key = PBKDF2SHA512.derive_key("password", salt: "salt", iteration_count: 3, bytesize: 200)
      {0, 1, 63, 64, 65, 128, 129}.each do |bytesize|
        PBKDF2SHA512.derive_key("password", salt: "salt", iteration_count: 3, bytesize: bytesize)
          .should eq(longest_key[0, bytesize])
      end
    end

    it "accepts bytes as well as strings" do
      PBKDF2SHA256.derive_key("password".to_slice, salt: "salt".to_slice, iteration_count: 5, bytesize: 32)
        .should eq(PBKDF2SHA256.derive_key("password", salt: "salt", iteration_count: 5, bytesize: 32))
    end

    it "refuses fewer than one iteration with IterationCountTooSmall" do
      expect_raises(Beryl::Crypto::IterationCountTooSmall, "at least one iteration, not 0") do
        PBKDF2SHA256.derive_key("password", salt: "salt", iteration_count: 0, bytesize: 32)
      end
    end

    it "refuses a negative size" do
      expect_raises(Beryl::Crypto::DerivedKeySizeIsNegative) do
        PBKDF2SHA256.derive_key("password", salt: "salt", iteration_count: 1, bytesize: -1)
      end
    end
  end
end
