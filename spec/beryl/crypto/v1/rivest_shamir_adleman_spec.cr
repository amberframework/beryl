require "../../../spec_helper"

private alias RSA = Beryl::Crypto::V1::RSA
private alias SHA1 = Beryl::Crypto::Compatibility::SHA1
private alias SHA256 = Beryl::Crypto::V1::SHA256

# A 2,048-bit key with all eight components, from a Wycheproof file, read
# when an example first needs it (a run filtered to other specs, such as a
# differential, never reads the file).
module RsaUnitSpecKey
  class_getter components : RsaKeyComponents::Components do
    test_file = Wycheproof::TestFile(Wycheproof::RsaOaepTestGroup).from_json(
      VectorFile.read("wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json")
    )
    RsaKeyComponents.from_wycheproof(test_file.list_of_test_groups.first.private_key)
  end
  class_getter private_key : Beryl::Crypto::V1::RSA::PrivateKey { components.private_key }
end

private def components : RsaKeyComponents::Components
  RsaUnitSpecKey.components
end

private def private_key : Beryl::Crypto::V1::RSA::PrivateKey
  RsaUnitSpecKey.private_key
end

private def public_key : Beryl::Crypto::V1::RSA::PublicKey
  RsaUnitSpecKey.private_key.public_key
end

private def private_key_with(components : RsaKeyComponents::Components, **changes) : RSA::PrivateKey
  components.copy_with(**changes).private_key
end

# Returns *bytes* with one bit flipped at *index*.
private def flipped(bytes : Bytes, index : Int32) : Bytes
  copy = bytes.dup
  copy[index] ^= 0x01_u8
  copy
end

# Returns the big-endian number one more than *bytes*.
private def plus_two(bytes : Bytes) : Bytes
  RsaKeyComponents.bytes_of(BigInt.new(bytes.hexstring, 16) + 2)
end

describe Beryl::Crypto::V1::RivestShamirAdleman do
  describe RSA::PublicKey do
    it "takes the public exponent as bytes or as an integer" do
      RSA::PublicKey.new(components.modulus, Bytes[0x01, 0x00, 0x01]).public_exponent.should eq(65_537_u64)
      RSA::PublicKey.new(components.modulus, 65_537).public_exponent.should eq(65_537_u64)
      RSA::PublicKey.new(components.modulus, 65_537).modulus_bit_count.should eq(2_048)
    end

    it "refuses moduli under 2,048 bits, over 8,192 bits, and even moduli" do
      expect_raises(Beryl::Crypto::KeySizeNotSupported) { RSA::PublicKey.new(components.modulus[-255..], 65_537) }
      expect_raises(Beryl::Crypto::KeySizeNotSupported) { RSA::PublicKey.new(Bytes.new(1_025, 0xff_u8), 65_537) }
      even_modulus = components.modulus.dup
      even_modulus[-1] &= 0xfe_u8
      expect_raises(Beryl::Crypto::KeySizeNotSupported) { RSA::PublicKey.new(even_modulus, 65_537) }
    end

    it "refuses public exponents that are even, under 3, or over 2^32 - 1" do
      {0, 1, 2, 65_536, 0x1_0000_0001_i64}.each do |public_exponent|
        expect_raises(Beryl::Crypto::PublicExponentNotSupported) { RSA::PublicKey.new(components.modulus, public_exponent) }
      end
      expect_raises(Beryl::Crypto::PublicExponentNotSupported) { RSA::PublicKey.new(components.modulus, Bytes.new(9, 0x01_u8)) }
    end
  end

  describe RSA::PrivateKey do
    it "refuses a modulus over 4,096 bits" do
      expect_raises(Beryl::Crypto::KeySizeNotSupported) do
        private_key_with(components, modulus: Bytes.new(513, 0xff_u8))
      end
    end

    it "refuses components that do not belong together" do
      expect_raises(Beryl::Crypto::MalformedPrivateKey) { private_key_with(components, second_prime: plus_two(components.second_prime)) }
      expect_raises(Beryl::Crypto::MalformedPrivateKey) { private_key_with(components, coefficient: plus_two(components.coefficient)) }
      expect_raises(Beryl::Crypto::MalformedPrivateKey) { private_key_with(components, first_prime_exponent: components.first_prime) }
      expect_raises(Beryl::Crypto::MalformedPrivateKey) { private_key_with(components, private_exponent: components.modulus) }
      expect_raises(Beryl::Crypto::MalformedPrivateKey) { private_key_with(components, first_prime: components.second_prime, second_prime: components.first_prime) }
    end

    it "refuses exponents that do not invert the public exponent, found by its test operation and the check after it" do
      expect_raises(Beryl::Crypto::MalformedPrivateKey, "do not invert") do
        private_key_with(components, first_prime_exponent: plus_two(components.first_prime_exponent))
      end
      expect_raises(Beryl::Crypto::MalformedPrivateKey, "do not invert") do
        private_key_with(components, second_prime_exponent: plus_two(components.second_prime_exponent))
      end
    end

    it "takes the same key from components with leading zero bytes" do
      padded = components.copy_with(first_prime: Bytes[0, 0] + components.first_prime, coefficient: Bytes[0] + components.coefficient)
      padded.private_key.sign_with_pkcs1("message", hash_function: SHA256).should eq(private_key.sign_with_pkcs1("message", hash_function: SHA256))
    end
  end

  describe "PKCS #1 v1.5 signatures" do
    it "signs the same bytes every time, and the public key verifies them for every hash" do
      {% for hash in %w[V1::SHA224 V1::SHA256 V1::SHA384 V1::SHA512 V1::SHA512_256] %}
        signature = private_key.sign_with_pkcs1("message", hash_function: Beryl::Crypto::{{ hash.id }})
        signature.size.should eq(256)
        private_key.sign_with_pkcs1("message", hash_function: Beryl::Crypto::{{ hash.id }}).should eq(signature)
        public_key.verify_pkcs1_signature("message", signature, hash_function: Beryl::Crypto::{{ hash.id }}).should be_true
        public_key.verify_pkcs1_signature("massage", signature, hash_function: Beryl::Crypto::{{ hash.id }}).should be_false
      {% end %}
    end

    it "returns false, without raising, for a signature of the wrong size, out of range or altered" do
      signature = private_key.sign_with_pkcs1("message", hash_function: SHA256)
      public_key.verify_pkcs1_signature("message", signature[1..], hash_function: SHA256).should be_false
      public_key.verify_pkcs1_signature("message", Bytes.empty, hash_function: SHA256).should be_false
      public_key.verify_pkcs1_signature("message", Bytes.new(256, 0xff_u8), hash_function: SHA256).should be_false
      public_key.verify_pkcs1_signature("message", Bytes.new(256), hash_function: SHA256).should be_false
      public_key.verify_pkcs1_signature("message", flipped(signature, 100), hash_function: SHA256).should be_false
      public_key.verify_pkcs1_signature("message", signature, hash_function: SHA1).should be_false
    end
  end

  describe "PSS signatures" do
    it "signs with a fresh salt each time, and the public key verifies with the salt size" do
      {0, 20, 32, 64}.each do |salt_bytesize|
        signature = private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: salt_bytesize)
        public_key.verify_pss_signature("message", signature, hash_function: SHA256, salt_bytesize: salt_bytesize).should be_true
        public_key.verify_pss_signature("message", signature, hash_function: SHA256, salt_bytesize: salt_bytesize + 1).should be_false
        public_key.verify_pss_signature("massage", signature, hash_function: SHA256, salt_bytesize: salt_bytesize).should be_false
        next if salt_bytesize == 0
        private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: salt_bytesize).should_not eq(signature)
      end
    end

    it "raises SaltTooLongForModulus when the salt does not fit" do
      expect_raises(Beryl::Crypto::SaltTooLongForModulus) { private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: 223) }
      expect_raises(Beryl::Crypto::SaltTooLongForModulus) { private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: -1) }
      private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: 222).size.should eq(256)
    end

    it "returns false, without raising, for a malformed signature or a negative salt size" do
      signature = private_key.sign_with_pss("message", hash_function: SHA256, salt_bytesize: 32)
      public_key.verify_pss_signature("message", signature[1..], hash_function: SHA256, salt_bytesize: 32).should be_false
      public_key.verify_pss_signature("message", Bytes.new(256, 0xff_u8), hash_function: SHA256, salt_bytesize: 32).should be_false
      public_key.verify_pss_signature("message", flipped(signature, 7), hash_function: SHA256, salt_bytesize: 32).should be_false
      public_key.verify_pss_signature("message", signature, hash_function: SHA256, salt_bytesize: -1).should be_false
      public_key.verify_pss_signature("message", signature, hash_function: SHA256, salt_bytesize: 1_000).should be_false
    end
  end

  describe "OAEP encryption" do
    it "decrypts what the public key encrypted, with and without a label, under SHA-1 and SHA-256" do
      {% for hash in %w[Compatibility::SHA1 V1::SHA256 V1::SHA512] %}
        ciphertext = public_key.encrypt_with_oaep("password", hash_function: Beryl::Crypto::{{ hash.id }})
        ciphertext.size.should eq(256)
        private_key.decrypt_with_oaep(ciphertext, hash_function: Beryl::Crypto::{{ hash.id }}).should eq("password".to_slice)
        labeled = public_key.encrypt_with_oaep(Bytes.empty, hash_function: Beryl::Crypto::{{ hash.id }}, label: "label")
        private_key.decrypt_with_oaep(labeled, hash_function: Beryl::Crypto::{{ hash.id }}, label: "label").should eq(Bytes.empty)
        private_key.decrypt_with_oaep(labeled, hash_function: Beryl::Crypto::{{ hash.id }}, label: "other").should be_nil
      {% end %}
    end

    it "encrypts the longest message that fits and refuses one byte more" do
      longest = Bytes.new(256 - 2 * 32 - 2, 0x61_u8)
      ciphertext = public_key.encrypt_with_oaep(longest, hash_function: SHA256)
      private_key.decrypt_with_oaep(ciphertext, hash_function: SHA256).should eq(longest)
      expect_raises(Beryl::Crypto::MessageTooLongForModulus) do
        public_key.encrypt_with_oaep(Bytes.new(longest.size + 1), hash_function: SHA256)
      end
    end

    it "returns nil for every malformed ciphertext alike" do
      ciphertext = public_key.encrypt_with_oaep("password", hash_function: SHA256)
      private_key.decrypt_with_oaep(ciphertext[1..], hash_function: SHA256).should be_nil
      private_key.decrypt_with_oaep(Bytes.new(256, 0xff_u8), hash_function: SHA256).should be_nil
      private_key.decrypt_with_oaep(flipped(ciphertext, 255), hash_function: SHA256).should be_nil
      private_key.decrypt_with_oaep(ciphertext, hash_function: SHA1).should be_nil
    end

    it "decodes a well-formed encoding and gives 0 for one broken at any place" do
      label_digest = SHA256.digest(Bytes.empty)
      seed = Bytes.new(32, 0x5a_u8)
      encoded = RSA::MessageEncoding.encode_oaep(SHA256, "hi".to_slice, label_digest, seed, 256)
      RSA::MessageEncoding.decode_oaep(SHA256, encoded.dup, label_digest, 1_u64).should eq(3_u32)
      RSA::MessageEncoding.decode_oaep(SHA256, encoded.dup, label_digest, 0_u64).should eq(0_u32)
      {0, 1, 40, 100, 200, 255}.each do |index|
        RSA::MessageEncoding.decode_oaep(SHA256, flipped(encoded, index), label_digest, 1_u64).should eq(0_u32)
      end
    end
  end

  it "is reachable by its short name" do
    Beryl::Crypto::V1::RSA.should eq(Beryl::Crypto::V1::RivestShamirAdleman)
  end
end
