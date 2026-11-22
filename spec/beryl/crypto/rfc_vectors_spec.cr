require "../../spec_helper"

# Test cases printed in the RFCs. RFC 4231 and RFC 5869 are read field by
# field from the pinned RFC text. RFC 1321, RFC 2202, RFC 6070 and RFC 7914
# print their inputs as prose ("0xdd repeated 50 times"), so those inputs are
# written out here, and each expected output is first shown to appear in the
# pinned RFC text before it is used.

private def text_without_whitespace(text : String) : String
  text.gsub(/\s+/, "")
end

private def repeated_byte(byte : UInt8, count : Int32) : Bytes
  Bytes.new(count, byte)
end

private def field_bytes(test_case : RfcLabeledFields::TestCase, label : String) : Bytes
  field_text = test_case[label]
  # "(0 octets)" and "not provided" both stand for the empty string.
  return Bytes.empty unless field_text.matches?(/\A(?:[0-9a-f]{2})+\z/)

  field_text.hexbytes
end

# RFC 2202: {key, message, HMAC-MD5 digest, HMAC-SHA-1 digest}. Test cases 1,
# 3 and 5 use a key as long as the digest, so each hash has its own key.
private LIST_OF_RFC_2202_TEST_CASES = [
  {repeated_byte(0x0b, 16), repeated_byte(0x0b, 20), "Hi There".to_slice,
   "9294727a3638bb1c13f48ef8158bfc9d", "b617318655057264e28bc0b6fb378c8ef146be00"},
  {"Jefe".to_slice, "Jefe".to_slice, "what do ya want for nothing?".to_slice,
   "750c783e6ab0b503eaa86e310a5db738", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},
  {repeated_byte(0xaa, 16), repeated_byte(0xaa, 20), repeated_byte(0xdd, 50),
   "56be34521d144c88dbb8c733f0e8b3f6", "125d7342b9ac11cd91a39af48aa17b4f63f175d3"},
  {"0102030405060708090a0b0c0d0e0f10111213141516171819".hexbytes,
   "0102030405060708090a0b0c0d0e0f10111213141516171819".hexbytes, repeated_byte(0xcd, 50),
   "697eaf0aca3a3aea3a75164746ffaa79", "4c9007f4026250c6bc8414f9bf50c86c2d7235da"},
  {repeated_byte(0x0c, 16), repeated_byte(0x0c, 20), "Test With Truncation".to_slice,
   "56461ef2342edc00f9bab995690efd4c", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"},
  {repeated_byte(0xaa, 80), repeated_byte(0xaa, 80),
   "Test Using Larger Than Block-Size Key - Hash Key First".to_slice,
   "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", "aa4ae5e15272d00e95705637ce8a3b55ed402112"},
  {repeated_byte(0xaa, 80), repeated_byte(0xaa, 80),
   "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_slice,
   "6f630fad67cda0ee1fb1f562db3aa53e", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"},
]

# RFC 1321 appendix A.5: {message, digest}.
private LIST_OF_RFC_1321_TEST_CASES = [
  {"", "d41d8cd98f00b204e9800998ecf8427e"},
  {"a", "0cc175b9c0f1b6a831c399e269772661"},
  {"abc", "900150983cd24fb0d6963f7d28e17f72"},
  {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
  {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
  {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
  {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
   "57edf4a22be3c955ac49da2e2107b67a"},
]

# RFC 6070 section 2: {password, salt, iteration count, derived key}.
private LIST_OF_RFC_6070_TEST_CASES = [
  {"password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
  {"password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
  {"password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1"},
  {"password", "salt", 16_777_216, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"},
  {"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
   "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
  {"pass\0word", "sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3"},
]

# RFC 7914 section 11: {password, salt, iteration count, derived key}.
private LIST_OF_RFC_7914_TEST_CASES = [
  {"passwd", "salt", 1,
   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" \
   "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
  {"Password", "NaCl", 80_000,
   "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" \
   "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
]

describe "RFC test vectors" do
  describe "RFC 1321 (MD5)" do
    rfc_text = text_without_whitespace(VectorFile.read("rfc/rfc1321.txt"))

    it "passes the seven cases of appendix A.5" do
      LIST_OF_RFC_1321_TEST_CASES.each do |message, expected_digest|
        rfc_text.should contain(expected_digest)
        Beryl::Crypto::Compatibility::MD5.hexdigest(message).should eq(expected_digest)
        VectorCaseCount.record("MD5", "RFC")
      end
    end
  end

  describe "RFC 2202 (HMAC-MD5 and HMAC-SHA-1)" do
    rfc_text = text_without_whitespace(VectorFile.read("rfc/rfc2202.txt"))

    it "passes the seven HMAC-MD5 cases" do
      LIST_OF_RFC_2202_TEST_CASES.each do |md5_key, _sha1_key, message, expected_md5_tag, _expected_sha1_tag|
        rfc_text.should contain("0x#{expected_md5_tag}")
        tag = Beryl::Crypto::V1::HMAC(Beryl::Crypto::Compatibility::MD5).authenticate(message, key: md5_key)
        tag.hexstring.should eq(expected_md5_tag)
        VectorCaseCount.record("HMAC-MD5", "RFC")
      end
    end

    it "passes the seven HMAC-SHA-1 cases" do
      LIST_OF_RFC_2202_TEST_CASES.each do |_md5_key, sha1_key, message, _expected_md5_tag, expected_sha1_tag|
        rfc_text.should contain("0x#{expected_sha1_tag}")
        tag = Beryl::Crypto::V1::HMAC(Beryl::Crypto::Compatibility::SHA1).authenticate(message, key: sha1_key)
        tag.hexstring.should eq(expected_sha1_tag)
        VectorCaseCount.record("HMAC-SHA-1", "RFC")
      end
    end
  end

  describe "RFC 4231 (HMAC-SHA-224, 256, 384 and 512)" do
    list_of_test_cases = RfcLabeledFields.parse(
      VectorFile.read("rfc/rfc4231.txt"),
      case_heading: /\A4\.\d\.\s+Test Case \d/,
      list_of_labels: ["Key", "Data", "HMAC-SHA-224", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512"],
    )

    it "reads seven test cases" do
      list_of_test_cases.size.should eq(7)
    end

    {% for hash in [{"224", "Beryl::Crypto::V1::SHA224"}, {"256", "Beryl::Crypto::V1::SHA256"},
                    {"384", "Beryl::Crypto::V1::SHA384"}, {"512", "Beryl::Crypto::V1::SHA512"}] %}
      it "passes the seven HMAC-SHA-{{ hash[0].id }} cases" do
        list_of_test_cases.each do |test_case|
          key = field_bytes(test_case, "Key")
          message = field_bytes(test_case, "Data")
          expected_tag = field_bytes(test_case, "HMAC-SHA-{{ hash[0].id }}")
          expected_tag.should_not be_empty

          # Test case 5 prints the tag cut to 128 bits.
          authentication = Beryl::Crypto::V1::HMAC({{ hash[1].id }}).new(key)
          authentication.update(message).final[0, expected_tag.size].should eq(expected_tag)
          VectorCaseCount.record("HMAC-SHA-{{ hash[0].id }}", "RFC")
        end
      end
    {% end %}

    it "has the key and data sizes the RFC states" do
      list_of_test_cases.map { |test_case| field_bytes(test_case, "Key").size }.should eq([20, 4, 20, 25, 20, 131, 131])
      list_of_test_cases.map { |test_case| field_bytes(test_case, "Data").size }.should eq([8, 28, 50, 50, 20, 54, 152])
    end
  end

  describe "RFC 5869 (HKDF)" do
    list_of_test_cases = RfcLabeledFields.parse(
      VectorFile.read("rfc/rfc5869.txt"),
      case_heading: /\AA\.\d\.\s+Test Case \d/,
      list_of_labels: ["Hash", "IKM", "salt", "info", "L", "PRK", "OKM"],
    )

    it "reads seven test cases, three on SHA-256 and four on SHA-1" do
      list_of_test_cases.map { |test_case| test_case["Hash"] }.should eq(
        ["SHA-256", "SHA-256", "SHA-256", "SHA-1", "SHA-1", "SHA-1", "SHA-1"]
      )
    end

    {% for hash in [{"SHA-256", "Beryl::Crypto::V1::SHA256"}, {"SHA-1", "Beryl::Crypto::Compatibility::SHA1"}] %}
      it "passes the {{ hash[0].id }} cases: extract, expand and the combined call" do
        hkdf = Beryl::Crypto::V1::HKDF({{ hash[1].id }})
        list_of_test_cases.select { |test_case| test_case["Hash"] == {{ hash[0] }} }.each do |test_case|
          input_key_material = field_bytes(test_case, "IKM")
          salt = field_bytes(test_case, "salt")
          info = field_bytes(test_case, "info")
          derived_key_bytesize = test_case["L"].to_i
          expected_pseudorandom_key = field_bytes(test_case, "PRK")
          expected_derived_key = field_bytes(test_case, "OKM")
          expected_derived_key.size.should eq(derived_key_bytesize)

          pseudorandom_key = hkdf.extract(input_key_material, salt: salt)
          pseudorandom_key.should eq(expected_pseudorandom_key)
          hkdf.expand(pseudorandom_key, info: info, bytesize: derived_key_bytesize).should eq(expected_derived_key)
          hkdf.derive_key(input_key_material, salt: salt, info: info, bytesize: derived_key_bytesize)
            .should eq(expected_derived_key)
          VectorCaseCount.record("HKDF-{{ hash[0].id }}", "RFC")
        end
      end
    {% end %}
  end

  describe "RFC 6070 (PBKDF2-HMAC-SHA-1)" do
    rfc_text = text_without_whitespace(VectorFile.read("rfc/rfc6070.txt"))

    it "passes the five cases under one million iterations" do
      list_of_quick_test_cases = LIST_OF_RFC_6070_TEST_CASES.reject { |test_case| test_case[2] >= SLOW_PBKDF2_ITERATION_COUNT }
      list_of_quick_test_cases.size.should eq(5)
      list_of_quick_test_cases.each do |password, salt, iteration_count, expected_derived_key|
        rfc_text.should contain(expected_derived_key)
        derived_key = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::Compatibility::SHA1).derive_key(
          password, salt: salt, iteration_count: iteration_count, bytesize: expected_derived_key.size // 2
        )
        derived_key.hexstring.should eq(expected_derived_key)
        VectorCaseCount.record("PBKDF2-HMAC-SHA-1", "RFC")
      end
    end

    if RequestedSpecTag.includes?("slow")
      it "passes the case of 16,777,216 iterations", tags: "slow" do
        list_of_slow_test_cases = LIST_OF_RFC_6070_TEST_CASES.select { |test_case| test_case[2] >= SLOW_PBKDF2_ITERATION_COUNT }
        list_of_slow_test_cases.size.should eq(1)
        list_of_slow_test_cases.each do |password, salt, iteration_count, expected_derived_key|
          rfc_text.should contain(expected_derived_key)
          derived_key = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::Compatibility::SHA1).derive_key(
            password, salt: salt, iteration_count: iteration_count, bytesize: expected_derived_key.size // 2
          )
          derived_key.hexstring.should eq(expected_derived_key)
          VectorCaseCount.record("PBKDF2-HMAC-SHA-1", "RFC")
        end
      end
    end
  end

  describe "RFC 7914 section 11 (PBKDF2-HMAC-SHA-256)" do
    rfc_text = text_without_whitespace(VectorFile.read("rfc/rfc7914.txt"))

    it "passes both cases" do
      pbkdf2 = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256)
      LIST_OF_RFC_7914_TEST_CASES.each do |password, salt, iteration_count, expected_derived_key|
        rfc_text.should contain(expected_derived_key)
        derived_key = pbkdf2.derive_key(password, salt: salt, iteration_count: iteration_count, bytesize: 64)
        derived_key.hexstring.should eq(expected_derived_key)
        VectorCaseCount.record("PBKDF2-HMAC-SHA-256", "RFC")
      end
    end
  end
end
