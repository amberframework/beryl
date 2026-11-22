require "../../spec_helper"

# Wycheproof (C2SP/wycheproof, `testvectors_v1`) for the ciphers. A case
# marked `valid` must encrypt to the published ciphertext and tag and
# decrypt back; a case marked `invalid` must be refused, either with `nil`
# (a forged or altered message) or with a named error (a nonce or key size
# the cipher does not take).

# Returns whether Beryl accepts the case: it decrypts to the published
# message and, encrypting, reproduces the published ciphertext and tag.
private def accepts_case?(test : Wycheproof::AeadTest, & : Bytes -> Beryl::Crypto::V1::AuthenticatedEncryption) : Bool
  cipher = yield test.key.hexbytes
  nonce = test.nonce.hexbytes
  associated_data = test.associated_data.hexbytes
  sealed = (test.ciphertext + test.tag).hexbytes

  plaintext = cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data)
  return false unless plaintext
  return false unless plaintext == test.message.hexbytes

  cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data) == sealed
rescue Beryl::Crypto::Error
  false
end

describe "Wycheproof cipher vectors" do
  {% for file in [{"chacha20_poly1305", "ChaCha20-Poly1305", "Beryl::Crypto::V1::ChaCha20Poly1305.new(key)"},
                  {"xchacha20_poly1305", "XChaCha20-Poly1305", "Beryl::Crypto::V1::XChaCha20Poly1305.new(key)"},
                  {"aes_gcm", "AES-GCM", "Beryl::Crypto::V1::AESGCM.new(key, tag_bytesize: tag_bytesize)"}] %}
    it "{{ file[1].id }} decides every case of {{ file[0].id }}_test.json as marked" do
      test_file = Wycheproof::TestFile(Wycheproof::AeadTestGroup).from_json(
        VectorFile.read("wycheproof/{{ file[0].id }}_test.json")
      )
      cases_run = 0

      test_file.list_of_test_groups.each do |test_group|
        tag_bytesize = test_group.tag_bit_size // 8
        test_group.list_of_tests.each do |test|
          is_accepted = accepts_case?(test) { |key| {{ file[2].id }} }

          if test.result == "acceptable"
            VectorCaseCount.record_acceptable_decision(
              "{{ file[0].id }}_test.json tcId #{test.test_case_id} (#{test.comment}): #{is_accepted ? "accepted" : "rejected"}"
            )
          elsif is_accepted != (test.result == "valid")
            fail "{{ file[0].id }}_test.json tcId #{test.test_case_id} (#{test.comment}) is marked #{test.result}, Beryl #{is_accepted ? "accepted" : "rejected"} it"
          end
          cases_run += 1
          VectorCaseCount.record({{ file[1] }}, "Wycheproof")
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  {% end %}

  it "AES-CBC with PKCS#7 decides every case of aes_cbc_pkcs5_test.json as marked" do
    test_file = Wycheproof::TestFile(Wycheproof::BlockCipherModeTestGroup).from_json(
      VectorFile.read("wycheproof/aes_cbc_pkcs5_test.json")
    )
    cases_run = 0

    test_file.list_of_test_groups.each do |test_group|
      test_group.list_of_tests.each do |test|
        cipher = Beryl::Crypto::Compatibility::AESCBC.new(test.key.hexbytes)
        initialization_vector = test.initialization_vector.hexbytes
        plaintext = cipher.decrypt(test.ciphertext.hexbytes, initialization_vector: initialization_vector)
        is_accepted = plaintext == test.message.hexbytes &&
                      cipher.encrypt(test.message.hexbytes, initialization_vector: initialization_vector) == test.ciphertext.hexbytes

        if test.result == "acceptable"
          VectorCaseCount.record_acceptable_decision(
            "aes_cbc_pkcs5_test.json tcId #{test.test_case_id} (#{test.comment}): #{is_accepted ? "accepted" : "rejected"}"
          )
        elsif is_accepted != (test.result == "valid")
          fail "aes_cbc_pkcs5_test.json tcId #{test.test_case_id} (#{test.comment}) is marked #{test.result}, Beryl #{is_accepted ? "accepted" : "rejected"} it"
        end
        cases_run += 1
        VectorCaseCount.record("AES-CBC", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end
end
