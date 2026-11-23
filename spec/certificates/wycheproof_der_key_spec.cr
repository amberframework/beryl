require "../spec_helper"

# Wycheproof with every public key read from its DER SubjectPublicKeyInfo
# (`publicKeyDer`, and the `public` field of ecdh_secp256r1_test.json)
# through `Beryl::Certificates::SubjectPublicKeyInfo`, the path a
# certificate's key takes. A case marked `valid` must verify (or agree on
# the shared secret), `invalid` must be refused, and each `acceptable`
# decision is recorded.

private def record_der_key_decision(file_name : String, test_case_id : Int32, comment : String, flags : Array(String), result : String, is_accepted : Bool) : Nil
  if result == "acceptable"
    VectorCaseCount.record_acceptable_decision(
      "#{file_name} tcId #{test_case_id} (#{comment}; #{flags.join(", ")}): #{is_accepted ? "accepted" : "rejected"}"
    )
  elsif is_accepted != (result == "valid")
    fail "#{file_name} tcId #{test_case_id} (#{comment}) is marked #{result}, Beryl #{is_accepted ? "accepted" : "rejected"} it"
  end
end

private def digest_named(hash_name : String, message : Bytes) : Bytes
  case hash_name
  when "SHA-224"     then Beryl::Crypto::V1::SHA224.digest(message)
  when "SHA-256"     then Beryl::Crypto::V1::SHA256.digest(message)
  when "SHA-384"     then Beryl::Crypto::V1::SHA384.digest(message)
  when "SHA-512"     then Beryl::Crypto::V1::SHA512.digest(message)
  when "SHA-512/256" then Beryl::Crypto::V1::SHA512_256.digest(message)
  else                    raise "no hash named #{hash_name}"
  end
end

private def verify_pkcs1_named(key : Beryl::Crypto::V1::RSA::PublicKey, hash_name : String, message : Bytes, signature : Bytes) : Bool
  case hash_name
  when "SHA-224"     then key.verify_pkcs1_signature(message, signature, hash_function: Beryl::Crypto::V1::SHA224)
  when "SHA-256"     then key.verify_pkcs1_signature(message, signature, hash_function: Beryl::Crypto::V1::SHA256)
  when "SHA-384"     then key.verify_pkcs1_signature(message, signature, hash_function: Beryl::Crypto::V1::SHA384)
  when "SHA-512"     then key.verify_pkcs1_signature(message, signature, hash_function: Beryl::Crypto::V1::SHA512)
  when "SHA-512/256" then key.verify_pkcs1_signature(message, signature, hash_function: Beryl::Crypto::V1::SHA512_256)
  else                    raise "no hash named #{hash_name}"
  end
end

private def verification_key_from_der(hex : String) : Beryl::Certificates::VerificationKey?
  Beryl::Certificates::SubjectPublicKeyInfo.from_der(hex.hexbytes).verification_key
rescue Beryl::Certificates::MalformedCertificate
  nil
end

describe "Wycheproof public keys read from DER" do
  {% for file in [{"ecdsa_secp256r1_sha256_test", "P-256 ECDSA"}, {"ecdsa_secp384r1_sha384_test", "P-384 ECDSA"}] %}
    it "{{ file[1].id }} decides every case of {{ file[0].id }}.json as marked, with the key from DER" do
      test_file = Wycheproof::TestFile(Wycheproof::EcdsaVerifyTestGroup).from_json(VectorFile.read("wycheproof/{{ file[0].id }}.json"))
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        key = verification_key_from_der(test_group.public_key_der)
        key.should_not be_nil
        test_group.list_of_tests.each do |test|
          digest = digest_named(test_group.hash_name, test.message.hexbytes)
          is_accepted = case key
                        when Beryl::Crypto::V1::P256::PublicKey then key.verify_digest(digest, test.signature.hexbytes)
                        when Beryl::Crypto::V1::P384::PublicKey then key.verify_digest(digest, test.signature.hexbytes)
                        else                                         false
                        end
          record_der_key_decision("{{ file[0].id }}.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
          cases_run += 1
          VectorCaseCount.record("{{ file[1].id }} (DER key)", "Wycheproof")
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  {% end %}

  it "Ed25519 decides every case of ed25519_test.json as marked, with the key from DER" do
    test_file = Wycheproof::TestFile(Wycheproof::EddsaVerifyTestGroup).from_json(VectorFile.read("wycheproof/ed25519_test.json"))
    cases_run = 0
    test_file.list_of_test_groups.each do |test_group|
      key = verification_key_from_der(test_group.public_key_der)
      key.should be_a(Beryl::Crypto::V1::Ed25519::VerificationKey)
      test_group.list_of_tests.each do |test|
        is_accepted = key.is_a?(Beryl::Crypto::V1::Ed25519::VerificationKey) && key.verify(test.message.hexbytes, test.signature.hexbytes)
        record_der_key_decision("ed25519_test.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
        cases_run += 1
        VectorCaseCount.record("Ed25519 (DER key)", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end

  {% for file in %w(rsa_signature_2048_sha224_test rsa_signature_2048_sha256_test rsa_signature_2048_sha384_test
                   rsa_signature_2048_sha512_test rsa_signature_2048_sha512_256_test
                   rsa_signature_3072_sha256_test rsa_signature_3072_sha384_test rsa_signature_3072_sha512_test
                   rsa_signature_3072_sha512_256_test
                   rsa_signature_4096_sha256_test rsa_signature_4096_sha384_test rsa_signature_4096_sha512_test
                   rsa_signature_4096_sha512_256_test
                   rsa_signature_8192_sha256_test rsa_signature_8192_sha384_test rsa_signature_8192_sha512_test) %}
    it "RSA PKCS #1 decides every case of {{ file.id }}.json as marked, with the key from DER" do
      test_file = Wycheproof::TestFile(Wycheproof::RsaSignatureTestGroup).from_json(VectorFile.read("wycheproof/{{ file.id }}.json"))
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        key = verification_key_from_der(test_group.public_key_der)
        key.should be_a(Beryl::Crypto::V1::RSA::PublicKey)
        test_group.list_of_tests.each do |test|
          is_accepted = key.is_a?(Beryl::Crypto::V1::RSA::PublicKey) &&
                        verify_pkcs1_named(key, test_group.hash_name, test.message.hexbytes, test.signature.hexbytes)
          record_der_key_decision("{{ file.id }}.json", test.test_case_id, test.comment, test.list_of_flags, test.result, is_accepted)
          cases_run += 1
          VectorCaseCount.record("RSA PKCS#1 (DER key)", "Wycheproof")
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  {% end %}

  it "P-256 ECDH decides every case of ecdh_secp256r1_test.json as marked, with the peer key from DER" do
    test_file = Wycheproof::TestFile(Wycheproof::KeyAgreementTestGroup).from_json(VectorFile.read("wycheproof/ecdh_secp256r1_test.json"))
    cases_run = 0
    test_file.list_of_test_groups.each do |test_group|
      test_group.list_of_tests.each do |test|
        is_accepted = begin
          peer = verification_key_from_der(test.public_key)
          private_bytes = CavpEcdsaFile.fixed_width(test.private_key, 32) || raise "private key too long"
          if peer.is_a?(Beryl::Crypto::V1::P256::PublicKey)
            Beryl::Crypto::V1::P256::PrivateKey.new(private_bytes).shared_secret(peer) == test.shared.hexbytes
          else
            false
          end
        rescue Beryl::Crypto::Error
          false
        end
        record_der_key_decision("ecdh_secp256r1_test.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
        cases_run += 1
        VectorCaseCount.record("P-256 ECDH (DER key)", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end
end
