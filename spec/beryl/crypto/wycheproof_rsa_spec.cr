require "../../spec_helper"

# Wycheproof RSA files (C2SP/wycheproof, `testvectors_v1`). Every case marked
# `valid` must be accepted and every case marked `invalid` refused; a case
# marked `acceptable` may go either way, and Beryl's decision is printed
# after the suite. Groups outside what Beryl implements (a hash for MGF1
# that differs from the message hash, SHA-1 in PSS, moduli outside the key
# sizes Beryl accepts) are counted and skipped; `docs/crypto/public-key.md`
# lists them.

private alias RSA = Beryl::Crypto::V1::RSA

# Notes a decision on one case and fails when a `valid` or `invalid` case
# went the wrong way.
private def decide_rsa_case(file_name : String, test_case_id : Int32, comment : String, result : String,
                            is_accepted : Bool, algorithm : String) : Nil
  if result == "acceptable"
    VectorCaseCount.record_acceptable_decision(
      "#{file_name} tcId #{test_case_id} (#{comment}): #{is_accepted ? "accepted" : "refused"}"
    )
  elsif is_accepted != (result == "valid")
    fail "#{file_name} tcId #{test_case_id} (#{comment}) is marked #{result}, Beryl #{is_accepted ? "accepted" : "refused"} it"
  end
  VectorCaseCount.record(algorithm, "Wycheproof")
end

private def read_signature_file(file_name : String) : Wycheproof::TestFile(Wycheproof::RsaSignatureTestGroup)
  Wycheproof::TestFile(Wycheproof::RsaSignatureTestGroup).from_json(VectorFile.read("wycheproof/#{file_name}"))
end

# The PKCS #1 v1.5 verification files and the PSS files Beryl runs, by size
# and hash.
LIST_OF_RSA_SIGNATURE_FILES = %w[
  rsa_signature_2048_sha224_test.json rsa_signature_2048_sha256_test.json rsa_signature_2048_sha384_test.json
  rsa_signature_2048_sha512_test.json rsa_signature_2048_sha512_256_test.json
  rsa_signature_3072_sha256_test.json rsa_signature_3072_sha384_test.json rsa_signature_3072_sha512_test.json
  rsa_signature_3072_sha512_256_test.json
  rsa_signature_4096_sha256_test.json rsa_signature_4096_sha384_test.json rsa_signature_4096_sha512_test.json
  rsa_signature_4096_sha512_256_test.json
  rsa_signature_8192_sha256_test.json rsa_signature_8192_sha384_test.json rsa_signature_8192_sha512_test.json
]
LIST_OF_RSA_SIGNATURE_GENERATION_FILES = %w[
  rsa_pkcs1_2048_sig_gen_test.json rsa_pkcs1_3072_sig_gen_test.json rsa_pkcs1_4096_sig_gen_test.json
]
LIST_OF_RSA_PSS_FILES = %w[
  rsa_pss_2048_sha256_mgf1_0_test.json rsa_pss_2048_sha256_mgf1_32_test.json rsa_pss_2048_sha384_mgf1_48_test.json
  rsa_pss_2048_sha512_256_mgf1_32_test.json rsa_pss_3072_sha256_mgf1_32_test.json
  rsa_pss_4096_sha256_mgf1_32_test.json rsa_pss_4096_sha384_mgf1_48_test.json rsa_pss_4096_sha512_mgf1_32_test.json
  rsa_pss_4096_sha512_mgf1_64_test.json rsa_pss_misc_test.json
]
LIST_OF_RSA_OAEP_FILES = %w[
  rsa_oaep_2048_sha1_mgf1sha1_test.json rsa_oaep_2048_sha224_mgf1sha224_test.json
  rsa_oaep_2048_sha256_mgf1sha256_test.json rsa_oaep_2048_sha384_mgf1sha384_test.json
  rsa_oaep_2048_sha512_mgf1sha512_test.json rsa_oaep_3072_sha256_mgf1sha256_test.json
  rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json rsa_oaep_3072_sha512_mgf1sha512_test.json
  rsa_oaep_4096_sha256_mgf1sha256_test.json rsa_oaep_4096_sha512_mgf1sha512_test.json rsa_oaep_misc_test.json
]

# The cases the misc files hold outside what Beryl implements, checked so a
# change in what is skipped shows: PSS with SHA-1 or with a different MGF1
# hash; OAEP with a different MGF1 hash or a modulus outside 2,048 to 4,096
# bits.
EXPECTED_SKIPPED_RSA_CASE_COUNT = {"rsa_pss_misc_test.json" => 126, "rsa_oaep_misc_test.json" => 333}

describe "Wycheproof RSA vectors" do
  LIST_OF_RSA_SIGNATURE_FILES.each do |file_name|
    it "PKCS #1 v1.5 verification decides every case of #{file_name} as marked" do
      test_file = read_signature_file(file_name)
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        public_key = RSA::PublicKey.new(test_group.public_key.modulus.hexbytes, test_group.public_key.public_exponent.hexbytes)
        public_key.modulus_bit_count.should eq(test_group.key_bit_size)
        test_group.list_of_tests.each do |test|
          is_accepted = with_secure_hash_2_or_1_named(test_group.hash_name) do |hash_function|
            public_key.verify_pkcs1_signature(test.message.hexbytes, test.signature.hexbytes, hash_function: hash_function)
          end
          raise "#{file_name} names a hash Beryl does not have: #{test_group.hash_name}" if is_accepted.nil?
          decide_rsa_case(file_name, test.test_case_id, test.comment, test.result, is_accepted, "RSA PKCS#1 v1.5 verify")
          cases_run += 1
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  end

  LIST_OF_RSA_SIGNATURE_GENERATION_FILES.each do |file_name|
    it "PKCS #1 v1.5 signing gives the signature of every case of #{file_name}" do
      test_file = read_signature_file(file_name)
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        components = RsaKeyComponents.from_wycheproof(test_group.private_key)
        begin
          private_key = components.private_key
        rescue error : Beryl::Crypto::MalformedPrivateKey
          # A key whose primes differ in size by far more than FIPS 186-5 allows:
          # Beryl refuses the key. The published signatures must still verify.
          public_key = RSA::PublicKey.new(components.modulus, components.public_exponent)
          test_group.list_of_tests.each do |test|
            test.result.should eq("acceptable")
            is_verified = with_secure_hash_2_named(test_group.hash_name) do |hash_function|
              public_key.verify_pkcs1_signature(test.message.hexbytes, test.signature.hexbytes, hash_function: hash_function)
            end
            is_verified.should be_true
            VectorCaseCount.record_acceptable_decision(
              "#{file_name} tcId #{test.test_case_id} (#{test.list_of_flags.join(", ")}): key refused (#{error.message}); the published signature verifies"
            )
            VectorCaseCount.record("RSA PKCS#1 v1.5 sign", "Wycheproof")
            cases_run += 1
          end
          next
        end
        private_key.modulus_bit_count.should eq(test_group.key_bit_size)
        test_group.list_of_tests.each do |test|
          message = test.message.hexbytes
          expected_signature = test.signature.hexbytes
          produced_signature = with_secure_hash_2_named(test_group.hash_name) do |hash_function|
            private_key.sign_with_pkcs1(message, hash_function: hash_function)
          end
          if produced_signature
            decide_rsa_case(file_name, test.test_case_id, test.comment, test.result,
              produced_signature == expected_signature, "RSA PKCS#1 v1.5 sign")
          else
            # SHA-1: Beryl verifies but does not sign. The published
            # signature must still verify.
            test_group.hash_name.should eq("SHA-1")
            is_verified = private_key.public_key.verify_pkcs1_signature(message, expected_signature,
              hash_function: Beryl::Crypto::Compatibility::SHA1)
            VectorCaseCount.record_acceptable_decision(
              "#{file_name} tcId #{test.test_case_id} (SHA-1, marked #{test.result}): not signed, Beryl signs with SHA-2 only; the published signature #{is_verified ? "verifies" : "does not verify"}"
            )
            is_verified.should be_true
            VectorCaseCount.record("RSA PKCS#1 v1.5 sign", "Wycheproof")
          end
          cases_run += 1
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  end

  LIST_OF_RSA_PSS_FILES.each do |file_name|
    it "PSS verification decides every case of #{file_name} as marked" do
      test_file = read_signature_file(file_name)
      cases_run = 0
      cases_skipped = 0
      test_file.list_of_test_groups.each do |test_group|
        if test_group.hash_name != test_group.mask_generation_hash_name || test_group.hash_name == "SHA-1"
          cases_skipped += test_group.list_of_tests.size
          next
        end
        public_key = RSA::PublicKey.new(test_group.public_key.modulus.hexbytes, test_group.public_key.public_exponent.hexbytes)
        test_group.list_of_tests.each do |test|
          is_accepted = with_secure_hash_2_named(test_group.hash_name) do |hash_function|
            public_key.verify_pss_signature(test.message.hexbytes, test.signature.hexbytes,
              hash_function: hash_function, salt_bytesize: test_group.salt_bytesize)
          end
          raise "#{file_name} names a hash Beryl does not have: #{test_group.hash_name}" if is_accepted.nil?
          decide_rsa_case(file_name, test.test_case_id, test.comment, test.result, is_accepted, "RSA-PSS verify")
          cases_run += 1
        end
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_RSA_CASE_COUNT.fetch(file_name, 0))
      (cases_run + cases_skipped).should eq(test_file.number_of_tests)
    end
  end

  LIST_OF_RSA_OAEP_FILES.each do |file_name|
    it "OAEP decryption decides every case of #{file_name} as marked" do
      test_file = Wycheproof::TestFile(Wycheproof::RsaOaepTestGroup).from_json(VectorFile.read("wycheproof/#{file_name}"))
      cases_run = 0
      cases_skipped = 0
      test_file.list_of_test_groups.each do |test_group|
        is_in_scope = test_group.hash_name == test_group.mask_generation_hash_name &&
                      RSA::PrivateKey::SMALLEST_MODULUS_BIT_COUNT <= test_group.key_bit_size <= RSA::PrivateKey::LARGEST_MODULUS_BIT_COUNT
        unless is_in_scope
          cases_skipped += test_group.list_of_tests.size
          next
        end
        private_key = RsaKeyComponents.from_wycheproof(test_group.private_key).private_key
        test_group.list_of_tests.each do |test|
          message = test.message.hexbytes
          decrypted = with_secure_hash_2_or_1_named(test_group.hash_name) do |hash_function|
            private_key.decrypt_with_oaep(test.ciphertext.hexbytes, hash_function: hash_function, label: test.label.hexbytes)
          end
          decide_rsa_case(file_name, test.test_case_id, test.comment, test.result, decrypted == message, "RSA-OAEP decrypt")
          cases_run += 1
        end
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_RSA_CASE_COUNT.fetch(file_name, 0))
      (cases_run + cases_skipped).should eq(test_file.number_of_tests)
    end
  end
end
