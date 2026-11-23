require "../../spec_helper"

# Wycheproof (C2SP/wycheproof, `testvectors_v1`) for the curves. A case
# marked `valid` must be accepted with the published result, a case marked
# `invalid` refused (with `nil`, `false` or a named error), and each case
# marked `acceptable` has its decision recorded.

private def record_decision(file_name : String, test_case_id : Int32, comment : String, flags : Array(String), result : String, is_accepted : Bool) : Nil
  if result == "acceptable"
    VectorCaseCount.record_acceptable_decision(
      "#{file_name} tcId #{test_case_id} (#{comment}; #{flags.join(", ")}): #{is_accepted ? "accepted" : "rejected"}"
    )
  elsif is_accepted != (result == "valid")
    fail "#{file_name} tcId #{test_case_id} (#{comment}) is marked #{result}, Beryl #{is_accepted ? "accepted" : "rejected"} it"
  end
end

describe "Wycheproof public-key vectors" do
  it "X25519 decides every case of x25519_test.json as marked" do
    test_file = Wycheproof::TestFile(Wycheproof::KeyAgreementTestGroup).from_json(VectorFile.read("wycheproof/x25519_test.json"))
    cases_run = 0
    test_file.list_of_test_groups.each do |test_group|
      test_group.list_of_tests.each do |test|
        private_key = Beryl::Crypto::V1::X25519::PrivateKey.new(test.private_key.hexbytes)
        shared = private_key.shared_secret(Beryl::Crypto::V1::X25519::PublicKey.new(test.public_key.hexbytes))
        is_accepted = !shared.nil? && shared == test.shared.hexbytes
        # A refused all-zero secret is the right answer for a small-order point.
        if shared.nil?
          test.shared.hexbytes.all?(&.zero?).should be_true
        end
        record_decision("x25519_test.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
        cases_run += 1
        VectorCaseCount.record("X25519", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end

  it "Ed25519 decides every case of ed25519_test.json as marked" do
    test_file = Wycheproof::TestFile(Wycheproof::EddsaVerifyTestGroup).from_json(VectorFile.read("wycheproof/ed25519_test.json"))
    cases_run = 0
    test_file.list_of_test_groups.each do |test_group|
      verification_key = Beryl::Crypto::V1::Ed25519::VerificationKey.new(test_group.public_key.encoded.hexbytes)
      test_group.list_of_tests.each do |test|
        is_accepted = verification_key.verify(test.message.hexbytes, test.signature.hexbytes)
        record_decision("ed25519_test.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
        cases_run += 1
        VectorCaseCount.record("Ed25519", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end

  it "P-256 ECDH decides every case of ecdh_secp256r1_ecpoint_test.json as marked" do
    test_file = Wycheproof::TestFile(Wycheproof::KeyAgreementTestGroup).from_json(VectorFile.read("wycheproof/ecdh_secp256r1_ecpoint_test.json"))
    cases_run = 0
    test_file.list_of_test_groups.each do |test_group|
      test_group.list_of_tests.each do |test|
        is_accepted = begin
          # Wycheproof writes private keys as signed big-endian integers, so
          # a leading zero byte may make them 33 bytes long.
          private_bytes = CavpEcdsaFile.fixed_width(test.private_key, 32) || raise "private key too long"
          private_key = Beryl::Crypto::V1::P256::PrivateKey.new(private_bytes)
          peer = Beryl::Crypto::V1::P256::PublicKey.new(test.public_key.hexbytes)
          private_key.shared_secret(peer) == test.shared.hexbytes
        rescue Beryl::Crypto::Error
          false
        end
        record_decision("ecdh_secp256r1_ecpoint_test.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
        cases_run += 1
        VectorCaseCount.record("P-256 ECDH", "Wycheproof")
      end
    end
    cases_run.should eq(test_file.number_of_tests)
  end

  {% for file in [{"ecdsa_secp256r1_sha256_test", "P256", "DER", "P-256 ECDSA"},
                  {"ecdsa_secp256r1_sha256_p1363_test", "P256", "FixedWidth", "P-256 ECDSA"},
                  {"ecdsa_secp384r1_sha384_test", "P384", "DER", "P-384 ECDSA"},
                  {"ecdsa_secp384r1_sha384_p1363_test", "P384", "FixedWidth", "P-384 ECDSA"}] %}
    it "{{ file[3].id }} decides every case of {{ file[0].id }}.json as marked" do
      test_file = Wycheproof::TestFile(Wycheproof::EcdsaVerifyTestGroup).from_json(VectorFile.read("wycheproof/{{ file[0].id }}.json"))
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        public_key = Beryl::Crypto::V1::{{ file[1].id }}::PublicKey.new(test_group.public_key.uncompressed.hexbytes)
        test_group.list_of_tests.each do |test|
          is_accepted = public_key.verify(test.message.hexbytes, test.signature.hexbytes,
            format: Beryl::Crypto::V1::SignatureFormat::{{ file[2].id }})
          record_decision("{{ file[0].id }}.json", test.test_case_id, test.comment, test.flags, test.result, is_accepted)
          cases_run += 1
          VectorCaseCount.record({{ file[3] }}, "Wycheproof")
        end
      end
      cases_run.should eq(test_file.number_of_tests)
    end
  {% end %}
end
