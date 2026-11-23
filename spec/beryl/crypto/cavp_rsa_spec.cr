require "../../spec_helper"

# NIST CAVP RSA vectors (`186-3rsatestvectors.zip`), 2,048 and 3,072-bit
# sections. Verification files mark each case P (pass) or F (fail); the
# signature-generation files give n, e and d and the expected signature,
# and the primes are recovered in `RsaKeyComponents.recover`. Sections and
# hashes outside what Beryl implements (1,024-bit moduli, SHA-512/224, SHA-1
# in PSS) are counted and skipped, and listed in `docs/crypto/public-key.md`.

private alias RSA = Beryl::Crypto::V1::RSA

# One case with the key fields in force for it: CAVP writes n (and in the
# generation files e and d) once per section, before the cases.
private record RsaCavpCase, fields : CavpResponseFile::Record, modulus : String, public_exponent : String,
  private_exponent : String

private def read_rsa_cases(file_name : String) : Array(RsaCavpCase)
  list_of_cases = [] of RsaCavpCase
  modulus = public_exponent = private_exponent = ""
  # The FIPS 186-4 files put a line holding one space inside some cases;
  # it is not the blank line that ends a case.
  contents = VectorFile.read("nist-cavp/rsa/#{file_name}").lines(chomp: false).reject do |line|
    line.strip.empty? && !line.chomp.empty?
  end.join
  CavpResponseFile.parse(contents).each do |record|
    modulus = record["n"]? || modulus
    public_exponent = record["e"]? || public_exponent
    private_exponent = record["d"]? || private_exponent
    list_of_cases << RsaCavpCase.new(record, modulus, public_exponent, private_exponent) if record.has_key?("Msg")
  end
  list_of_cases
end

private def rsa_case_in_scope?(test_case : RsaCavpCase, accepts_sha1 : Bool) : Bool
  hash_name = test_case.fields["SHAAlg"]
  test_case.fields["mod"].to_i >= 2_048 && hash_name != "SHA512224" && (accepts_sha1 || hash_name != "SHA1")
end

# The salt of a CAVP PSS case: "00" stands for no salt.
private def cavp_salt(test_case : RsaCavpCase) : Bytes
  salt_hex = test_case.fields["SaltVal"]
  salt_hex == "00" ? Bytes.empty : salt_hex.hexbytes
end

# The salt size of a PSS verification case. SigVerPSS_186-3_TruncatedSHAs.rsp
# gives no SaltVal; its header states "SHA-512/256(Salt len: 32)".
private def cavp_salt_bytesize(test_case : RsaCavpCase) : Int32
  return cavp_salt(test_case).size if test_case.fields.has_key?("SaltVal")
  return 32 if test_case.fields["SHAAlg"] == "SHA512256"

  raise "no salt size for a #{test_case.fields["SHAAlg"]} case"
end

# Reads hexadecimal that may have an odd number of digits (CAVP drops a
# leading zero digit now and then).
private def even_hexbytes(hex : String) : Bytes
  hex.rjust(hex.size + hex.size % 2, '0').hexbytes
end

# The signature of a CAVP case as modulus-sized bytes: CAVP drops the
# leading zero digits of some signatures.
private def cavp_signature(test_case : RsaCavpCase) : Bytes
  test_case.fields["S"].rjust(test_case.fields["mod"].to_i // 4, '0').hexbytes
end

# Builds the public key of a verification case; nil when Beryl refuses the
# key itself (some F cases change the public exponent).
private def cavp_public_key(test_case : RsaCavpCase) : RSA::PublicKey?
  RSA::PublicKey.new(even_hexbytes(test_case.modulus), even_hexbytes(test_case.public_exponent))
rescue Beryl::Crypto::PublicExponentNotSupported | Beryl::Crypto::KeySizeNotSupported
  nil
end

# The cases skipped per file, checked so a change in what is skipped shows.
EXPECTED_SKIPPED_CAVP_RSA_CASE_COUNT = {
  "SigVer15_186-3.rsp"                => 90,
  "SigVer15_186-3_TruncatedSHAs.rsp"  => 72,
  "SigVerPSS_186-3.rsp"               => 126,
  "SigVerPSS_186-3_TruncatedSHAs.rsp" => 72,
  "SigGen15_186-3.txt"                => 0,
  "SigGen15_186-3_TruncatedSHAs.txt"  => 20,
  "SigGenPSS_186-3.txt"               => 0,
  "SigGenPSS_186-3_TruncatedSHAs.txt" => 20,
}

describe "NIST CAVP RSA vectors" do
  {"SigVer15_186-3.rsp", "SigVer15_186-3_TruncatedSHAs.rsp"}.each do |file_name|
    it "PKCS #1 v1.5 verification decides every case of #{file_name} as marked" do
      list_of_cases = read_rsa_cases(file_name)
      cases_skipped = 0
      list_of_cases.each do |test_case|
        unless rsa_case_in_scope?(test_case, accepts_sha1: true)
          cases_skipped += 1
          next
        end
        public_key = cavp_public_key(test_case)
        is_accepted = if public_key
                        with_secure_hash_2_or_1_named(test_case.fields["SHAAlg"]) do |hash_function|
                          public_key.verify_pkcs1_signature(even_hexbytes(test_case.fields["Msg"]), cavp_signature(test_case),
                            hash_function: hash_function)
                        end
                      else
                        false
                      end
        is_expected = test_case.fields["Result"].starts_with?('P')
        fail "#{file_name}: a case marked #{test_case.fields["Result"]} was #{is_accepted ? "accepted" : "refused"}" unless is_accepted == is_expected
        VectorCaseCount.record("RSA PKCS#1 v1.5 verify", "CAVP")
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_CAVP_RSA_CASE_COUNT[file_name])
    end
  end

  {"SigVerPSS_186-3.rsp", "SigVerPSS_186-3_TruncatedSHAs.rsp"}.each do |file_name|
    it "PSS verification decides every case of #{file_name} as marked" do
      list_of_cases = read_rsa_cases(file_name)
      cases_skipped = 0
      list_of_cases.each do |test_case|
        unless rsa_case_in_scope?(test_case, accepts_sha1: false)
          cases_skipped += 1
          next
        end
        public_key = cavp_public_key(test_case)
        is_accepted = if public_key
                        with_secure_hash_2_named(test_case.fields["SHAAlg"]) do |hash_function|
                          public_key.verify_pss_signature(even_hexbytes(test_case.fields["Msg"]), cavp_signature(test_case),
                            hash_function: hash_function, salt_bytesize: cavp_salt_bytesize(test_case))
                        end
                      else
                        false
                      end
        is_expected = test_case.fields["Result"].starts_with?('P')
        fail "#{file_name}: a case marked #{test_case.fields["Result"]} was #{is_accepted ? "accepted" : "refused"}" unless is_accepted == is_expected
        VectorCaseCount.record("RSA-PSS verify", "CAVP")
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_CAVP_RSA_CASE_COUNT[file_name])
    end
  end

  {"SigGen15_186-3.txt", "SigGen15_186-3_TruncatedSHAs.txt"}.each do |file_name|
    it "PKCS #1 v1.5 signing gives the signature of every case of #{file_name}" do
      list_of_cases = read_rsa_cases(file_name)
      cases_skipped = 0
      list_of_cases.each do |test_case|
        unless rsa_case_in_scope?(test_case, accepts_sha1: false)
          cases_skipped += 1
          next
        end
        private_key = RsaKeyComponents.recover(test_case.modulus, test_case.public_exponent, test_case.private_exponent).private_key
        signature = with_secure_hash_2_named(test_case.fields["SHAAlg"]) do |hash_function|
          private_key.sign_with_pkcs1(even_hexbytes(test_case.fields["Msg"]), hash_function: hash_function)
        end
        signature.should eq(cavp_signature(test_case))
        VectorCaseCount.record("RSA PKCS#1 v1.5 sign", "CAVP")
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_CAVP_RSA_CASE_COUNT[file_name])
    end
  end

  {"SigGenPSS_186-3.txt", "SigGenPSS_186-3_TruncatedSHAs.txt"}.each do |file_name|
    it "PSS signing with the published salt gives the signature of every case of #{file_name}" do
      list_of_cases = read_rsa_cases(file_name)
      cases_skipped = 0
      list_of_cases.each do |test_case|
        unless rsa_case_in_scope?(test_case, accepts_sha1: false)
          cases_skipped += 1
          next
        end
        private_key = RsaKeyComponents.recover(test_case.modulus, test_case.public_exponent, test_case.private_exponent).private_key
        message = even_hexbytes(test_case.fields["Msg"])
        salt = cavp_salt(test_case)
        with_secure_hash_2_named(test_case.fields["SHAAlg"]) do |hash_function|
          private_key.sign_with_pss_using_salt(message, salt, hash_function: hash_function).should eq(cavp_signature(test_case))
          private_key.public_key.verify_pss_signature(message, cavp_signature(test_case),
            hash_function: hash_function, salt_bytesize: salt.size).should be_true
        end
        VectorCaseCount.record("RSA-PSS sign", "CAVP")
      end
      cases_skipped.should eq(EXPECTED_SKIPPED_CAVP_RSA_CASE_COUNT[file_name])
    end
  end
end
