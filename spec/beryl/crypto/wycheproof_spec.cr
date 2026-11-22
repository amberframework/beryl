require "../../spec_helper"

# Wycheproof (C2SP/wycheproof, `testvectors_v1`). Every case marked `valid`
# must be accepted and every case marked `invalid` rejected. A case marked
# `acceptable` may go either way; Beryl's decision is printed after the suite.

# Runs the PBKDF2 cases of one Wycheproof file that are slow (at or over
# `SLOW_PBKDF2_ITERATION_COUNT`) or the ones that are not; the block derives
# the key for one case.
private def decide_pbkdf2_cases(file_name : String, algorithm : String, are_slow : Bool, & : Wycheproof::PbkdfTest -> Bytes) : Nil
  test_file = Wycheproof::TestFile(Wycheproof::PbkdfTestGroup).from_json(VectorFile.read("wycheproof/#{file_name}"))
  list_of_tests = test_file.list_of_test_groups.flat_map(&.list_of_tests)
  list_of_tests.size.should eq(test_file.number_of_tests)

  list_of_tests.each do |test|
    is_a_slow_case = test.iteration_count >= SLOW_PBKDF2_ITERATION_COUNT
    next unless is_a_slow_case == are_slow

    is_accepted = (yield test) == test.derived_key.hexbytes
    if test.result == "acceptable"
      VectorCaseCount.record_acceptable_decision(
        "#{file_name} tcId #{test.test_case_id} (#{test.comment}): #{is_accepted ? "accepted" : "rejected"}"
      )
    elsif is_accepted != (test.result == "valid")
      fail "#{file_name} tcId #{test.test_case_id} (#{test.comment}) is marked #{test.result}, Beryl #{is_accepted ? "accepted" : "rejected"} it"
    end
    VectorCaseCount.record(algorithm, "Wycheproof")
  end
end

describe "Wycheproof vectors" do
  {% for file in [{"hmac_sha1", "HMAC-SHA-1", "Beryl::Crypto::Compatibility::SHA1"},
                  {"hmac_sha224", "HMAC-SHA-224", "Beryl::Crypto::V1::SHA224"},
                  {"hmac_sha256", "HMAC-SHA-256", "Beryl::Crypto::V1::SHA256"},
                  {"hmac_sha384", "HMAC-SHA-384", "Beryl::Crypto::V1::SHA384"},
                  {"hmac_sha512", "HMAC-SHA-512", "Beryl::Crypto::V1::SHA512"},
                  {"hmac_sha512_256", "HMAC-SHA-512/256", "Beryl::Crypto::V1::SHA512_256"}] %}
    it "{{ file[1].id }} decides every case of {{ file[0].id }}_test.json as marked" do
      test_file = Wycheproof::TestFile(Wycheproof::MacTestGroup).from_json(
        VectorFile.read("wycheproof/{{ file[0].id }}_test.json")
      )
      cases_run = 0

      test_file.list_of_test_groups.each do |test_group|
        tag_bytesize = test_group.tag_bit_size // 8
        test_group.list_of_tests.each do |test|
          key = test.key.hexbytes
          key.size.should eq(test_group.key_bit_size // 8)

          authentication = Beryl::Crypto::V1::HMAC({{ file[2].id }}).new(key)
          authentication.update(test.message.hexbytes)
          is_accepted = authentication.verify(test.tag.hexbytes, truncated_to_bytesize: tag_bytesize)

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

  {% for file in [{"hkdf_sha1", "HKDF-SHA-1", "Beryl::Crypto::Compatibility::SHA1"},
                  {"hkdf_sha256", "HKDF-SHA-256", "Beryl::Crypto::V1::SHA256"},
                  {"hkdf_sha384", "HKDF-SHA-384", "Beryl::Crypto::V1::SHA384"},
                  {"hkdf_sha512", "HKDF-SHA-512", "Beryl::Crypto::V1::SHA512"}] %}
    it "{{ file[1].id }} decides every case of {{ file[0].id }}_test.json as marked" do
      test_file = Wycheproof::TestFile(Wycheproof::HkdfTestGroup).from_json(
        VectorFile.read("wycheproof/{{ file[0].id }}_test.json")
      )
      cases_run = 0

      test_file.list_of_test_groups.each do |test_group|
        test_group.list_of_tests.each do |test|
          is_accepted =
            begin
              derived_key = Beryl::Crypto::V1::HKDF({{ file[2].id }}).derive_key(
                test.input_key_material.hexbytes,
                salt: test.salt.hexbytes,
                info: test.info.hexbytes,
                bytesize: test.derived_key_bytesize,
              )
              derived_key == test.derived_key.hexbytes
            rescue Beryl::Crypto::DerivedKeyTooLong
              false
            end

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

  {% for file in [{"pbkdf2_hmacsha1", "PBKDF2-HMAC-SHA-1", "Beryl::Crypto::Compatibility::SHA1"},
                  {"pbkdf2_hmacsha256", "PBKDF2-HMAC-SHA-256", "Beryl::Crypto::V1::SHA256"},
                  {"pbkdf2_hmacsha512", "PBKDF2-HMAC-SHA-512", "Beryl::Crypto::V1::SHA512"}] %}
    it "{{ file[1].id }} decides every case of {{ file[0].id }}_test.json under one million iterations as marked" do
      decide_pbkdf2_cases("{{ file[0].id }}_test.json", {{ file[1] }}, are_slow: false) do |test|
        Beryl::Crypto::Compatibility::PBKDF2({{ file[2].id }}).derive_key(
          test.password.hexbytes,
          salt: test.salt.hexbytes,
          iteration_count: test.iteration_count,
          bytesize: test.derived_key_bytesize,
        )
      end
    end

    if RequestedSpecTag.includes?("slow")
      it "{{ file[1].id }} decides the cases of {{ file[0].id }}_test.json at one million iterations and over as marked", tags: "slow" do
        decide_pbkdf2_cases("{{ file[0].id }}_test.json", {{ file[1] }}, are_slow: true) do |test|
          Beryl::Crypto::Compatibility::PBKDF2({{ file[2].id }}).derive_key(
            test.password.hexbytes,
            salt: test.salt.hexbytes,
            iteration_count: test.iteration_count,
            bytesize: test.derived_key_bytesize,
          )
        end
      end
    end
  {% end %}
end
