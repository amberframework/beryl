require "../../spec_helper"

# NIST CAVP Secure Hash Algorithm Validation System (SHAVS), byte-oriented
# vectors: {standard name, file name prefix}.
private LIST_OF_SHAVS_ALGORITHMS = [
  {"SHA-1", "SHA1"},
  {"SHA-224", "SHA224"},
  {"SHA-256", "SHA256"},
  {"SHA-384", "SHA384"},
  {"SHA-512", "SHA512"},
  {"SHA-512/256", "SHA512_256"},
]

# SHAVS §6.4: one hundred checkpoints, each the result of chaining one
# thousand digests over the three previous digests.
private MONTE_CARLO_CHECKPOINT_COUNT       =  100
private MONTE_CARLO_DIGESTS_PER_CHECKPOINT = 1000

describe "NIST CAVP SHA byte-oriented vectors" do
  LIST_OF_SHAVS_ALGORITHMS.each do |standard_name, file_name_prefix|
    build_hash = HASH_FUNCTION_BY_STANDARD_NAME[standard_name]

    {"ShortMsg", "LongMsg"}.each do |kind|
      it "#{standard_name} passes every case of #{file_name_prefix}#{kind}.rsp" do
        contents = VectorFile.read("nist-cavp/shs/#{file_name_prefix}#{kind}.rsp")
        list_of_records = CavpResponseFile.parse(contents)
        list_of_records.should_not be_empty

        list_of_records.each do |record|
          message_bit_size = record["Len"].to_i
          # A zero-length case prints its message as "00".
          message = message_bit_size == 0 ? Bytes.empty : record["Msg"].hexbytes
          message.size.should eq(message_bit_size // 8)

          digest = build_hash.call.update(message).final
          if digest.hexstring != record["MD"]
            fail "#{file_name_prefix}#{kind}.rsp Len = #{message_bit_size}: got #{digest.hexstring}, expected #{record["MD"]}"
          end
          VectorCaseCount.record(standard_name, "CAVP")
        end
      end
    end

    it "#{standard_name} passes every checkpoint of #{file_name_prefix}Monte.rsp" do
      contents = VectorFile.read("nist-cavp/shs/#{file_name_prefix}Monte.rsp")
      list_of_records = CavpResponseFile.parse(contents)
      seed = list_of_records.first["Seed"].hexbytes
      list_of_checkpoints = list_of_records.select(&.has_key?("COUNT"))
      list_of_checkpoints.size.should eq(MONTE_CARLO_CHECKPOINT_COUNT)

      hash = build_hash.call
      list_of_checkpoints.each do |checkpoint|
        third_last = seed
        second_last = seed
        last = seed
        MONTE_CARLO_DIGESTS_PER_CHECKPOINT.times do
          hash.reset
          hash.update(third_last).update(second_last).update(last)
          third_last = second_last
          second_last = last
          last = hash.final
        end
        seed = last

        if seed.hexstring != checkpoint["MD"]
          fail "#{file_name_prefix}Monte.rsp COUNT = #{checkpoint["COUNT"]}: got #{seed.hexstring}, expected #{checkpoint["MD"]}"
        end
        VectorCaseCount.record(standard_name, "CAVP")
      end
    end
  end
end
