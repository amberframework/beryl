require "../../spec_helper"

# NIST CAVP HMAC vectors (`HMAC.rsp`). Each `[L=n]` section names its hash by
# digest size in bytes; each case gives the key, the message and the tag cut
# to `Tlen` bytes. The fourth value of each section below is its case count
# (75 per tag length offered).
describe "NIST CAVP HMAC vectors" do
  list_of_records = CavpResponseFile.parse(VectorFile.read("nist-cavp/mac/HMAC.rsp"))

  it "reads all 1,575 cases" do
    list_of_records.size.should eq(1575)
  end

  {% for section in [{20, "SHA-1", "Beryl::Crypto::Compatibility::SHA1", 300},
                     {28, "SHA-224", "Beryl::Crypto::V1::SHA224", 375},
                     {32, "SHA-256", "Beryl::Crypto::V1::SHA256", 225},
                     {48, "SHA-384", "Beryl::Crypto::V1::SHA384", 300},
                     {64, "SHA-512", "Beryl::Crypto::V1::SHA512", 375}] %}
    it "HMAC-{{ section[1].id }} passes every case of section [L={{ section[0] }}]" do
      list_of_section_records = list_of_records.select { |record| record["L"] == {{ section[0].stringify }} }
      list_of_section_records.size.should eq({{ section[3] }})

      list_of_section_records.each do |record|
        key = record["Key"].hexbytes
        message = record["Msg"].hexbytes
        expected_tag = record["Mac"].hexbytes
        tag_bytesize = record["Tlen"].to_i
        key.size.should eq(record["Klen"].to_i)
        expected_tag.size.should eq(tag_bytesize)

        full_tag = Beryl::Crypto::V1::HMAC({{ section[2].id }}).authenticate(message, key: key)
        if full_tag[0, tag_bytesize] != expected_tag
          fail "HMAC.rsp [L={{ section[0] }}] Count = #{record["Count"]}: got #{full_tag[0, tag_bytesize].hexstring}, expected #{record["Mac"]}"
        end

        authentication = Beryl::Crypto::V1::HMAC({{ section[2].id }}).new(key)
        authentication.update(message)
        authentication.verify(expected_tag, truncated_to_bytesize: tag_bytesize).should be_true

        altered_tag = expected_tag.dup
        altered_tag[tag_bytesize - 1] ^= 0x01_u8
        authentication.reset.update(message)
        authentication.verify(altered_tag, truncated_to_bytesize: tag_bytesize).should be_false

        VectorCaseCount.record("HMAC-{{ section[1].id }}", "CAVP")
      end
    end
  {% end %}
end
