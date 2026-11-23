require "../../spec_helper"

private alias FieldArithmetic = Beryl::Crypto::FieldArithmetic
private alias MontgomeryArithmetic = Beryl::Crypto::V1::MontgomeryArithmetic

# Little-endian 64-bit words of a big-endian hex integer.
private def words_of(hex : String) : Array(UInt64)
  hex.rjust((hex.size + 15) // 16 * 16, '0').scan(/.{16}/).map(&.[0].to_u64(16)).reverse
end

describe "Beryl::Crypto::FieldArithmetic, the constants the assembly reads" do
  {% for entry in [
                    {"P256ScalarFieldWithAssembly", "P256", "GROUP_ORDER"},
                    {"P384FieldWithAssembly", "P384", "FIELD_PRIME"},
                    {"P384ScalarFieldWithAssembly", "P384", "GROUP_ORDER"},
                  ] %}
    it "holds the {{ entry[2].id.downcase.gsub(/_/, " ") }} of {{ entry[1].id }} and its negated inverse in {{ entry[0].id }}" do
      expected = words_of(Beryl::Crypto::V1::{{ entry[1].id }}::Arithmetic::{{ entry[2].id }}.hexstring)
      FieldArithmetic::{{ entry[0].id }}::MODULUS_WORDS.to_a.should eq(expected)
      FieldArithmetic::{{ entry[0].id }}::NEGATED_MODULUS_INVERSE.should eq(MontgomeryArithmetic.negated_inverse_of_low_word(expected[0]))
    end
  {% end %}
end
