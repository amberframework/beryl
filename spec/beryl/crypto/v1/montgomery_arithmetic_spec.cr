require "../../../spec_helper"

private alias MontgomeryArithmetic = Beryl::Crypto::V1::MontgomeryArithmetic
private alias MontgomeryMultiplicationInAssembly = Beryl::Crypto::V1::MontgomeryMultiplicationInAssembly

# Random words from a seeded generator, so a failure replays.
private def random_words(random : Random, word_count : Int32) : Slice(UInt64)
  Slice(UInt64).new(word_count) { random.next_u.to_u64 << 32 | random.next_u }
end

# A random odd modulus with its top bit set, and a number below it.
private def random_modulus(random : Random, word_count : Int32) : Slice(UInt64)
  modulus = random_words(random, word_count)
  modulus[0] |= 1_u64
  modulus[word_count - 1] |= 1_u64 << 63
  modulus
end

private def random_below(random : Random, modulus : Slice(UInt64)) : Slice(UInt64)
  value = random_words(random, modulus.size)
  value[modulus.size - 1] &= modulus[modulus.size - 1] >> 1
  value
end

describe "Beryl::Crypto::V1::MontgomeryMultiplicationInAssembly" do
  {% for word_count in [16, 24, 32, 48, 64] %}
    it "returns what the Crystal multiplication returns, {{ word_count }} words" do
      {% if flag?(:aarch64) && !flag?(:beryl_portable_rsa) %}
        random = Random::PCG32.new({{ word_count }}_u64)
        200.times do
          modulus = random_modulus(random, {{ word_count }})
          negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
          first_factor = random_below(random, modulus)
          second_factor = random_below(random, modulus)
          scratch = Slice(UInt64).new({{ word_count }} + 2)
          expected = Slice(UInt64).new({{ word_count }})
          MontgomeryArithmetic.multiply_{{ word_count }}(expected.to_unsafe, first_factor.to_unsafe, second_factor.to_unsafe,
            modulus.to_unsafe, negated_inverse, scratch.to_unsafe)

          from_assembly = Slice(UInt64).new({{ word_count }})
          {% if word_count == 16 %}
            MontgomeryMultiplicationInAssembly.multiply_16(from_assembly.to_unsafe, first_factor.to_unsafe, second_factor.to_unsafe,
              modulus.to_unsafe, negated_inverse)
          {% else %}
            MontgomeryMultiplicationInAssembly.multiply_{{ word_count }}(from_assembly.to_unsafe, first_factor.to_unsafe,
              second_factor.to_unsafe, modulus.to_unsafe, negated_inverse, scratch.to_unsafe)
          {% end %}
          from_assembly.should eq(expected)

          # The result may overwrite the first factor.
          {% if word_count == 16 %}
            MontgomeryMultiplicationInAssembly.multiply_16(first_factor.to_unsafe, first_factor.to_unsafe, second_factor.to_unsafe,
              modulus.to_unsafe, negated_inverse)
          {% else %}
            MontgomeryMultiplicationInAssembly.multiply_{{ word_count }}(first_factor.to_unsafe, first_factor.to_unsafe,
              second_factor.to_unsafe, modulus.to_unsafe, negated_inverse, scratch.to_unsafe)
          {% end %}
          first_factor.should eq(expected)
        end
      {% end %}
    end
  {% end %}
end

describe "Beryl::Crypto::V1::MontgomeryArithmetic.square" do
  it "returns what the multiplication of a number by itself returns" do
    random = Random::PCG32.new(2048_u64)
    {16, 24, 32, 48, 64}.each do |word_count|
      100.times do
        modulus = random_modulus(random, word_count)
        negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
        factor = random_below(random, modulus)
        scratch = Slice(UInt64).new(2 * word_count + 2)
        expected = Slice(UInt64).new(word_count)
        MontgomeryArithmetic.multiply(expected, factor, factor, modulus, negated_inverse, scratch)
        MontgomeryArithmetic.square(factor, factor, modulus, negated_inverse, scratch)
        factor.should eq(expected)
      end
    end
  end

  it "reduces the largest number below the modulus, whose square carries furthest" do
    random = Random::PCG32.new(4096_u64)
    100.times do
      modulus = random_modulus(random, 16)
      negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
      factor = modulus.dup
      factor[0] -= 1
      scratch = Slice(UInt64).new(34)
      expected = Slice(UInt64).new(16)
      MontgomeryArithmetic.multiply(expected, factor, factor, modulus, negated_inverse, scratch)
      MontgomeryArithmetic.square(factor, factor, modulus, negated_inverse, scratch)
      factor.should eq(expected)
    end
  end
end
