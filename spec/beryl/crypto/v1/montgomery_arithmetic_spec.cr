require "big"
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
          scratch = Slice(UInt64).new(2 * {{ word_count }} + 2)
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

  {% for word_count in [24, 32, 48, 64] %}
    it "squares as the Crystal multiplication of a number by itself does, {{ word_count }} words" do
      {% if flag?(:aarch64) && !flag?(:beryl_portable_rsa) %}
        random = Random::PCG32.new({{ word_count }}_u64 + 1)
        400.times do |trial|
          modulus = random_modulus(random, {{ word_count }})
          negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
          factor = random_below(random, modulus)
          # Every word all ones below the top makes the longest carries.
          if trial % 4 == 0
            factor = modulus.dup
            factor[0] -= 1
          end
          scratch = Slice(UInt64).new(2 * {{ word_count }} + 2)
          expected = Slice(UInt64).new({{ word_count }})
          MontgomeryArithmetic.multiply_{{ word_count }}(expected.to_unsafe, factor.to_unsafe, factor.to_unsafe,
            modulus.to_unsafe, negated_inverse, scratch.to_unsafe)
          from_assembly = Slice(UInt64).new({{ word_count }})
          MontgomeryMultiplicationInAssembly.square_{{ word_count }}(from_assembly.to_unsafe, factor.to_unsafe, modulus.to_unsafe,
            negated_inverse, scratch.to_unsafe)
          from_assembly.should eq(expected)

          # The result may overwrite the factor.
          MontgomeryMultiplicationInAssembly.square_{{ word_count }}(factor.to_unsafe, factor.to_unsafe, modulus.to_unsafe,
            negated_inverse, scratch.to_unsafe)
          factor.should eq(expected)
        end
      {% end %}
    end

    it "multiplies factors of every word all ones, and an unreduced first factor, {{ word_count }} words" do
      {% if flag?(:aarch64) && !flag?(:beryl_portable_rsa) %}
        random = Random::PCG32.new({{ word_count }}_u64 + 2)
        200.times do |trial|
          modulus = random_modulus(random, {{ word_count }})
          modulus.map! { |word| word | 0xffffffff00000000_u64 } if trial.odd?
          negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
          second_factor = modulus.dup
          second_factor[0] -= 1
          first_factor = trial % 3 == 0 ? Slice(UInt64).new({{ word_count }}, UInt64::MAX) : second_factor.dup
          scratch = Slice(UInt64).new(2 * {{ word_count }} + 2)
          expected = Slice(UInt64).new({{ word_count }})
          MontgomeryArithmetic.multiply_{{ word_count }}(expected.to_unsafe, first_factor.to_unsafe, second_factor.to_unsafe,
            modulus.to_unsafe, negated_inverse, scratch.to_unsafe)
          from_assembly = Slice(UInt64).new({{ word_count }})
          MontgomeryMultiplicationInAssembly.multiply_{{ word_count }}(from_assembly.to_unsafe, first_factor.to_unsafe,
            second_factor.to_unsafe, modulus.to_unsafe, negated_inverse, scratch.to_unsafe)
          from_assembly.should eq(expected)
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

describe "Beryl::Crypto::V1::MontgomeryArithmetic.select_table_entry" do
  it "copies the entry asked for, for every entry and every specialized word count" do
    random = Random::PCG32.new(16_u64)
    {16, 24, 32, 48, 64}.each do |word_count|
      table = random_words(random, MontgomeryArithmetic::TABLE_ENTRY_COUNT * word_count)
      selected = Slice(UInt64).new(word_count)
      MontgomeryArithmetic::TABLE_ENTRY_COUNT.times do |entry|
        MontgomeryArithmetic.select_table_entry(selected, table, entry.to_u64, word_count)
        selected.should eq(table[entry * word_count, word_count])
      end
    end
  end
end

describe "Beryl::Crypto::V1::MontgomeryArithmetic.compute_r_squared" do
  it "gives R² mod m for moduli of every bit length within their top word" do
    random = Random::PCG32.new(65_u64)
    {1, 2, 16, 17, 24, 32, 33, 48, 64}.each do |word_count|
      20.times do |trial|
        modulus = random_words(random, word_count)
        modulus[0] |= 1_u64
        top_bit = trial % 64
        modulus[word_count - 1] &= (1_u64 << top_bit) | ((1_u64 << top_bit) &- 1_u64)
        modulus[word_count - 1] |= 1_u64 << top_bit
        bit_count = 64 * (word_count - 1) + top_bit + 1
        next if bit_count < 2
        negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
        result = Slice(UInt64).new(word_count)
        MontgomeryArithmetic.compute_r_squared(result, modulus, bit_count, negated_inverse,
          Slice(UInt64).new(MontgomeryArithmetic.multiplication_scratch_word_count(word_count)))
        big_modulus = modulus.to_a.reverse.reduce(BigInt.new(0)) { |sum, word| (sum << 64) + word }
        expected = (BigInt.new(1) << (128 * word_count)) % big_modulus
        result.to_a.reverse.reduce(BigInt.new(0)) { |sum, word| (sum << 64) + word }.should eq(expected)
      end
    end
  end
end

describe "Beryl::Crypto::V1::MontgomeryArithmetic.exponentiate_by_public_exponent" do
  it "gives base^e mod m on both paths, with and without the correction R^e" do
    random = Random::PCG32.new(65537_u64)
    {16, 24, 32, 48, 64}.each do |word_count|
      {3_u64, 65537_u64, 0xffffffff_u64}.each do |exponent|
        5.times do
          modulus = random_modulus(random, word_count)
          negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(modulus[0])
          base = random_below(random, modulus)
          scratch = Slice(UInt64).new(MontgomeryArithmetic.public_exponentiation_scratch_word_count(word_count))
          r_squared = Slice(UInt64).new(word_count)
          MontgomeryArithmetic.compute_r_squared(r_squared, modulus, 64 * word_count, negated_inverse, scratch[word_count, 2 * word_count + 2])
          correction = Slice(UInt64).new(word_count)
          MontgomeryArithmetic.compute_public_exponent_correction(correction, exponent, modulus, r_squared, negated_inverse, scratch)
          plain = Slice(UInt64).new(word_count)
          MontgomeryArithmetic.exponentiate_by_public_exponent(plain, base, exponent, modulus, r_squared, negated_inverse, scratch)
          corrected = Slice(UInt64).new(word_count)
          MontgomeryArithmetic.exponentiate_by_public_exponent_with_correction(corrected, base, exponent, modulus, correction,
            negated_inverse, scratch)
          to_big = ->(words : Slice(UInt64)) { words.to_a.reverse.reduce(BigInt.new(0)) { |sum, word| (sum << 64) + word } }
          big_modulus = to_big.call(modulus)
          expected = BigInt.new(1)
          63.downto(0) do |bit|
            expected = expected * expected % big_modulus
            expected = expected * to_big.call(base) % big_modulus if (exponent >> bit) & 1 == 1
          end
          to_big.call(plain).should eq(expected)
          to_big.call(corrected).should eq(expected)
        end
      end
    end
  end
end
