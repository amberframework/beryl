module Beryl::Crypto::V1::RivestShamirAdleman
  # :nodoc:
  #
  # An odd modulus (an RSA modulus or one of its primes) with the values
  # Montgomery arithmetic needs for it, computed once: R² mod m and
  # -m⁻¹ mod 2^64. Building one runs in time that depends only on the word
  # count, so a prime's value does not show; its bit length does (see
  # `Declassification.reveal(public_value : UInt64)`).
  struct OddModulus
    getter words : Slice(UInt64)
    getter r_squared : Slice(UInt64)
    getter negated_inverse : UInt64
    getter bit_count : Int32

    # Reads the big-endian *bytes* (leading zero bytes allowed) and returns
    # the modulus, sized to its bit length.
    def self.from_bytes(bytes : Bytes) : OddModulus
      wide_words = Slice(UInt64).new(Math.max(1, MontgomeryArithmetic.word_count_for(bytes.size)))
      MontgomeryArithmetic.decode_big_endian(bytes, wide_words)
      bit_count = Declassification.reveal(MontgomeryArithmetic.bit_length(wide_words)).to_i32
      words = Slice(UInt64).new(Math.max(1, (bit_count + 63) // 64))
      wide_words[0, words.size].copy_to(words)
      SecretWiping.wipe(Bytes.new(wide_words.to_unsafe.as(UInt8*), wide_words.size * 8))
      new(words, bit_count)
    end

    # Takes *words* (little-endian) as the modulus; *bit_count* is its bit
    # length. The modulus must be odd for the arithmetic to be right; the
    # time taken does not depend on it.
    def initialize(@words : Slice(UInt64), @bit_count : Int32)
      @negated_inverse = MontgomeryArithmetic.negated_inverse_of_low_word(@words[0])
      @r_squared = Slice(UInt64).new(@words.size)
      MontgomeryArithmetic.compute_r_squared(@r_squared, @words, @negated_inverse, scratch_of(2 * @words.size + 2))
    end

    def word_count : Int32
      @words.size
    end

    # The number of bytes that hold any value below the modulus.
    def bytesize : Int32
      (@bit_count + 7) // 8
    end

    # Sets *result* to the Montgomery form of *value*, of any length.
    def reduce_to_montgomery_form(result : Slice(UInt64), value : Slice(UInt64)) : Nil
      scratch = scratch_of(3 * word_count + 2)
      MontgomeryArithmetic.reduce_to_montgomery_form(result, value, @words, @r_squared, @negated_inverse, scratch)
      wipe(scratch)
    end

    # Sets *result* to the Montgomery form of base^exponent, given the
    # Montgomery form of the base, in time independent of the exponent's
    # value.
    def exponentiate(result : Slice(UInt64), base_in_montgomery_form : Slice(UInt64), exponent : Bytes) : Nil
      scratch = scratch_of(MontgomeryArithmetic.exponentiation_scratch_word_count(word_count))
      MontgomeryArithmetic.exponentiate(result, base_in_montgomery_form, exponent, @words, @r_squared, @negated_inverse, scratch)
    end

    # Sets *result* to base^exponent mod m for a public exponent.
    def exponentiate_by_public_exponent(result : Slice(UInt64), base : Slice(UInt64), exponent : UInt64) : Nil
      scratch = scratch_of(3 * word_count)
      MontgomeryArithmetic.exponentiate_by_public_exponent(result, base, exponent, @words, @r_squared, @negated_inverse, scratch)
      wipe(scratch)
    end

    # Sets *value* from Montgomery form to plain form.
    def leave_montgomery_form(value : Slice(UInt64)) : Nil
      scratch = scratch_of(2 * word_count + 2)
      MontgomeryArithmetic.leave_montgomery_form(value, @words, @negated_inverse, scratch)
      wipe(scratch)
    end

    # Sets *result* to a·b/R mod m (*b* below m).
    def multiply(result : Slice(UInt64), a : Slice(UInt64), b : Slice(UInt64)) : Nil
      scratch = scratch_of(word_count + 2)
      MontgomeryArithmetic.multiply(result, a, b, @words, @negated_inverse, scratch)
      wipe(scratch)
    end

    # Sets *result* to (a - b) mod m (both below m).
    def subtract(result : Slice(UInt64), a : Slice(UInt64), b : Slice(UInt64)) : Nil
      MontgomeryArithmetic.subtract(result, a, b, @words)
    end

    # Overwrites the modulus and its precomputed values.
    def wipe : Nil
      wipe(@words)
      wipe(@r_squared)
    end

    private def scratch_of(word_count : Int32) : Slice(UInt64)
      Slice(UInt64).new(word_count)
    end

    private def wipe(words : Slice(UInt64)) : Nil
      SecretWiping.wipe(Bytes.new(words.to_unsafe.as(UInt8*), words.size * 8))
    end
  end
end
