# The field functions written in assembly (src/beryl/crypto/field_arithmetic/
# fields_in_assembly.cr), each checked against fiat-crypto's own C for the
# function it replaces, on inputs inside fiat-crypto's input bounds (every
# value of every limb) drawn as for the translations.
module AssemblyEquality
  macro equality_case(module_name, function_name, c_function, word_count, argument_count)
    { {{ module_name.stringify }}, {{ function_name.stringify }}, ->(count : Int64, draw : InputDraw) do
      differences = 0_i64
      first_argument = StaticArray(UInt64, {{ word_count }}).new(0_u64)
      second_argument = StaticArray(UInt64, {{ word_count }}).new(0_u64)
      count.times do
        {{ word_count }}.times do |index|
          first_argument[index] = draw.next_within(0_u64, UInt64::MAX)
          second_argument[index] = draw.next_within(0_u64, UInt64::MAX)
        end
        from_c = StaticArray(UInt64, {{ word_count }}).new(0_u64)
        {% if argument_count == 2 %}
          from_assembly = Beryl::Crypto::FieldArithmetic::{{ module_name }}.{{ function_name }}(first_argument, second_argument)
          LibFiatCryptoC.{{ c_function }}(from_c.to_unsafe, first_argument.to_unsafe, second_argument.to_unsafe)
        {% else %}
          from_assembly = Beryl::Crypto::FieldArithmetic::{{ module_name }}.{{ function_name }}(first_argument)
          LibFiatCryptoC.{{ c_function }}(from_c.to_unsafe, first_argument.to_unsafe)
        {% end %}
        differences += 1 unless from_assembly == from_c
      end
      differences
    end }
  end

  # `P256FieldWithAssembly.half` has no fiat-crypto function of its own:
  # its result r for an input a below p (the only inputs the curve code
  # gives it) is checked by fiat-crypto's C `add`, which must give back a
  # from r + r, and against the portable Crystal halving bit for bit.
  macro halving_case
    {"P256FieldWithAssembly", "half", ->(count : Int64, draw : InputDraw) do
      differences = 0_i64
      prime = Beryl::Crypto::FieldArithmetic::P256FieldWithAssembly::PRIME_WORDS
      argument = StaticArray(UInt64, 4).new(0_u64)
      count.times do
        loop do
          4.times { |index| argument[index] = draw.next_within(0_u64, UInt64::MAX) }
          is_below_prime = false
          3.downto(0) do |index|
            next if argument[index] == prime[index]
            is_below_prime = argument[index] < prime[index]
            break
          end
          break if is_below_prime
        end
        halved = Beryl::Crypto::FieldArithmetic::P256FieldWithAssembly.half(argument)
        doubled = StaticArray(UInt64, 4).new(0_u64)
        LibFiatCryptoC.p256_64_add(doubled.to_unsafe, halved.to_unsafe, halved.to_unsafe)
        portable = Beryl::Crypto::FieldArithmetic::FieldsInAssembly.half_portable(argument, prime)
        differences += 1 unless doubled == argument && portable == halved
      end
      differences
    end}
  end

  # The value below p = 2^255 - 19 that four 64-bit words stand for, as 32
  # bytes, by fiat-crypto's C: the words become five 51-bit limbs (the top
  # one 52 bits, inside fiat-crypto's loose bounds), `carry` makes them
  # tight and `to_bytes` canonical.
  def self.canonical_bytes_of_words(words : StaticArray(UInt64, 4)) : StaticArray(UInt8, 32)
    limbs = StaticArray(UInt64, 5).new(0_u64)
    mask = (1_u64 << 51) - 1
    limbs[0] = words[0] & mask
    limbs[1] = ((words[0] >> 51) | (words[1] << 13)) & mask
    limbs[2] = ((words[1] >> 38) | (words[2] << 26)) & mask
    limbs[3] = ((words[2] >> 25) | (words[3] << 39)) & mask
    limbs[4] = words[3] >> 12
    tight = StaticArray(UInt64, 5).new(0_u64)
    LibFiatCryptoC.curve25519_64_carry(tight.to_unsafe, limbs.to_unsafe)
    bytes = StaticArray(UInt8, 32).new(0_u8)
    LibFiatCryptoC.curve25519_64_to_bytes(bytes.to_unsafe, tight.to_unsafe)
    bytes
  end

  # Five tight 51-bit limbs of the value of four words, for fiat-crypto's C.
  def self.tight_limbs_of_words(words : StaticArray(UInt64, 4)) : StaticArray(UInt64, 5)
    bytes = canonical_bytes_of_words(words)
    limbs = StaticArray(UInt64, 5).new(0_u64)
    LibFiatCryptoC.curve25519_64_from_bytes(limbs.to_unsafe, bytes.to_unsafe)
    limbs
  end

  # `Curve25519SolinasFieldWithAssembly`'s addition, subtraction and
  # multiplication by 121666, which fiat-crypto's Solinas output does not
  # have: each variant must return the portable Crystal's words bit for bit,
  # and those words must stand for what fiat-crypto's C `curve25519_64`
  # `add`, `sub` or `carry_scmul_121666` gives modulo p.
  macro solinas_reference_case(variant, function_name, argument_count)
  { "Curve25519SolinasFieldWithAssembly::{{ variant.id }}", {{ function_name.stringify }}, ->(count : Int64, draw : InputDraw) do
    differences = 0_i64
    first_argument = StaticArray(UInt64, 4).new(0_u64)
    second_argument = StaticArray(UInt64, 4).new(0_u64)
    count.times do
      4.times do |index|
        first_argument[index] = draw.next_within(0_u64, UInt64::MAX)
        second_argument[index] = draw.next_within(0_u64, UInt64::MAX)
      end
      first_limbs = AssemblyEquality.tight_limbs_of_words(first_argument)
      expected_limbs = StaticArray(UInt64, 5).new(0_u64)
      {% if argument_count == 2 %}
        from_variant = Beryl::Crypto::FieldArithmetic::Curve25519SolinasFieldWithAssembly::{{ variant.id }}.{{ function_name }}(first_argument, second_argument)
        from_portable = Beryl::Crypto::FieldArithmetic::Curve25519SolinasFieldWithAssembly::Portable.{{ function_name }}(first_argument, second_argument)
        second_limbs = AssemblyEquality.tight_limbs_of_words(second_argument)
        loose_limbs = StaticArray(UInt64, 5).new(0_u64)
        LibFiatCryptoC.curve25519_64_{{ function_name }}(loose_limbs.to_unsafe, first_limbs.to_unsafe, second_limbs.to_unsafe)
        LibFiatCryptoC.curve25519_64_carry(expected_limbs.to_unsafe, loose_limbs.to_unsafe)
      {% else %}
        from_variant = Beryl::Crypto::FieldArithmetic::Curve25519SolinasFieldWithAssembly::{{ variant.id }}.{{ function_name }}(first_argument)
        from_portable = Beryl::Crypto::FieldArithmetic::Curve25519SolinasFieldWithAssembly::Portable.{{ function_name }}(first_argument)
        LibFiatCryptoC.curve25519_64_carry_{{ function_name }}(expected_limbs.to_unsafe, first_limbs.to_unsafe)
      {% end %}
      expected_bytes = StaticArray(UInt8, 32).new(0_u8)
      LibFiatCryptoC.curve25519_64_to_bytes(expected_bytes.to_unsafe, expected_limbs.to_unsafe)
      differences += 1 unless from_variant == from_portable && AssemblyEquality.canonical_bytes_of_words(from_variant) == expected_bytes
    end
    differences
  end }
end

  # The `Curve25519SolinasFieldWithAssembly` variants this processor runs,
  # each with `mul` and `square` against fiat-crypto's C and the rest
  # against the reference.
  {% begin %}
    {%
      list_of_variants = ["Portable"]
      list_of_variants << "AArch64" if flag?(:aarch64)
      list_of_variants << "X86WithMultiply" if flag?(:x86_64)
      list_of_variants << "X86WithWideMultiply" if flag?(:x86_64) && !flag?(:beryl_without_mulx)
    %}
    SOLINAS_CASES = [
      {% for variant in list_of_variants %}
        equality_case(Curve25519SolinasFieldWithAssembly::{{ variant.id }}, mul, curve25519_solinas_64_mul, 4, 2),
        equality_case(Curve25519SolinasFieldWithAssembly::{{ variant.id }}, square, curve25519_solinas_64_square, 4, 1),
        solinas_reference_case({{ variant }}, add, 2),
        solinas_reference_case({{ variant }}, sub, 2),
        solinas_reference_case({{ variant }}, scmul_121666, 1),
      {% end %}
    ]
  {% end %}

  # The x86-64 P-256 multiplication's two forms, each against fiat-crypto's
  # C whichever one `mul` picks on this processor.
  {% if flag?(:x86_64) && !flag?(:beryl_portable_curves) %}
    P256_FORM_CASES = [
      equality_case(P256FieldWithAssembly, mul_with_multiply, p256_64_mul, 4, 2),
      {% if !flag?(:beryl_without_mulx) %}
        equality_case(P256FieldWithAssembly, mul_with_wide_multiply, p256_64_mul, 4, 2),
        equality_case(P256FieldWithAssembly, square_with_wide_multiply, p256_64_square, 4, 1),
      {% end %}
    ]
  {% else %}
    P256_FORM_CASES = [] of {String, String, Proc(Int64, InputDraw, Int64)}
  {% end %}

  LIST_OF_CASES = SOLINAS_CASES + P256_FORM_CASES + [
    halving_case,
    equality_case(P256FieldWithAssembly, mul, p256_64_mul, 4, 2),
    equality_case(P256FieldWithAssembly, square, p256_64_square, 4, 1),
    equality_case(P256FieldWithAssembly, add, p256_64_add, 4, 2),
    equality_case(P256FieldWithAssembly, sub, p256_64_sub, 4, 2),
    equality_case(P256FieldWithAssembly, opp, p256_64_opp, 4, 1),
    equality_case(P256ScalarFieldWithAssembly, mul, p256_scalar_64_mul, 4, 2),
    equality_case(P256ScalarFieldWithAssembly, square, p256_scalar_64_square, 4, 1),
    equality_case(P384FieldWithAssembly, mul, p384_64_mul, 6, 2),
    equality_case(P384FieldWithAssembly, square, p384_64_square, 6, 1),
    equality_case(P384ScalarFieldWithAssembly, mul, p384_scalar_64_mul, 6, 2),
    equality_case(P384ScalarFieldWithAssembly, square, p384_scalar_64_square, 6, 1),
  ]
end
