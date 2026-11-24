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

  LIST_OF_CASES = [
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
