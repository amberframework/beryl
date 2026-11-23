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

  LIST_OF_CASES = [
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
