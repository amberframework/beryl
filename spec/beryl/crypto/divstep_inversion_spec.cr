require "../../spec_helper"

private alias P256Arithmetic = Beryl::Crypto::V1::P256::Arithmetic
private alias Curve25519FieldElement = Beryl::Crypto::V1::Curve25519FieldElement

# A random value below the big-endian *modulus*, as big-endian bytes.
private def random_below(modulus : Bytes, random : Random) : Bytes
  loop do
    candidate = random.random_bytes(modulus.size)
    return candidate if Beryl::Crypto::ConstantTimeSelection.big_endian_less_than_bit(candidate, modulus) == 1
  end
end

# Edge values below the big-endian *modulus*: 0, 1, 2, modulus - 1 and
# modulus - 2.
private def edge_values(modulus : Bytes) : Array(Bytes)
  list_of_values = [0, 1, 2].map { |small| Bytes.new(modulus.size) { |index| index == modulus.size - 1 ? small.to_u8 : 0_u8 } }
  list_of_values << P256Arithmetic.big_endian_minus_small(modulus, 1_u8)
  list_of_values << P256Arithmetic.big_endian_minus_small(modulus, 2_u8)
  list_of_values
end

describe Beryl::Crypto::FieldArithmetic::DivstepInversion do
  random = Random.new(20261123)

  it "inverts modulo the P-256 field prime exactly as Fermat's exponent p - 2 does" do
    list_of_values = edge_values(P256Arithmetic::FIELD_PRIME) + Array.new(20_000) { random_below(P256Arithmetic::FIELD_PRIME, random) }
    list_of_values.each do |encoded|
      element = P256Arithmetic.field_element_from_big_endian(encoded)
      P256Arithmetic.field_invert(element).should eq(P256Arithmetic.field_power(element, P256Arithmetic.field_inverse_exponent))
    end
  end

  it "inverts modulo the P-256 group order exactly as Fermat's exponent n - 2 does" do
    scalar_field = P256Arithmetic::ScalarField
    list_of_values = edge_values(P256Arithmetic::GROUP_ORDER) + Array.new(20_000) { random_below(P256Arithmetic::GROUP_ORDER, random) }
    list_of_values.each do |encoded|
      element = scalar_field.to_montgomery(P256Arithmetic.limbs_from_big_endian(encoded))
      P256Arithmetic.scalar_invert(element).should eq(P256Arithmetic.scalar_power(element, P256Arithmetic.scalar_inverse_exponent))
    end
  end

  it "inverts modulo 2^255 - 19 exactly as Fermat's exponent p - 2 does" do
    prime = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed".hexbytes
    exponent = P256Arithmetic.big_endian_minus_small(prime, 2_u8)
    list_of_values = edge_values(prime) + Array.new(20_000) { random_below(prime, random) }
    list_of_values.each do |big_endian|
      element = Curve25519FieldElement.from_bytes(big_endian.dup.reverse!)
      power = Curve25519FieldElement.one
      (exponent.size * 8 - 1).downto(0) do |position|
        power = power.square
        power *= element if P256Arithmetic.exponent_bit(exponent, position) == 1
      end
      element.invert.to_bytes.should eq(power.to_bytes)
    end
  end
end
