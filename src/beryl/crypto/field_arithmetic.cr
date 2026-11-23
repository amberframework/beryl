require "./field_arithmetic/curve25519_field"
require "./field_arithmetic/curve25519_scalar_field"
require "./field_arithmetic/p256_field"
require "./field_arithmetic/p256_scalar_field"
require "./field_arithmetic/p384_field"
require "./field_arithmetic/p384_scalar_field"

# :nodoc:
#
# Field arithmetic for the curves, generated from fiat-crypto by
# `scripts/generate_field_arithmetic.rb`. Everything here is internal:
# callers use the curves in `Beryl::Crypto::V1`.
module Beryl::Crypto::FieldArithmetic
end
