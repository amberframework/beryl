require "./v1/secure_hash_with_224_bit_digest"
require "./v1/secure_hash_with_256_bit_digest"
require "./v1/secure_hash_with_384_bit_digest"
require "./v1/secure_hash_with_512_bit_digest"
require "./v1/secure_hash_with_512_bit_state_and_256_bit_digest"
require "./v1/hash_based_message_authentication_code"
require "./v1/hash_based_key_derivation_function"

# The first generation of Beryl's algorithms, each under a name that states
# what it is and a short alias that matches its common name:
#
# | Alias | Class | Standard |
# |---|---|---|
# | `SHA224` | `SecureHashWith224BitDigest` | FIPS 180-4 |
# | `SHA256` | `SecureHashWith256BitDigest` | FIPS 180-4 |
# | `SHA384` | `SecureHashWith384BitDigest` | FIPS 180-4 |
# | `SHA512` | `SecureHashWith512BitDigest` | FIPS 180-4 |
# | `SHA512_256` | `SecureHashWith512BitStateAnd256BitDigest` | FIPS 180-4 |
# | `HMAC(D)` | `HashBasedMessageAuthenticationCode(D)` | RFC 2104 |
# | `HKDF(D)` | `HashBasedKeyDerivationFunction(D)` | RFC 5869 |
#
# Code that must keep producing the same bytes names its algorithm here. Code
# that wants today's recommended choice calls `Beryl::Crypto.digest`,
# `Beryl::Crypto.authenticate` or `Beryl::Crypto.derive_key`, whose algorithm
# may move to a later generation.
module Beryl::Crypto::V1
end
