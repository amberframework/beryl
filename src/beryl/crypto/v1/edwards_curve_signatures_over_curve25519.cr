require "random/secure"
require "../error"
require "../secret_wiping"
require "./secure_hash_with_512_bit_digest"
require "./edwards25519_group"

module Beryl::Crypto::V1
  # Ed25519 signatures (RFC 8032 §5.1), the pure variant without context.
  #
  # ```
  # signing_key = Beryl::Crypto::V1::Ed25519::SigningKey.generate
  # signature = signing_key.sign("a message")                   # 64 bytes
  # signing_key.verification_key.verify("a message", signature) # => true
  # ```
  #
  # Key generation and signing multiply the base point by a secret scalar
  # in constant time. Verification is variable time (every input is public)
  # and strict: it refuses S >= L and a public key whose encoding is not
  # canonical or not on the curve (RFC 8032 §5.1.7). It checks
  # [S]B = R + [k]A without the cofactor by comparing the encoding of
  # [S]B - [k]A with R, as ref10 and OpenSSL do; that encoding is always
  # canonical, so an R that is not is refused by the comparison itself.
  module EdwardsCurveSignaturesOverCurve25519
    SEED_BYTESIZE      = 32
    PUBLIC_BYTESIZE    = 32
    SIGNATURE_BYTESIZE = 64

    private alias Group = Edwards25519Group

    # A public key: the 32-byte encoding of A = [a]B.
    struct VerificationKey
      getter encoded : Bytes
      @point : Edwards25519Group::Point

      # Raises `InvalidPublicKey` when *encoded* is not 32 bytes or does not
      # decode to a point.
      def initialize(encoded : Bytes)
        unless encoded.size == PUBLIC_BYTESIZE
          raise InvalidPublicKey.new("an Ed25519 public key is #{PUBLIC_BYTESIZE} bytes, not #{encoded.size}")
        end
        point = Edwards25519Group::Point.decode(encoded)
        raise InvalidPublicKey.new("the bytes do not encode an Ed25519 public key") unless point
        @encoded = encoded.dup
        @point = point
      end

      def to_slice : Bytes
        @encoded.dup
      end

      # Returns whether *signature* is a valid signature of *message* under
      # this key.
      def verify(message : Bytes | String, signature : Bytes) : Bool
        return false unless signature.size == SIGNATURE_BYTESIZE

        encoded_r = signature[0, 32]
        encoded_s = signature[32, 32]
        return false unless Edwards25519Group::Scalar.canonical?(encoded_s)

        challenge = SHA512.new.update(encoded_r).update(@encoded).update(message.to_slice).final
        negated_challenge = Edwards25519Group::Scalar.encode(
          Beryl::Crypto::FieldArithmetic::Curve25519ScalarField.opp(Edwards25519Group::Scalar.reduce(challenge))
        )
        candidate_r = Edwards25519Group.multiply_and_add_public(encoded_s, @point, negated_challenge)
        candidate_r.encode == encoded_r
      end

      def ==(other : VerificationKey) : Bool
        @encoded == other.encoded
      end
    end

    # A private key: the 32-byte seed of RFC 8032 §5.1.5.
    class SigningKey
      @seed : Bytes
      @secret_scalar : Bytes
      @prefix : Bytes
      getter verification_key : VerificationKey

      # Returns a new signing key from `Random::Secure`.
      def self.generate : self
        seed = Bytes.new(SEED_BYTESIZE)
        Random::Secure.random_bytes(seed)
        key = new(seed)
        SecretWiping.wipe(seed)
        key
      end

      # Derives the key from a 32-byte *seed* (RFC 8032 §5.1.5).
      def initialize(seed : Bytes)
        unless seed.size == SEED_BYTESIZE
          raise KeySizeMismatch.new("an Ed25519 private key is #{SEED_BYTESIZE} bytes, not #{seed.size}")
        end
        @seed = seed.dup
        expanded = SHA512.digest(@seed)
        @secret_scalar = expanded[0, 32].dup
        @prefix = expanded[32, 32].dup
        SecretWiping.wipe(expanded)
        @secret_scalar[0] &= 248_u8
        @secret_scalar[31] &= 127_u8
        @secret_scalar[31] |= 64_u8
        @verification_key = VerificationKey.new(Edwards25519Group.multiply_base(@secret_scalar).encode)
      end

      # Returns the 64-byte signature R || S of *message* (RFC 8032 §5.1.6).
      def sign(message : Bytes | String) : Bytes
        message_bytes = message.to_slice
        nonce_hash = SHA512.new.update(@prefix).update(message_bytes).final
        nonce = Edwards25519Group::Scalar.reduce(nonce_hash)
        SecretWiping.wipe(nonce_hash)
        encoded_nonce = Edwards25519Group::Scalar.encode(nonce)
        encoded_r = Edwards25519Group.multiply_base(encoded_nonce).encode
        SecretWiping.wipe(encoded_nonce)

        challenge = SHA512.new.update(encoded_r).update(verification_key.encoded).update(message_bytes).final
        reduced_challenge = Edwards25519Group::Scalar.reduce(challenge)
        reduced_secret = Edwards25519Group::Scalar.reduce(@secret_scalar)
        encoded_s = Edwards25519Group::Scalar.encode(
          Edwards25519Group::Scalar.multiply_add(reduced_challenge, reduced_secret, nonce)
        )

        signature = Bytes.new(SIGNATURE_BYTESIZE)
        encoded_r.copy_to(signature[0, 32])
        encoded_s.copy_to(signature[32, 32])
        signature
      end

      # Returns a copy of the 32-byte seed.
      def to_slice : Bytes
        @seed.dup
      end

      def finalize
        SecretWiping.wipe(@seed)
        SecretWiping.wipe(@secret_scalar)
        SecretWiping.wipe(@prefix)
      end
    end
  end

  alias Ed25519 = EdwardsCurveSignaturesOverCurve25519
end
