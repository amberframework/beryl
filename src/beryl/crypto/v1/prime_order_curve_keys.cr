require "random/secure"
require "../error"
require "../secret_wiping"
require "../declassification"
require "../data_independent_timing"
require "../constant_time_selection"
require "./deterministic_signature_nonce"
require "./elliptic_curve_signature_encoding"

module Beryl::Crypto::V1
  # :nodoc:
  #
  # Writes `PublicKey` (ECDSA verification) and, when *with_private_key* is
  # true, `PrivateKey` (key generation, ECDSA signing, ECDH) into the module
  # it is called in, on the curve arithmetic *arithmetic* (a module made by
  # `define_prime_order_curve_arithmetic`) with *hash* as the curve's
  # signature hash.
  macro define_prime_order_curve_keys(arithmetic, hash, curve_name, with_private_key)
    # A public key: a point of the curve other than the point at infinity.
    struct PublicKey
      @point : {{ arithmetic }}::Point

      # Decodes a SEC 1 point (uncompressed 0x04 || X || Y, or compressed
      # 0x02/0x03 || X). Raises `InvalidPublicKey` for anything that is not
      # a point of {{ curve_name.id }} or is the point at infinity.
      def initialize(encoded : Bytes)
        point = {{ arithmetic }}.decode_point(encoded)
        raise InvalidPublicKey.new("the bytes do not encode a {{ curve_name.id }} public key") unless point
        @point = point
      end

      # :nodoc:
      def initialize(@point : {{ arithmetic }}::Point)
      end

      # :nodoc:
      def point : {{ arithmetic }}::Point
        @point
      end

      # Returns 0x04 || X || Y.
      def to_uncompressed : Bytes
        {{ arithmetic }}.encode_uncompressed(@point)
      end

      # Returns 0x02 || X or 0x03 || X.
      def to_compressed : Bytes
        {{ arithmetic }}.encode_compressed(@point)
      end

      def to_slice : Bytes
        to_uncompressed
      end

      def ==(other : PublicKey) : Bool
        to_uncompressed == other.to_uncompressed
      end

      # Returns whether *signature* is an ECDSA signature by this key of
      # *message* hashed with {{ hash.id }}.
      def verify(message : Bytes | String, signature : Bytes, *, format : SignatureFormat = SignatureFormat::DER) : Bool
        verify_digest({{ hash }}.digest(message.to_slice), signature, format: format)
      end

      # Returns whether *signature* is an ECDSA signature by this key of a
      # message whose hash is *digest* (any hash; FIPS 186-5 §6.4.2 takes
      # its leftmost bits).
      def verify_digest(digest : Bytes, signature : Bytes, *, format : SignatureFormat = SignatureFormat::DER) : Bool
        decoded = EllipticCurveSignatureEncoding.decode(signature, format, {{ arithmetic }}::BYTESIZE)
        return false unless decoded
        encoded_r, encoded_s = decoded
        order = {{ arithmetic }}::GROUP_ORDER
        {encoded_r, encoded_s}.each do |component|
          return false if component.all?(&.zero?)
          return false unless {{ arithmetic }}.below_bit(component, order) == 1
        end

        scalar_field = {{ arithmetic }}::ScalarField
        digest_integer = scalar_field.to_montgomery({{ arithmetic }}.reduce_once_modulo_order({{ arithmetic }}.digest_to_integer(digest)))
        r = scalar_field.to_montgomery({{ arithmetic }}.limbs_from_big_endian(encoded_r))
        s = scalar_field.to_montgomery({{ arithmetic }}.limbs_from_big_endian(encoded_s))
        inverse_s = {{ arithmetic }}.scalar_power(s, {{ arithmetic }}.scalar_inverse_exponent)
        first_scalar = {{ arithmetic }}.limbs_to_big_endian(scalar_field.from_montgomery(scalar_field.mul(digest_integer, inverse_s)))
        second_scalar = {{ arithmetic }}.limbs_to_big_endian(scalar_field.from_montgomery(scalar_field.mul(r, inverse_s)))

        candidate = {{ arithmetic }}.multiply_and_add_public(first_scalar, @point, second_scalar)
        return false if {{ arithmetic }}.neutral_bit(candidate) == 1

        {{ arithmetic }}.limbs_to_big_endian({{ arithmetic }}.x_coordinate_modulo_order(candidate)) == encoded_r
      end
    end

    {% if with_private_key %}
      # A private key: a secret scalar d in [1, n - 1].
      class PrivateKey
        @scalar : Bytes
        getter public_key : PublicKey

        # Returns a new key drawn from `Random::Secure` by rejection sampling
        # (FIPS 186-5 Appendix A.2.2).
        def self.generate : self
          candidate = Bytes.new({{ arithmetic }}::BYTESIZE)
          loop do
            Random::Secure.random_bytes(candidate)
            if Declassification.reveal(DataIndependentTiming.run { PrivateKey.in_range_bit(candidate) } == 1)
              key = new(candidate)
              SecretWiping.wipe(candidate)
              return key
            end
          end
        end

        # :nodoc:
        def self.in_range_bit(scalar : Bytes) : UInt64
          is_nonzero = ConstantTimeSelection.all_zero_bit(scalar) ^ 1_u64
          is_nonzero & {{ arithmetic }}.below_bit(scalar, {{ arithmetic }}::GROUP_ORDER)
        end

        # Keeps a copy of the big-endian scalar *scalar*. Raises
        # `KeySizeMismatch` for the wrong length and `InvalidPrivateKey`
        # for zero or a value not below n.
        def initialize(scalar : Bytes)
          unless scalar.size == {{ arithmetic }}::BYTESIZE
            raise KeySizeMismatch.new("a {{ curve_name.id }} private key is #{{{ arithmetic }}::BYTESIZE} bytes, not #{scalar.size}")
          end
          unless Declassification.reveal(DataIndependentTiming.run { PrivateKey.in_range_bit(scalar) } == 1)
            raise InvalidPrivateKey.new("a {{ curve_name.id }} private key must be between 1 and the group order minus 1")
          end
          @scalar = scalar.dup
          @public_key = DataIndependentTiming.run { PublicKey.new({{ arithmetic }}.multiply_generator(@scalar)) }
        end

        # Returns the ECDSA signature of *message* hashed with
        # {{ hash.id }}, with the RFC 6979 nonce.
        def sign(message : Bytes | String, *, format : SignatureFormat = SignatureFormat::DER) : Bytes
          sign_digest({{ hash }}.digest(message.to_slice), {{ hash }}, format: format)
        end

        # Returns the ECDSA signature of a message whose hash, computed with
        # *hash_function*, is *digest*; the RFC 6979 nonce uses HMAC with
        # the same hash.
        def sign_digest(digest : Bytes, hash_function : D.class, *, format : SignatureFormat = SignatureFormat::DER) : Bytes forall D
          DataIndependentTiming.run do
            digest_integer = {{ arithmetic }}.limbs_to_big_endian({{ arithmetic }}.reduce_once_modulo_order({{ arithmetic }}.digest_to_integer(digest)))
            nonce = DeterministicSignatureNonce(D).generate(@scalar, digest_integer, {{ arithmetic }}::GROUP_ORDER)
            signature = sign_with_nonce(digest, nonce, format: format)
            SecretWiping.wipe(nonce)
            signature
          end
        end

        # :nodoc:
        #
        # Signs with a given nonce, for the published vectors that fix k.
        # Raises when r or s comes out zero (probability about 2^-256).
        def sign_with_nonce(digest : Bytes, nonce : Bytes, *, format : SignatureFormat = SignatureFormat::DER) : Bytes
          DataIndependentTiming.run do
            scalar_field = {{ arithmetic }}::ScalarField
            r_limbs = {{ arithmetic }}.x_coordinate_modulo_order({{ arithmetic }}.multiply_generator(nonce))
            encoded_r = {{ arithmetic }}.limbs_to_big_endian(r_limbs)
            r = scalar_field.to_montgomery(r_limbs)
            digest_integer = scalar_field.to_montgomery({{ arithmetic }}.reduce_once_modulo_order({{ arithmetic }}.digest_to_integer(digest)))
            private_scalar = scalar_field.to_montgomery({{ arithmetic }}.limbs_from_big_endian(@scalar))
            nonce_scalar = scalar_field.to_montgomery({{ arithmetic }}.limbs_from_big_endian(nonce))
            inverse_nonce = {{ arithmetic }}.scalar_power(nonce_scalar, {{ arithmetic }}.scalar_inverse_exponent)
            s = scalar_field.mul(inverse_nonce, scalar_field.add(digest_integer, scalar_field.mul(r, private_scalar)))
            encoded_s = {{ arithmetic }}.limbs_to_big_endian(scalar_field.from_montgomery(s))
            has_zero_component = ConstantTimeSelection.all_zero_bit(encoded_r) | ConstantTimeSelection.all_zero_bit(encoded_s)
            if Declassification.reveal(has_zero_component == 1)
              raise Error.new("ECDSA produced a zero signature component; sign again with another nonce")
            end

            EllipticCurveSignatureEncoding.encode(Declassification.reveal(encoded_r), Declassification.reveal(encoded_s), format)
          end
        end

        # Returns the ECDH shared secret with *peer*: the x coordinate of
        # [d]Q, {{ arithmetic }}::BYTESIZE big-endian bytes (SEC 1 §3.3.1;
        # RFC 9846 §7.4.2). *peer* was checked to be on the curve when it
        # was decoded, and the group has prime order, so the result is never
        # the point at infinity.
        def shared_secret(peer : PublicKey) : Bytes
          DataIndependentTiming.run do
            multiples = {{ arithmetic }}.multiples_of(peer.point)
            product = {{ arithmetic }}.multiply_constant_time(@scalar, multiples)
            x, _ = {{ arithmetic }}.to_affine(product)
            {{ arithmetic }}.field_element_to_big_endian(x)
          end
        end

        # Returns a copy of the big-endian scalar.
        def to_slice : Bytes
          @scalar.dup
        end

        def finalize
          SecretWiping.wipe(@scalar)
        end
      end
    {% end %}
  end
end
