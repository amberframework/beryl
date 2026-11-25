# Spec-only views of the buffers each AEAD derives from its key, and of the
# AEAD a TLS record protection holds, so specs can show that `wipe` zeroes
# them.
class Beryl::Crypto::V1::AdvancedEncryptionStandardInGaloisCounterMode
  def list_of_key_material_for_spec : Array(Bytes)
    [
      Bytes.new(@round_keys.to_unsafe.as(UInt8*), @round_keys.bytesize),
      Bytes.new(@hash_key_state.to_unsafe.as(UInt8*), @hash_key_state.bytesize),
      @round_key_bytes,
      @hash_key_powers,
    ]
  end
end

class Beryl::Crypto::V1::AuthenticatedEncryptionWithChaCha20AndPoly1305
  def list_of_key_material_for_spec : Array(Bytes)
    [@key]
  end
end

class Beryl::Crypto::V1::AuthenticatedEncryptionWithExtendedNonceChaCha20AndPoly1305
  def list_of_key_material_for_spec : Array(Bytes)
    [@key]
  end
end

class Beryl::TLS::RecordProtection
  def authenticated_encryption_for_spec : Beryl::Crypto::V1::AuthenticatedEncryption
    @authenticated_encryption
  end
end
