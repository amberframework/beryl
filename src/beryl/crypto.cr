require "./crypto/error"
require "./crypto/v1"
require "./crypto/compatibility"

# Cryptography written in Crystal.
#
# The calls on this module always use the algorithm Beryl recommends today:
#
# ```
# Beryl::Crypto.digest("contents of a file")                             # SHA-256
# tag = Beryl::Crypto.authenticate("message", key: secret_key)           # HMAC-SHA256
# Beryl::Crypto.verify_authentication("message", tag, key: secret_key)   # => true
# Beryl::Crypto.derive_key(shared_secret, info: "cookies", bytesize: 32) # HKDF-SHA256
# ```
#
# `Beryl::Crypto::V1` names each algorithm exactly, for code that must keep
# producing the same bytes. `Beryl::Crypto::Compatibility` holds MD5, SHA-1
# and PBKDF2 for formats that require them.
module Beryl::Crypto
  # Returns the SHA-256 digest of *data* (32 bytes).
  def self.digest(data : Bytes | String) : Bytes
    V1::SHA256.digest(data)
  end

  # Returns the HMAC-SHA256 authentication tag of *message* under *key*
  # (32 bytes).
  def self.authenticate(message : Bytes | String, *, key : Bytes | String) : Bytes
    V1::HMAC(V1::SHA256).authenticate(message, key: key)
  end

  # Returns whether *authentication_tag* is the HMAC-SHA256 tag of *message*
  # under *key*. The comparison runs in constant time.
  def self.verify_authentication(message : Bytes | String, authentication_tag : Bytes, *, key : Bytes | String) : Bool
    V1::HMAC(V1::SHA256).verify(message, authentication_tag, key: key)
  end

  # Returns *bytesize* bytes of key derived from *input_key_material* with
  # HKDF-SHA256. *info* names the purpose, so that different purposes get
  # unrelated keys; *salt* is optional and need not be secret.
  def self.derive_key(
    input_key_material : Bytes | String,
    *,
    salt : Bytes | String = Bytes.empty,
    info : Bytes | String = Bytes.empty,
    bytesize : Int32 = 32,
  ) : Bytes
    V1::HKDF(V1::SHA256).derive_key(input_key_material, salt: salt, info: info, bytesize: bytesize)
  end
end
