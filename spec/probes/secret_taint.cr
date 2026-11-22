# Constant-time check by memory checker (the ctgrind method,
# https://github.com/agl/ctgrind).
#
# Every secret this program handles (keys, messages, plaintexts, candidate
# tags, passwords) is read from memory that was allocated and never written.
# Valgrind Memcheck tracks such bytes as undefined and reports any branch or
# memory address computed from them, so a clean run shows that no secret
# decided a branch or an index:
#
#     crystal build --release -Dgc_none -Dwithout_openssl spec/probes/secret_taint.cr -o secret_taint
#     valgrind --error-exitcode=99 ./secret_taint          # must exit 0
#     valgrind --error-exitcode=99 ./secret_taint leaky    # must exit 99
#
# The second run compares secrets with an early exit, which is exactly the
# fault this check exists to catch; it proves the detector is awake.
#
# `-Dgc_none` keeps the garbage collector, which scans memory without regard
# for what is defined, out of the report. Linux only: Valgrind does not run
# on macOS arm64.
require "../../src/beryl/crypto"

# Returns *bytesize* bytes that Memcheck treats as secret.
def secret_bytes(bytesize : Int32) : Bytes
  Bytes.new(LibC.malloc(bytesize).as(UInt8*), bytesize)
end

# Stores a result that depends on secrets where the optimizer must keep it,
# without branching on it.
def keep(result_storage : Bytes, result : Bytes) : Nil
  result.copy_to(result_storage[0, result.size])
end

def keep(result_storage : Bytes, result : Bool) : Nil
  result_storage.to_unsafe.as(Bool*).value = result
end

def keep(result_storage : Bytes, result : UInt32) : Nil
  result_storage.to_unsafe.as(UInt32*).value = result
end

# Compares with an early exit: the textbook timing leak.
def leaky_equal?(first : Bytes, second : Bytes) : Bool
  first.size.times do |index|
    return false if first[index] != second[index]
  end
  true
end

result_storage = Bytes.new(16_384)
public_message = "a message everyone may read".to_slice

if ARGV.first? == "leaky"
  keep(result_storage, leaky_equal?(secret_bytes(32), secret_bytes(32)))
  exit 0
end

# Hashes of a secret message, at lengths on both sides of the padding split.
{% for hash in %w[Beryl::Crypto::Compatibility::MD5 Beryl::Crypto::Compatibility::SHA1
                 Beryl::Crypto::V1::SHA224 Beryl::Crypto::V1::SHA256 Beryl::Crypto::V1::SHA384
                 Beryl::Crypto::V1::SHA512 Beryl::Crypto::V1::SHA512_256] %}
  {0, 1, 55, 56, 64, 111, 112, 128, 300}.each do |bytesize|
    keep(result_storage, {{ hash.id }}.new.update(secret_bytes(bytesize)).final)
  end

  # HMAC under a secret key shorter than, equal to and longer than the block.
  {0, 20, 64, 128, 200}.each do |key_bytesize|
    authentication = Beryl::Crypto::V1::HMAC({{ hash.id }}).new(secret_bytes(key_bytesize))
    authentication.update(public_message)
    authentication.update(secret_bytes(100))
    keep(result_storage, authentication.final)

    # verify: a secret candidate of the right length, then of the wrong one.
    digest_bytesize = authentication.digest_size
    authentication.reset.update(public_message)
    keep(result_storage, authentication.verify(secret_bytes(digest_bytesize)))
    authentication.reset.update(public_message)
    keep(result_storage, authentication.verify(secret_bytes(digest_bytesize - 1)))
    authentication.reset.update(public_message)
    keep(result_storage, authentication.verify(secret_bytes(digest_bytesize // 2 + 2), truncated_to_bytesize: digest_bytesize // 2 + 2))
  end
{% end %}

# The convenience calls.
keep(result_storage, Beryl::Crypto.digest(secret_bytes(77)))
keep(result_storage, Beryl::Crypto.authenticate(secret_bytes(77), key: secret_bytes(32)))
keep(result_storage, Beryl::Crypto.verify_authentication(public_message, secret_bytes(32), key: secret_bytes(32)))
keep(result_storage, Beryl::Crypto.derive_key(secret_bytes(32), salt: secret_bytes(16), info: public_message, bytesize: 100))

# HKDF: secret input key material and salt, public info and length.
{% for hash in %w[Beryl::Crypto::Compatibility::SHA1 Beryl::Crypto::V1::SHA256
                 Beryl::Crypto::V1::SHA384 Beryl::Crypto::V1::SHA512] %}
  pseudorandom_key = Beryl::Crypto::V1::HKDF({{ hash.id }}).extract(secret_bytes(48), salt: secret_bytes(20))
  keep(result_storage, Beryl::Crypto::V1::HKDF({{ hash.id }}).expand(pseudorandom_key, info: public_message, bytesize: 300))
  keep(result_storage, Beryl::Crypto::V1::HKDF({{ hash.id }}).derive_key(secret_bytes(48), info: public_message, bytesize: 70))
{% end %}

# PBKDF2: secret password, public salt, iteration count and length.
{% for hash in %w[Beryl::Crypto::Compatibility::SHA1 Beryl::Crypto::V1::SHA256 Beryl::Crypto::V1::SHA512] %}
  keep(result_storage, Beryl::Crypto::Compatibility::PBKDF2({{ hash.id }}).derive_key(
    secret_bytes(24), salt: public_message, iteration_count: 5, bytesize: 150
  ))
{% end %}

# The ciphers. Keys, plaintexts and candidate messages are secret; nonces,
# associated data and every length are public. Lengths sit on both sides of
# each block size (16 bytes for AES, GHASH and Poly1305, 64 for ChaCha20 and
# one AES pass).
LIST_OF_MESSAGE_BYTESIZES = {0, 1, 15, 16, 17, 63, 64, 65, 200}
public_nonce = Bytes.new(24) { |index| (index + 1).to_u8 }

# Runs encryption and the tag check of one cipher. `decrypt` itself is the
# tag check, then one branch on its verdict (the verdict is the return
# value, see `Beryl::Crypto::Declassification`), then the same keystream
# pass that encryption runs; the two halves run here with nothing revealed.
def exercise(result_storage : Bytes, cipher : Beryl::Crypto::V1::AuthenticatedEncryption, nonce : Bytes, associated_data : Bytes) : Nil
  LIST_OF_MESSAGE_BYTESIZES.each do |bytesize|
    keep(result_storage, cipher.encrypt(secret_bytes(bytesize), nonce: nonce, associated_data: associated_data))
    keep(result_storage, cipher.authentic?(secret_bytes(bytesize + cipher.tag_bytesize), nonce: nonce, associated_data: associated_data))
  end
end

exercise(result_storage, Beryl::Crypto::V1::ChaCha20Poly1305.new(secret_bytes(32)), public_nonce[0, 12], public_message)
exercise(result_storage, Beryl::Crypto::V1::XChaCha20Poly1305.new(secret_bytes(32)), public_nonce, public_message)
{16, 24, 32}.each do |key_bytesize|
  exercise(result_storage, Beryl::Crypto::V1::AESGCM.new(secret_bytes(key_bytesize)), public_nonce[0, 12], public_message)
  # A nonce of another length goes through GHASH under the secret hash key.
  exercise(result_storage, Beryl::Crypto::V1::AESGCM.new(secret_bytes(key_bytesize), tag_bytesize: 12), public_nonce[0, 20], public_message)
end

# The convenience call (its nonce is random, and public).
keep(result_storage, Beryl::Crypto.encrypt(secret_bytes(77), key: secret_bytes(32), associated_data: public_message))

# The AES block cipher in both directions, and CBC with its padding check.
{16, 24, 32}.each do |key_bytesize|
  round_keys = Slice(UInt64).new(Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_WORD_COUNT, 0_u64)
  Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.expand_key(secret_bytes(key_bytesize), round_keys)
  round_count = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.round_count_for(key_bytesize)
  {16, 48, 64, 80}.each do |bytesize|
    encrypted = Bytes.new(bytesize)
    Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.encrypt_blocks(round_keys, round_count, secret_bytes(bytesize), encrypted)
    keep(result_storage, encrypted)
    decrypted = Bytes.new(bytesize)
    Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.decrypt_blocks(round_keys, round_count, secret_bytes(bytesize), decrypted)
    keep(result_storage, decrypted)

    padded_plaintext = Bytes.new(bytesize)
    Beryl::Crypto::Compatibility::CipherBlockChaining.decrypt(round_keys, round_count, public_nonce[0, 16], secret_bytes(bytesize), padded_plaintext)
    keep(result_storage, Beryl::Crypto::Compatibility::CipherBlockChaining.padding_bytesize(padded_plaintext[bytesize - 16, 16]))
  end

  cipher = Beryl::Crypto::Compatibility::AESCBC.new(secret_bytes(key_bytesize))
  LIST_OF_MESSAGE_BYTESIZES.each do |bytesize|
    keep(result_storage, cipher.encrypt(secret_bytes(bytesize), initialization_vector: public_nonce[0, 16]))
  end
end

# Poly1305 and GHASH on their own, under secret keys.
LIST_OF_MESSAGE_BYTESIZES.each do |bytesize|
  tag = Bytes.new(16)
  Beryl::Crypto::V1::Poly1305OneTimeAuthenticator.authenticate(secret_bytes(32), secret_bytes(bytesize), tag)
  keep(result_storage, tag)

  hash_state = Slice(UInt64).new(Beryl::Crypto::V1::GaloisHash::STATE_WORD_COUNT, 0_u64)
  Beryl::Crypto::V1::GaloisHash.load_key(hash_state, secret_bytes(16))
  Beryl::Crypto::V1::GaloisHash.absorb(hash_state, secret_bytes(bytesize))
  Beryl::Crypto::V1::GaloisHash.write_digest(hash_state, tag)
  keep(result_storage, tag)
end

exit 0
