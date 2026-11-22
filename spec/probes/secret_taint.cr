# Constant-time check by memory checker (the ctgrind method,
# https://github.com/agl/ctgrind).
#
# Every secret this program handles (keys, messages, candidate tags,
# passwords) is read from memory that was allocated and never written.
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

# Compares with an early exit: the textbook timing leak.
def leaky_equal?(first : Bytes, second : Bytes) : Bool
  first.size.times do |index|
    return false if first[index] != second[index]
  end
  true
end

# Which compression functions this run exercises (under Valgrind the
# processor's features are whatever Valgrind reports to the program).
STDOUT.puts "SHA instructions in use: SHA-1 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA1_INSTRUCTIONS}, " \
            "SHA-256 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA256_INSTRUCTIONS}, " \
            "SHA-512 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA512_INSTRUCTIONS}"

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

exit 0
