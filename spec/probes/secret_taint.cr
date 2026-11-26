# Constant-time check by memory checker (the ctgrind method,
# https://github.com/agl/ctgrind).
#
# Every secret this program handles (keys, messages, plaintexts, candidate
# tags, passwords, private scalars) is read from memory that was allocated and never written.
# Valgrind Memcheck tracks such bytes as undefined and reports any branch or
# memory address computed from them, so a clean run shows that no secret
# decided a branch or an index:
#
#     crystal build --release -Dgc_none -Dwithout_openssl -Dberyl_without_data_independent_timing \
#       spec/probes/secret_taint.cr -o secret_taint
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

# Returns *word_count* words that Memcheck treats as secret.
def secret_words(word_count : Int32) : Slice(UInt64)
  Slice(UInt64).new(LibC.malloc(word_count * 8).as(UInt64*), word_count)
end

# Returns *bytesize* bytes that Memcheck treats as secret.
def secret_bytes(bytesize : Int32) : Bytes
  Bytes.new(LibC.malloc(bytesize).as(UInt8*), bytesize)
end

# Memcheck's client requests MAKE_MEM_UNDEFINED and MAKE_MEM_DEFINED
# (valgrind/memcheck.h): the x86-64 and AArch64 instruction sequences
# Valgrind recognizes, which do nothing when the program runs outside it.
# The rotations add up to whole turns, so the register they turn is left
# as it was.
def memcheck_request(request : UInt64, pointer : Void*, bytesize : Int32) : Nil
  arguments = StaticArray[request, pointer.address, bytesize.to_u64, 0_u64, 0_u64, 0_u64]
  result = 0_u64
  {% if flag?(:x86_64) %}
    asm("rolq $$3, %rdi\nrolq $$13, %rdi\nrolq $$61, %rdi\nrolq $$51, %rdi\nxchgq %rbx, %rbx"
            : "={rdx}"(result) : "{rax}"(arguments.to_unsafe), "{rdx}"(0_u64) : "cc", "memory" : "volatile")
  {% elsif flag?(:aarch64) %}
    asm("ror x12, x12, #3\nror x12, x12, #13\nror x12, x12, #51\nror x12, x12, #61\norr x10, x10, x10"
            : "={x3}"(result) : "{x4}"(arguments.to_unsafe), "{x3}"(0_u64) : "cc", "memory" : "volatile")
  {% end %}
end

MEMCHECK_MAKE_MEM_UNDEFINED = 0x4D430001_u64
MEMCHECK_MAKE_MEM_DEFINED   = 0x4D430002_u64

# Returns a copy of *value* that Memcheck treats as secret: for a secret
# that must hold a particular value (a P-256 scalar must be below n).
def secret_copy_of(value : Bytes) : Bytes
  copy = value.dup
  memcheck_request(MEMCHECK_MAKE_MEM_UNDEFINED, copy.to_unsafe.as(Void*), copy.size)
  copy
end

# `Declassification.reveal` marks what it returns as public, which is what
# it means: the verdict or the signature is the caller's to see. Memcheck
# is told so; the compiled library code between the secret and the reveal
# is the same as in a normal build.
module Beryl::Crypto::Declassification
  @[NoInline]
  def self.reveal(padding_bytesize : UInt32) : UInt32
    revealed = padding_bytesize
    memcheck_request(MEMCHECK_MAKE_MEM_DEFINED, pointerof(revealed).as(Void*), sizeof(UInt32))
    revealed
  end

  @[NoInline]
  def self.reveal(published : Bytes) : Bytes
    memcheck_request(MEMCHECK_MAKE_MEM_DEFINED, published.to_unsafe.as(Void*), published.size)
    published
  end
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

# Which compression functions this run exercises (under Valgrind the
# processor's features are whatever Valgrind reports to the program).
STDOUT.puts "SHA instructions in use: SHA-1 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA1_INSTRUCTIONS}, " \
            "SHA-256 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA256_INSTRUCTIONS}, " \
            "SHA-512 #{Beryl::Crypto::ProcessorFeatures::HAS_SHA512_INSTRUCTIONS} " \
            "(compression: #{Beryl::Crypto::V1::SecureHashWith64BitWords.compression_in_use})"

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

# RSA. The private operation runs on primes, exponents, coefficient, modulus
# and input that are all secret (the modulus too, which only makes the check
# stricter); the steps that reveal something by design (the sizes and
# verdict of a key, the check with the public exponent, the OAEP verdict)
# are left out, as `exercise` leaves out the branch on a tag check. Sizes of
# 2,048, 3,072 and 4,096 bits, with primes of half the words each.
alias RSA = Beryl::Crypto::V1::RSA
{2_048, 3_072, 4_096}.each do |modulus_bit_count|
  modulus_word_count = modulus_bit_count // 64
  prime_word_count = modulus_word_count // 2
  modulus = RSA::OddModulus.new(secret_words(modulus_word_count), modulus_bit_count)
  first_prime = RSA::OddModulus.new(secret_words(prime_word_count), prime_word_count * 64)
  second_prime = RSA::OddModulus.new(secret_words(prime_word_count), prime_word_count * 64)
  result = Slice(UInt64).new(modulus_word_count)
  is_in_range = RSA::PrivateKey.exponentiate_by_chinese_remainder(result, secret_words(modulus_word_count), first_prime, second_prime,
    secret_bytes(prime_word_count * 8), secret_bytes(prime_word_count * 8), secret_words(prime_word_count), modulus)
  keep(result_storage, Bytes.new(result.to_unsafe.as(UInt8*), result.size * 8))
  keep(result_storage, is_in_range.to_u32!)

  # Reading a key component and comparing it with a prime.
  component, is_below = RSA::PrivateKey.read_component_below(secret_bytes(prime_word_count * 8 + 1), first_prime)
  keep(result_storage, component)
  keep(result_storage, is_below.to_u32!)

  # OAEP decoding of a secret encoded message, under SHA-1 and SHA-256.
  modulus_bytesize = modulus_bit_count // 8
  keep(result_storage, RSA::MessageEncoding.decode_oaep(Beryl::Crypto::Compatibility::SHA1, secret_bytes(modulus_bytesize),
    Beryl::Crypto::Compatibility::SHA1.digest(public_message), 1_u64))
  keep(result_storage, RSA::MessageEncoding.decode_oaep(Beryl::Crypto::V1::SHA256, secret_bytes(modulus_bytesize),
    Beryl::Crypto::V1::SHA256.digest(public_message), 1_u64))
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

# The public-key operations: secret scalars, seeds and messages; public
# peer keys. The build leaves the Data Independent Timing mode alone (see
# `ProcessorFeatures`), so `DataIndependentTiming.run` is only its block.
x25519_peer = Beryl::Crypto::V1::X25519::PrivateKey.new(Bytes.new(32) { |index| (index * 7 + 1).to_u8 }).public_key
x25519_key = Beryl::Crypto::V1::X25519::PrivateKey.new(secret_bytes(32))
keep(result_storage, x25519_key.public_key.to_slice)
keep(result_storage, x25519_key.shared_secret(x25519_peer) || Bytes.new(0))

ed25519_key = Beryl::Crypto::V1::Ed25519::SigningKey.new(secret_bytes(32))
keep(result_storage, ed25519_key.verification_key.to_slice)
keep(result_storage, ed25519_key.sign(public_message))
keep(result_storage, ed25519_key.sign(secret_bytes(200)))

p256_peer = Beryl::Crypto::V1::P256::PrivateKey.new(Bytes.new(32) { |index| (index + 9).to_u8 }).public_key
p256_key = Beryl::Crypto::V1::P256::PrivateKey.new(secret_copy_of(Bytes.new(32) { |index| (index * 5 + 3).to_u8 }))
keep(result_storage, p256_key.public_key.to_uncompressed)
keep(result_storage, p256_key.shared_secret(p256_peer))
keep(result_storage, p256_key.sign(public_message))
keep(result_storage, p256_key.sign(secret_bytes(100), format: Beryl::Crypto::V1::SignatureFormat::FixedWidth))

exit 0
