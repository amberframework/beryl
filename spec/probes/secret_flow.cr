# Entry points for the static constant-time check of the compiled code.
#
#     crystal build --release --emit llvm-ir -Dwithout_openssl spec/probes/secret_flow.cr -o secret_flow
#     ruby scripts/check_secret_flow.rb secret_flow.ll
#
# Each method below is kept out of line so that it survives optimization
# under a name the checker can find. Its `Bytes` arguments are the secrets;
# `scripts/check_secret_flow.rb` follows them through the optimized LLVM IR
# and reports any branch, table index or division that depends on one.
# `leaky_comparison`, `leaky_comparison_of_round_keys`,
# `leaky_table_selection` and `leaky_limb_lookup` are the faults the check
# exists to catch and must be reported.
require "../../src/beryl/crypto"
require "../support/wycheproof"

module SecretFlowProbe
  alias HMACSHA256 = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256)
  alias HMACSHA512 = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA512)

  @[NoInline]
  def self.keying_sha256(key : Bytes) : HMACSHA256
    HMACSHA256.new(key)
  end

  @[NoInline]
  def self.keying_sha512(key : Bytes) : HMACSHA512
    HMACSHA512.new(key)
  end

  @[NoInline]
  def self.authentication_tag(authentication : HMACSHA256, message : Bytes, tag : Bytes) : Nil
    authentication.update(message)
    authentication.final(tag)
  end

  @[NoInline]
  def self.verification(authentication : HMACSHA256, candidate_tag : Bytes) : Bool
    authentication.verify(candidate_tag)
  end

  @[NoInline]
  def self.truncated_verification(authentication : HMACSHA512, candidate_tag : Bytes) : Bool
    authentication.verify(candidate_tag, truncated_to_bytesize: 32)
  end

  @[NoInline]
  def self.key_derivation(input_key_material : Bytes, salt : Bytes) : Bytes
    Beryl::Crypto.derive_key(input_key_material, salt: salt, info: "purpose", bytesize: 80)
  end

  @[NoInline]
  def self.password_stretching(password : Bytes) : Bytes
    Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256).derive_key(
      password, salt: "salt", iteration_count: 3, bytesize: 40
    )
  end

  alias ChaCha20Poly1305 = Beryl::Crypto::V1::ChaCha20Poly1305
  alias XChaCha20Poly1305 = Beryl::Crypto::V1::XChaCha20Poly1305
  alias AESGCM = Beryl::Crypto::V1::AESGCM
  alias AESCBC = Beryl::Crypto::Compatibility::AESCBC
  alias BitslicedAES = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard

  @[NoInline]
  def self.chacha20_poly1305_keying(key : Bytes) : ChaCha20Poly1305
    ChaCha20Poly1305.new(key)
  end

  @[NoInline]
  def self.chacha20_poly1305_encryption(cipher : ChaCha20Poly1305, plaintext : Bytes, nonce : Bytes, sealed : Bytes) : Nil
    cipher.encrypt(plaintext, into: sealed, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.chacha20_poly1305_decryption(cipher : ChaCha20Poly1305, sealed : Bytes, nonce : Bytes, plaintext : Bytes) : Bool
    cipher.decrypt(sealed, into: plaintext, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.xchacha20_poly1305_keying(key : Bytes) : XChaCha20Poly1305
    XChaCha20Poly1305.new(key)
  end

  @[NoInline]
  def self.xchacha20_poly1305_encryption(cipher : XChaCha20Poly1305, plaintext : Bytes, nonce : Bytes, sealed : Bytes) : Nil
    cipher.encrypt(plaintext, into: sealed, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.xchacha20_poly1305_decryption(cipher : XChaCha20Poly1305, sealed : Bytes, nonce : Bytes, plaintext : Bytes) : Bool
    cipher.decrypt(sealed, into: plaintext, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.aes_gcm_keying(key : Bytes) : AESGCM
    AESGCM.new(key)
  end

  @[NoInline]
  def self.aes_gcm_encryption(cipher : AESGCM, plaintext : Bytes, nonce : Bytes, sealed : Bytes) : Nil
    cipher.encrypt(plaintext, into: sealed, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.aes_gcm_decryption(cipher : AESGCM, sealed : Bytes, nonce : Bytes, plaintext : Bytes) : Bool
    cipher.decrypt(sealed, into: plaintext, nonce: nonce, associated_data: "header")
  end

  @[NoInline]
  def self.aes_cbc_keying(key : Bytes) : AESCBC
    AESCBC.new(key)
  end

  @[NoInline]
  def self.aes_cbc_encryption(cipher : AESCBC, plaintext : Bytes, initialization_vector : Bytes) : Bytes
    cipher.encrypt(plaintext, initialization_vector: initialization_vector)
  end

  @[NoInline]
  def self.aes_cbc_decryption(cipher : AESCBC, ciphertext : Bytes, initialization_vector : Bytes) : Bytes?
    cipher.decrypt(ciphertext, initialization_vector: initialization_vector)
  end

  @[NoInline]
  def self.aes_block_decryption(round_keys : Slice(UInt64), round_count : Int32, input : Bytes, output : Bytes) : Nil
    BitslicedAES.decrypt_blocks(round_keys, round_count, input, output)
  end

  @[NoInline]
  def self.sealed_message(message : Bytes, key : Bytes) : Bytes
    Beryl::Crypto.encrypt(message, key: key)
  end

  @[NoInline]
  def self.opened_message(encrypted_message : Bytes, key : Bytes) : Bytes?
    Beryl::Crypto.decrypt(encrypted_message, key: key)
  end

  alias X25519 = Beryl::Crypto::V1::X25519
  alias Ed25519 = Beryl::Crypto::V1::Ed25519
  alias P256 = Beryl::Crypto::V1::P256

  @[NoInline]
  def self.x25519_public_key(secret : Bytes) : X25519::PublicKey
    X25519::PrivateKey.new(secret).public_key
  end

  @[NoInline]
  def self.x25519_key_agreement(secret : Bytes, peer : X25519::PublicKey) : Bytes?
    X25519::PrivateKey.new(secret).shared_secret(peer)
  end

  @[NoInline]
  def self.ed25519_signing(seed : Bytes, message : Bytes) : Bytes
    Ed25519::SigningKey.new(seed).sign(message)
  end

  @[NoInline]
  def self.p256_key_agreement(scalar : Bytes, peer : P256::PublicKey) : Bytes
    P256::PrivateKey.new(scalar).shared_secret(peer)
  end

  @[NoInline]
  def self.p256_signing(scalar : Bytes, message : Bytes) : Bytes
    P256::PrivateKey.new(scalar).sign(message, format: Beryl::Crypto::V1::SignatureFormat::FixedWidth)
  end

  @[NoInline]
  def self.p256_signing_in_der(scalar : Bytes, message : Bytes) : Bytes
    P256::PrivateKey.new(scalar).sign(message)
  end

  alias RSAPrivateKey = Beryl::Crypto::V1::RSA::PrivateKey

  # Every component is secret here, the modulus and public exponent too:
  # their size, low bit and value pass through Declassification.reveal.
  @[NoInline]
  def self.rsa_private_key_construction(modulus : Bytes, public_exponent : Bytes, private_exponent : Bytes,
                                        first_prime : Bytes, second_prime : Bytes, first_prime_exponent : Bytes,
                                        second_prime_exponent : Bytes, coefficient : Bytes) : RSAPrivateKey
    RSAPrivateKey.new(
      modulus: modulus, public_exponent: public_exponent, private_exponent: private_exponent,
      first_prime: first_prime, second_prime: second_prime, first_prime_exponent: first_prime_exponent,
      second_prime_exponent: second_prime_exponent, coefficient: coefficient,
    )
  end

  @[NoInline]
  def self.rsa_pkcs1_signing(private_key : RSAPrivateKey, message : Bytes) : Bytes
    private_key.sign_with_pkcs1(message, hash_function: Beryl::Crypto::V1::SHA256)
  end

  @[NoInline]
  def self.rsa_pss_signing(private_key : RSAPrivateKey, message : Bytes, salt : Bytes) : Bytes
    private_key.sign_with_pss_using_salt(message, salt, hash_function: Beryl::Crypto::V1::SHA384)
  end

  @[NoInline]
  def self.rsa_oaep_decryption(private_key : RSAPrivateKey, ciphertext : Bytes) : Bytes?
    private_key.decrypt_with_oaep(ciphertext, hash_function: Beryl::Crypto::Compatibility::SHA1)
  end

  @[NoInline]
  def self.rsa_oaep_decryption_with_label(private_key : RSAPrivateKey, ciphertext : Bytes, label : Bytes) : Bytes?
    private_key.decrypt_with_oaep(ciphertext, hash_function: Beryl::Crypto::V1::SHA256, label: label)
  end

  # Stops at the first round key word that is zero: a leak in the form
  # cipher code would have it, which the check must report as well.
  @[NoInline]
  def self.leaky_comparison_of_round_keys(round_keys : Slice(UInt64)) : Bool
    round_keys.size.times do |index|
      return false if round_keys[index] == 0_u64
    end
    true
  end

  # Picks a table entry by the low bits of a limb: the leak an unprotected
  # window lookup in curve code would have, on a field element passed by
  # value rather than through a Slice.
  @[NoInline]
  def self.leaky_limb_lookup(limbs : StaticArray(UInt64, 4)) : UInt64
    table = StaticArray(UInt64, 16).new { |index| index.to_u64 &* 0x9e3779b97f4a7c15_u64 }
    table[limbs[0] & 0xf_u64]
  end

  # Reads a table entry at an index taken from a secret exponent byte, the
  # fault a modular exponentiation without a full-table scan would have.
  @[NoInline]
  def self.leaky_table_selection(table : Slice(UInt64), exponent : Bytes) : UInt64
    table[exponent[0] & 0x0f_u8]
  end

  # Compares with an early exit: the textbook timing leak.
  @[NoInline]
  def self.leaky_comparison(first : Bytes, second : Bytes) : Bool
    first.size.times do |index|
      return false if first[index] != second[index]
    end
    true
  end
end

# Run everything once so that no entry point is dead code, on every hash so
# that every compression function is in the module.
key = Bytes.new(32) { |index| index.to_u8 }
tag = Bytes.new(32)
authentication = SecretFlowProbe.keying_sha256(key)
SecretFlowProbe.authentication_tag(authentication, key, tag)
authentication.reset.update(key)
is_verified = SecretFlowProbe.verification(authentication, tag)
long_authentication = SecretFlowProbe.keying_sha512(key)
is_verified &= !SecretFlowProbe.truncated_verification(long_authentication, tag)
derived_key = SecretFlowProbe.key_derivation(key, tag)
stretched_key = SecretFlowProbe.password_stretching(key)
is_verified &= SecretFlowProbe.leaky_comparison(tag, tag)

# The ciphers, once each so that every entry point is in the module.
nonce = Bytes.new(24) { |index| (index + 1).to_u8 }
plaintext = Bytes.new(100) { |index| (index &* 3).to_u8! }
sealed = Bytes.new(116)
opened = Bytes.new(100)

chacha20_poly1305 = SecretFlowProbe.chacha20_poly1305_keying(key)
SecretFlowProbe.chacha20_poly1305_encryption(chacha20_poly1305, plaintext, nonce[0, 12], sealed)
is_verified &= SecretFlowProbe.chacha20_poly1305_decryption(chacha20_poly1305, sealed, nonce[0, 12], opened)
is_verified &= opened == plaintext

xchacha20_poly1305 = SecretFlowProbe.xchacha20_poly1305_keying(key)
SecretFlowProbe.xchacha20_poly1305_encryption(xchacha20_poly1305, plaintext, nonce, sealed)
is_verified &= SecretFlowProbe.xchacha20_poly1305_decryption(xchacha20_poly1305, sealed, nonce, opened)
is_verified &= opened == plaintext

{16, 24, 32}.each do |key_bytesize|
  aes_gcm = SecretFlowProbe.aes_gcm_keying(key[0, key_bytesize])
  {12, 20}.each do |nonce_bytesize|
    SecretFlowProbe.aes_gcm_encryption(aes_gcm, plaintext, nonce[0, nonce_bytesize], sealed)
    is_verified &= SecretFlowProbe.aes_gcm_decryption(aes_gcm, sealed, nonce[0, nonce_bytesize], opened)
    is_verified &= opened == plaintext
  end

  aes_cbc = SecretFlowProbe.aes_cbc_keying(key[0, key_bytesize])
  ciphertext = SecretFlowProbe.aes_cbc_encryption(aes_cbc, plaintext, nonce[0, 16])
  is_verified &= SecretFlowProbe.aes_cbc_decryption(aes_cbc, ciphertext, nonce[0, 16]) == plaintext

  round_keys = Slice(UInt64).new(SecretFlowProbe::BitslicedAES::ROUND_KEY_WORD_COUNT, 0_u64)
  SecretFlowProbe::BitslicedAES.expand_key(key[0, key_bytesize], round_keys)
  SecretFlowProbe.aes_block_decryption(round_keys, key_bytesize // 4 + 6, ciphertext[0, 64], opened[0, 64])
  SecretFlowProbe.leaky_comparison_of_round_keys(round_keys)
end
is_verified &= SecretFlowProbe.leaky_table_selection(Slice(UInt64).new(16) { |index| index.to_u64 }, key) == key[0].to_u64 & 0x0f_u64

# The public-key operations on secret scalars, seeds and messages. The peer
# keys are built from public bytes outside the entry points.
x25519_peer = SecretFlowProbe.x25519_public_key(Bytes.new(32) { |index| (index * 7 + 1).to_u8 })
is_verified &= !SecretFlowProbe.x25519_key_agreement(key, x25519_peer).nil?
ed25519_signature = SecretFlowProbe.ed25519_signing(key, plaintext)
p256_peer = SecretFlowProbe::P256::PrivateKey.new(Bytes.new(32) { |index| (index + 9).to_u8 }).public_key
p256_shared = SecretFlowProbe.p256_key_agreement(key, p256_peer)
p256_signature = SecretFlowProbe.p256_signing(key, plaintext)
p256_signature_in_der = SecretFlowProbe.p256_signing_in_der(key, plaintext)
is_verified &= SecretFlowProbe.leaky_limb_lookup(StaticArray(UInt64, 4).new { |index| key[index].to_u64 }) != 1_u64
is_verified &= ed25519_signature.size == 64 && p256_shared.size == 32 && p256_signature.size == 64 && p256_signature_in_der.size >= 8

encrypted_message = SecretFlowProbe.sealed_message(plaintext, key)
is_verified &= SecretFlowProbe.opened_message(encrypted_message, key) == plaintext
# RSA: a 2,048-bit key from a Wycheproof file, signing with PKCS #1 v1.5 and
# PSS, and OAEP decryption of a good and a bad ciphertext.
# The public-key side (verification, encryption) is left out: its inputs are
# public and it may branch on them, which this check cannot know.
rsa_test_group = Wycheproof::TestFile(Wycheproof::RsaOaepTestGroup).from_json(
  File.read(Path[__DIR__].parent / "vectors/wycheproof/rsa_oaep_2048_sha1_mgf1sha1_test.json")
).list_of_test_groups.first
rsa_key = rsa_test_group.private_key
rsa_test = rsa_test_group.list_of_tests.first
rsa_private_key = SecretFlowProbe.rsa_private_key_construction(
  rsa_key.modulus.hexbytes, rsa_key.public_exponent.hexbytes, rsa_key.private_exponent.hexbytes,
  rsa_key.first_prime.hexbytes, rsa_key.second_prime.hexbytes, rsa_key.first_prime_exponent.hexbytes,
  rsa_key.second_prime_exponent.hexbytes, rsa_key.coefficient.hexbytes,
)
is_verified &= SecretFlowProbe.rsa_pkcs1_signing(rsa_private_key, plaintext).size == 256
is_verified &= SecretFlowProbe.rsa_pss_signing(rsa_private_key, plaintext, key).size == 256
rsa_ciphertext = rsa_test.ciphertext.hexbytes
is_verified &= SecretFlowProbe.rsa_oaep_decryption(rsa_private_key, rsa_ciphertext) == rsa_test.message.hexbytes
is_verified &= SecretFlowProbe.rsa_oaep_decryption_with_label(rsa_private_key, rsa_ciphertext, key).nil?

list_of_digests = [
  Beryl::Crypto::Compatibility::MD5.digest(key), Beryl::Crypto::Compatibility::SHA1.digest(key),
  Beryl::Crypto::V1::SHA224.digest(key), Beryl::Crypto::V1::SHA256.digest(key),
  Beryl::Crypto::V1::SHA384.digest(key), Beryl::Crypto::V1::SHA512.digest(key),
  Beryl::Crypto::V1::SHA512_256.digest(key),
]
STDOUT.puts "#{is_verified} #{derived_key.hexstring} #{stretched_key.hexstring} #{list_of_digests.map(&.hexstring).join(' ')}"
exit(is_verified ? 0 : 1)
