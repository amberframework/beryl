# Entry points for the static constant-time check of the compiled code.
#
#     crystal build --release --emit llvm-ir -Dwithout_openssl spec/probes/secret_flow.cr -o secret_flow
#     ruby scripts/check_secret_flow.rb secret_flow.ll
#
# Each method below is kept out of line so that it survives optimization
# under a name the checker can find. Its `Bytes` arguments are the secrets;
# `scripts/check_secret_flow.rb` follows them through the optimized LLVM IR
# and reports any branch, table index or division that depends on one.
# `leaky_comparison` is the fault the check exists to catch and must be
# reported.
require "../../src/beryl/crypto"

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

list_of_digests = [
  Beryl::Crypto::Compatibility::MD5.digest(key), Beryl::Crypto::Compatibility::SHA1.digest(key),
  Beryl::Crypto::V1::SHA224.digest(key), Beryl::Crypto::V1::SHA256.digest(key),
  Beryl::Crypto::V1::SHA384.digest(key), Beryl::Crypto::V1::SHA512.digest(key),
  Beryl::Crypto::V1::SHA512_256.digest(key),
]
STDOUT.puts "#{is_verified} #{derived_key.hexstring} #{stretched_key.hexstring} #{list_of_digests.map(&.hexstring).join(' ')}"
exit(is_verified ? 0 : 1)
