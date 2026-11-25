require "big"
require "./der_writer"
require "./rsa_key_components"

# Builds a certificate authority and server certificates in memory for the
# TLS specs, signed with Beryl's own keys. Nothing is read from disk, so no
# private key sits in the repository.
#
# The certificates follow the profile B4's `ChainVerification` enforces
# (version 3, positive serial, basic constraints and key usage critical,
# subject and authority key identifiers, subject alternative names).
module TestCertificateAuthority
  alias Certificates = Beryl::Certificates
  alias V1 = Beryl::Crypto::V1

  # The key kinds a test server certificate can carry.
  enum KeyKind
    P256
    Rsa2048
    Ed25519
  end

  # A certificate authority: its P-256 key and self-signed certificate.
  class Authority
    getter private_key : V1::P256::PrivateKey
    getter certificate : Certificates::Certificate
    getter common_name : String

    def initialize(@common_name : String = "Beryl Test Root", *, not_after : Time = Time.utc + 365.days)
      @private_key = V1::P256::PrivateKey.generate
      key_identifier = TestCertificateAuthority.key_identifier(@private_key.public_key.to_uncompressed)
      extensions = [
        TestCertificateAuthority.extension("2.5.29.19", true, DerWriter.sequence(DerWriter.element(0x01_u8, Bytes[0xFF]))),
        TestCertificateAuthority.extension("2.5.29.15", true, DerWriter.element(0x03_u8, Bytes[1, 0x06])),
        TestCertificateAuthority.extension("2.5.29.14", false, DerWriter.octet_string(key_identifier)),
      ]
      @certificate = TestCertificateAuthority.build(
        issuer_name: @common_name, subject_name: @common_name,
        subject_public_key_info: TestCertificateAuthority.p256_public_key_info(@private_key.public_key),
        extensions: extensions, not_before: Time.utc - 1.day, not_after: not_after,
        signer: @private_key)
    end

    def trust_store : Certificates::TrustStore
      Certificates::TrustStore.new([@certificate])
    end

    # Issues a server certificate for *list_of_dns_names* and
    # *list_of_ip_addresses* with a new key of *key_kind*; returns the
    # certified key (leaf then this authority's certificate).
    # *list_of_extended_key_usages* holds the purposes' object identifiers
    # (serverAuth unless given). With no name and no address the leaf has
    # no subject alternative name, and *subject_name* is its common name.
    def issue(key_kind : KeyKind = KeyKind::P256, *, list_of_dns_names : Array(String) = ["localhost"],
              list_of_ip_addresses : Array(Bytes) = [Bytes[127, 0, 0, 1]], not_before : Time = Time.utc - 1.day,
              not_after : Time = Time.utc + 30.days, key_usage : Bytes = Bytes[7, 0x80],
              list_of_extended_key_usages : Array(String) = [SERVER_AUTHENTICATION],
              subject_name : String? = nil) : Beryl::TLS::CertifiedKey
      private_key, public_key_info = TestCertificateAuthority.generate_key(key_kind)
      list_of_names = list_of_dns_names.map { |name| DerWriter.element(0x82_u8, name.to_slice) } +
                      list_of_ip_addresses.map { |address| DerWriter.element(0x87_u8, address) }
      extensions = [
        TestCertificateAuthority.extension("2.5.29.19", true, DerWriter.element(0x30_u8, Bytes.empty)),
        TestCertificateAuthority.extension("2.5.29.15", true, DerWriter.element(0x03_u8, key_usage)),
        TestCertificateAuthority.extension("2.5.29.37", false,
          DerWriter.element(0x30_u8, DerWriter.concat(list_of_extended_key_usages.map { |usage| DerWriter.object_identifier(usage) }))),
        TestCertificateAuthority.extension("2.5.29.35", false, DerWriter.sequence(DerWriter.element(0x80_u8,
          TestCertificateAuthority.key_identifier(@private_key.public_key.to_uncompressed)))),
      ]
      unless list_of_names.empty?
        extensions << TestCertificateAuthority.extension("2.5.29.17", false, DerWriter.element(0x30_u8, DerWriter.concat(list_of_names)))
      end
      leaf = TestCertificateAuthority.build(
        issuer_name: @common_name, subject_name: subject_name || list_of_dns_names.first? || "server",
        subject_public_key_info: public_key_info, extensions: extensions,
        not_before: not_before, not_after: not_after, signer: @private_key)
      Beryl::TLS::CertifiedKey.new([leaf, @certificate], private_key)
    end

    # Issues a client certificate (extended key usage clientAuth, no
    # subject alternative name) for *common_name*, with a new key of
    # *key_kind*.
    def issue_client(key_kind : KeyKind = KeyKind::P256, *, common_name : String = "client",
                     list_of_extended_key_usages : Array(String) = [CLIENT_AUTHENTICATION]) : Beryl::TLS::CertifiedKey
      issue(key_kind, list_of_dns_names: [] of String, list_of_ip_addresses: [] of Bytes,
        list_of_extended_key_usages: list_of_extended_key_usages, subject_name: common_name)
    end
  end

  # The serverAuth and clientAuth purposes (RFC 5280 §4.2.1.12).
  SERVER_AUTHENTICATION = "1.3.6.1.5.5.7.3.1"
  CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2"

  @@shared_rsa_key : V1::RSA::PrivateKey? = nil

  # Returns a new private key of *key_kind* and its SubjectPublicKeyInfo.
  # RSA keys take a moment to generate, so one RSA-2048 key is shared
  # across the specs.
  def self.generate_key(key_kind : KeyKind) : {Certificates::SigningKey, Bytes}
    case key_kind
    when KeyKind::P256
      key = V1::P256::PrivateKey.generate
      {key, p256_public_key_info(key.public_key)}
    when KeyKind::Ed25519
      key = V1::Ed25519::SigningKey.generate
      info = DerWriter.sequence(DerWriter.sequence(DerWriter.object_identifier("1.3.101.112")),
        DerWriter.element(0x03_u8, Bytes[0] + key.verification_key.to_slice))
      {key, info}
    else
      key = @@shared_rsa_key ||= generate_rsa_key(2048)
      modulus = RsaKeyComponents.bytes_of(@@rsa_modulus || raise "no modulus")
      rsa_public_key = DerWriter.sequence(DerWriter.integer(modulus), DerWriter.integer(Bytes[1, 0, 1]))
      info = DerWriter.sequence(DerWriter.sequence(DerWriter.object_identifier("1.2.840.113549.1.1.1"), DerWriter.element(0x05_u8, Bytes.empty)),
        DerWriter.element(0x03_u8, Bytes[0] + rsa_public_key))
      {key, info}
    end
  end

  @@rsa_modulus : BigInt? = nil

  # Generates an RSA key with e = 65537 from two random primes found by
  # trial division and 32 Miller-Rabin rounds.
  def self.generate_rsa_key(bit_count : Int32) : V1::RSA::PrivateKey
    exponent = BigInt.new(65_537)
    loop do
      first_prime = random_prime(bit_count // 2)
      second_prime = random_prime(bit_count // 2)
      next if first_prime == second_prime
      first_prime, second_prime = second_prime, first_prime if first_prime < second_prime
      modulus = first_prime * second_prime
      next unless modulus.bit_length == bit_count
      totient = (first_prime - 1) * (second_prime - 1)
      next unless exponent.gcd(totient) == 1
      private_exponent = modular_inverse(exponent, totient)
      @@rsa_modulus = modulus
      return V1::RSA::PrivateKey.new(
        modulus: RsaKeyComponents.bytes_of(modulus), public_exponent: 65_537,
        private_exponent: RsaKeyComponents.bytes_of(private_exponent),
        first_prime: RsaKeyComponents.bytes_of(first_prime), second_prime: RsaKeyComponents.bytes_of(second_prime),
        first_prime_exponent: RsaKeyComponents.bytes_of(private_exponent % (first_prime - 1)),
        second_prime_exponent: RsaKeyComponents.bytes_of(private_exponent % (second_prime - 1)),
        coefficient: RsaKeyComponents.bytes_of(modular_inverse(second_prime, first_prime)),
      )
    end
  end

  private SMALL_PRIMES = (3..2000).select { |candidate| (2..Math.sqrt(candidate).to_i).none? { |divisor| candidate % divisor == 0 } }

  private def self.random_prime(bit_count : Int32) : BigInt
    loop do
      bytes = Random::Secure.random_bytes(bit_count // 8)
      bytes[0] |= 0xC0
      bytes[-1] |= 1
      candidate = BigInt.new(bytes.hexstring, 16)
      next if SMALL_PRIMES.any? { |small| candidate % small == 0 }
      return candidate if probably_prime?(candidate)
    end
  end

  private def self.probably_prime?(candidate : BigInt) : Bool
    odd_part = candidate - 1
    halving_count = 0
    while odd_part.even?
      odd_part //= 2
      halving_count += 1
    end
    32.times do
      base = BigInt.new(Random::Secure.random_bytes(16).hexstring, 16) % (candidate - 3) + 2
      value = RsaKeyComponents.power_modulo(base, odd_part, candidate)
      next if value == 1 || value == candidate - 1
      is_witness = true
      (halving_count - 1).times do
        value = value * value % candidate
        if value == candidate - 1
          is_witness = false
          break
        end
      end
      return false if is_witness
    end
    true
  end

  private def self.modular_inverse(value : BigInt, modulus : BigInt) : BigInt
    old_remainder, remainder = value % modulus, modulus
    old_coefficient, coefficient = BigInt.new(1), BigInt.new(0)
    until remainder == 0
      quotient = old_remainder // remainder
      old_remainder, remainder = remainder, old_remainder - quotient * remainder
      old_coefficient, coefficient = coefficient, old_coefficient - quotient * coefficient
    end
    old_coefficient % modulus
  end

  def self.p256_public_key_info(public_key : V1::P256::PublicKey) : Bytes
    DerWriter.sequence(
      DerWriter.sequence(DerWriter.object_identifier("1.2.840.10045.2.1"), DerWriter.object_identifier("1.2.840.10045.3.1.7")),
      DerWriter.element(0x03_u8, Bytes[0] + public_key.to_uncompressed))
  end

  def self.key_identifier(public_key_bytes : Bytes) : Bytes
    V1::SHA256.digest(public_key_bytes)[0, 20]
  end

  def self.extension(identifier : String, is_critical : Bool, value : Bytes) : Bytes
    parts = [DerWriter.object_identifier(identifier)]
    parts << DerWriter.element(0x01_u8, Bytes[0xFF]) if is_critical
    parts << DerWriter.octet_string(value)
    DerWriter.element(0x30_u8, DerWriter.concat(parts))
  end

  def self.name(common_name : String) : Bytes
    attribute = DerWriter.sequence(DerWriter.object_identifier("2.5.4.3"), DerWriter.element(0x0C_u8, common_name.to_slice))
    DerWriter.sequence(DerWriter.element(0x31_u8, attribute))
  end

  def self.time(value : Time) : Bytes
    DerWriter.element(0x17_u8, value.to_s("%y%m%d%H%M%SZ").to_slice)
  end

  # Builds and signs (ECDSA P-256 with SHA-256) one certificate.
  def self.build(*, issuer_name : String, subject_name : String, subject_public_key_info : Bytes, extensions : Array(Bytes),
                 not_before : Time, not_after : Time, signer : V1::P256::PrivateKey) : Certificates::Certificate
    algorithm = DerWriter.sequence(DerWriter.object_identifier("1.2.840.10045.4.3.2"))
    serial = Random::Secure.random_bytes(16)
    serial[0] &= 0x7F
    serial[0] |= 0x01
    to_be_signed = DerWriter.sequence(
      DerWriter.context(0, DerWriter.small_integer(2)),
      DerWriter.integer(serial),
      algorithm,
      name(issuer_name),
      DerWriter.sequence(time(not_before), time(not_after)),
      name(subject_name),
      subject_public_key_info,
      DerWriter.context(3, DerWriter.element(0x30_u8, DerWriter.concat(extensions))),
    )
    signature = signer.sign(to_be_signed)
    Certificates::Certificate.new(DerWriter.sequence(to_be_signed, algorithm, DerWriter.element(0x03_u8, Bytes[0] + signature)))
  end
end
