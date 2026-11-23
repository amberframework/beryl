require "big"

# Builds RSA keys for the specs from the components a vector file carries,
# and maps the vector files' hash names to Beryl's hash classes.
module RsaKeyComponents
  alias RSA = Beryl::Crypto::V1::RSA

  # The eight components of RFC 8017 §3.2, big-endian.
  record Components, modulus : Bytes, public_exponent : Bytes, private_exponent : Bytes, first_prime : Bytes,
    second_prime : Bytes, first_prime_exponent : Bytes, second_prime_exponent : Bytes, coefficient : Bytes do
    def private_key : RSA::PrivateKey
      RSA::PrivateKey.new(
        modulus: modulus, public_exponent: public_exponent, private_exponent: private_exponent,
        first_prime: first_prime, second_prime: second_prime, first_prime_exponent: first_prime_exponent,
        second_prime_exponent: second_prime_exponent, coefficient: coefficient,
      )
    end
  end

  @@recovered_by_modulus = {} of String => Components

  # Returns the components of a Wycheproof key; a key that gives only n, e
  # and d (the signature-generation files) has its primes recovered.
  def self.from_wycheproof(key : Wycheproof::RsaKey) : Components
    return recover(key.modulus, key.public_exponent, key.private_exponent) if key.first_prime.empty?

    Components.new(key.modulus.hexbytes, key.public_exponent.hexbytes, key.private_exponent.hexbytes,
      key.first_prime.hexbytes, key.second_prime.hexbytes, key.first_prime_exponent.hexbytes,
      key.second_prime_exponent.hexbytes, key.coefficient.hexbytes)
  end

  # Recovers p and q from n, e and d (hexadecimal) by the method of NIST
  # SP 800-56B Rev. 2 Appendix C.2: d·e - 1 = 2^t·r with r odd; for a base
  # g, the sequence g^r, g^2r, ... mod n reaches 1, and the value just
  # before it, when it is not ±1, is a square root of 1 that shares a
  # factor with n. Then builds the remaining components with BigInt.
  def self.recover(modulus_hex : String, public_exponent_hex : String, private_exponent_hex : String) : Components
    @@recovered_by_modulus[modulus_hex] ||= begin
      modulus = BigInt.new(modulus_hex, 16)
      public_exponent = BigInt.new(public_exponent_hex, 16)
      private_exponent = BigInt.new(private_exponent_hex, 16)
      first_prime = recover_factor(modulus, public_exponent, private_exponent)
      second_prime = modulus // first_prime
      first_prime, second_prime = second_prime, first_prime if first_prime < second_prime
      Components.new(
        bytes_of(modulus), bytes_of(public_exponent), bytes_of(private_exponent), bytes_of(first_prime),
        bytes_of(second_prime), bytes_of(private_exponent % (first_prime - 1)),
        bytes_of(private_exponent % (second_prime - 1)), bytes_of(power_modulo(second_prime, first_prime - 2, first_prime)),
      )
    end
  end

  private def self.recover_factor(modulus : BigInt, public_exponent : BigInt, private_exponent : BigInt) : BigInt
    odd_part = private_exponent * public_exponent - 1
    halving_count = 0
    while odd_part.even?
      odd_part //= 2
      halving_count += 1
    end
    (2..1_000).each do |base|
      value = power_modulo(BigInt.new(base), odd_part, modulus)
      next if value == 1 || value == modulus - 1

      halving_count.times do
        squared = power_modulo(value, 2, modulus)
        return (value - 1).gcd(modulus) if squared == 1
        break if squared == modulus - 1

        value = squared
      end
    end
    raise "could not recover the primes of a #{modulus.bit_length}-bit modulus"
  end

  # Returns base^exponent mod modulus, by square and multiply.
  def self.power_modulo(base : BigInt, exponent : BigInt | Int, modulus : BigInt) : BigInt
    exponent = exponent.to_big_i
    result = BigInt.new(1)
    base = base % modulus
    exponent.bit_length.downto(0) do |bit_position|
      result = result * result % modulus
      result = result * base % modulus if (exponent >> bit_position) & 1 == 1
    end
    result
  end

  def self.bytes_of(value : BigInt) : Bytes
    hex = value.to_s(16)
    hex = "0#{hex}" if hex.size.odd?
    hex.hexbytes
  end

  # The hash name as the files write it, without "-" and "/": "SHA-512/256"
  # and "SHA512256" are both "SHA512256".
  def self.normalized(hash_name : String) : String
    hash_name.delete("-/")
  end
end

# Runs the block with its argument set to the SHA-2 class named
# *hash_name*, and gives the block's value; nil for any other name. The
# block is compiled once per hash, so each call sees one concrete class.
macro with_secure_hash_2_named(hash_name, &block)
  case RsaKeyComponents.normalized({{ hash_name }})
  {% for pair in [{"SHA224", "Beryl::Crypto::V1::SHA224"}, {"SHA256", "Beryl::Crypto::V1::SHA256"},
                  {"SHA384", "Beryl::Crypto::V1::SHA384"}, {"SHA512", "Beryl::Crypto::V1::SHA512"},
                  {"SHA512256", "Beryl::Crypto::V1::SHA512_256"}] %}
  when {{ pair[0] }}
    {{ block.args[0] }} = {{ pair[1].id }}
    {{ block.body }}
  {% end %}
  end
end

# As `with_secure_hash_2_named`, with SHA-1 as well.
macro with_secure_hash_2_or_1_named(hash_name, &block)
  case RsaKeyComponents.normalized({{ hash_name }})
  {% for pair in [{"SHA1", "Beryl::Crypto::Compatibility::SHA1"},
                  {"SHA224", "Beryl::Crypto::V1::SHA224"}, {"SHA256", "Beryl::Crypto::V1::SHA256"},
                  {"SHA384", "Beryl::Crypto::V1::SHA384"}, {"SHA512", "Beryl::Crypto::V1::SHA512"},
                  {"SHA512256", "Beryl::Crypto::V1::SHA512_256"}] %}
  when {{ pair[0] }}
    {{ block.args[0] }} = {{ pair[1].id }}
    {{ block.body }}
  {% end %}
  end
end
