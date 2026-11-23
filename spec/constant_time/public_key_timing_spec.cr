require "./hmac_timing_spec"

# Constant-time check of the elliptic-curve operations that read a secret
# scalar, by timing (see `TimingLeakMeasurement`).
#
#     crystal-alpha spec --release --tag constant_time spec/constant_time/public_key_timing_spec.cr
#
# Each example times one operation under a fixed secret against random
# secrets. The fixed secrets are the ones most likely to take a shortcut:
# an all-zero X25519 scalar and Ed25519 seed, and the scalar 1 on P-256,
# whose windows are all zero but the last, so the table lookups pick the
# neutral point again and again.
#
# 1,000,000 measurements per class by default
# (BERYL_PUBLIC_KEY_CONSTANT_TIME_MEASUREMENTS overrides it; an operation
# here takes a thousand times as long as an HMAC, so CI runs fewer).
module PublicKeyTimingCheck
  DEFAULT_MEASUREMENTS_PER_CLASS = 1_000_000
  BATCH_SIZE                     = TimingLeakMeasurement::BATCH_SIZE
  SCALAR_BYTESIZE                = 32

  def self.measurements_per_class : Int32
    ENV["BERYL_PUBLIC_KEY_CONSTANT_TIME_MEASUREMENTS"]?.try(&.to_i) || DEFAULT_MEASUREMENTS_PER_CLASS
  end

  def self.new_measurement(stream : UInt64) : {TimingLeakMeasurement, Random::PCG32}
    generator = Random::PCG32.new(Random::Secure.rand(UInt64), stream)
    {TimingLeakMeasurement.new(measurements_per_class, generator), generator}
  end

  # Fills *storage* with random bytes, then overwrites the slots of the
  # first class with *fixed_byte*.
  def self.fill_fixed_against_random(storage : Bytes, slot_bytesize : Int32, list_of_classes : Array(Bool),
                                     generator : Random::PCG32, fixed_byte : UInt8) : Nil
    generator.random_bytes(storage)
    list_of_classes.each_with_index do |is_second_class, slot|
      next if is_second_class
      HmacTimingCheck.slot_of(storage, slot, slot_bytesize).fill(fixed_byte)
    end
  end

  # The big-endian P-256 scalar 1.
  def self.scalar_one : Bytes
    scalar = Bytes.new(SCALAR_BYTESIZE)
    scalar[SCALAR_BYTESIZE - 1] = 1_u8
    scalar
  end

  # Lays out one P-256 scalar per slot: 1 for the first class, a random
  # scalar below n for the second.
  def self.fill_p256_scalars(storage : Bytes, list_of_classes : Array(Bool), generator : Random::PCG32) : Nil
    one = scalar_one
    list_of_classes.each_with_index do |is_second_class, slot|
      scalar = HmacTimingCheck.slot_of(storage, slot, SCALAR_BYTESIZE)
      if is_second_class
        loop do
          generator.random_bytes(scalar)
          break if P256::PrivateKey.in_range_bit(scalar) == 1
        end
      else
        one.copy_to(scalar)
      end
    end
  end
end

private alias X25519 = Beryl::Crypto::V1::X25519
private alias Ed25519 = Beryl::Crypto::V1::Ed25519
private alias P256 = Beryl::Crypto::V1::P256
private alias SignatureNonce = Beryl::Crypto::V1::DeterministicSignatureNonce(Beryl::Crypto::V1::SHA256)

if RequestedSpecTag.includes?("constant_time")
  describe "public-key timing", tags: "constant_time" do
    it "X25519 multiplies in the same time by an all-zero scalar and by random scalars" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(31_u64)
      list_of_scalars = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)
      peer_u = X25519::PrivateKey.generate.public_key.to_slice

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_fixed_against_random(list_of_scalars, PublicKeyTimingCheck::SCALAR_BYTESIZE, list_of_classes, generator, 0_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        X25519.scalar_multiply(HmacTimingCheck.slot_of(list_of_scalars, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE), peer_u)
      end

      HmacTimingCheck.report("X25519 scalar multiplication, all-zero scalar against random scalars", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "Ed25519 derives a key in the same time from an all-zero seed and from random seeds" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(32_u64)
      list_of_seeds = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_fixed_against_random(list_of_seeds, PublicKeyTimingCheck::SCALAR_BYTESIZE, list_of_classes, generator, 0_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        Ed25519::SigningKey.new(HmacTimingCheck.slot_of(list_of_seeds, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE))
      end

      HmacTimingCheck.report("Ed25519 key derivation, all-zero seed against random seeds", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "Ed25519 signs in the same time under the all-zero seed and under random seeds" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(33_u64)
      list_of_seeds = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)
      list_of_keys = Array(Ed25519::SigningKey).new(PublicKeyTimingCheck::BATCH_SIZE) { Ed25519::SigningKey.generate }
      message = Random::Secure.random_bytes(64)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_fixed_against_random(list_of_seeds, PublicKeyTimingCheck::SCALAR_BYTESIZE, list_of_classes, generator, 0_u8)
        PublicKeyTimingCheck::BATCH_SIZE.times do |slot|
          list_of_keys[slot] = Ed25519::SigningKey.new(HmacTimingCheck.slot_of(list_of_seeds, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE))
        end
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        list_of_keys[slot].sign(message)
      end

      HmacTimingCheck.report("Ed25519 signing, all-zero seed against random seeds", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "P-256 multiplies the generator in the same time by 1 and by random scalars" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(34_u64)
      list_of_scalars = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_p256_scalars(list_of_scalars, list_of_classes, generator)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        P256::Arithmetic.multiply_generator(HmacTimingCheck.slot_of(list_of_scalars, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE))
      end

      HmacTimingCheck.report("P-256 generator multiplication, scalar 1 against random scalars", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "P-256 agrees on a shared secret in the same time under the key 1 and under random keys" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(35_u64)
      list_of_scalars = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)
      peer_multiples = P256::Arithmetic.multiples_of(P256::PrivateKey.generate.public_key.point)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_p256_scalars(list_of_scalars, list_of_classes, generator)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        P256::Arithmetic.multiply_constant_time(HmacTimingCheck.slot_of(list_of_scalars, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE), peer_multiples)
      end

      HmacTimingCheck.report("P-256 shared-secret multiplication, key 1 against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "P-256 signs in the same time with the nonce 1 and with random nonces" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(36_u64)
      list_of_nonces = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)
      private_key = P256::PrivateKey.generate
      digest = Random::Secure.random_bytes(32)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_p256_scalars(list_of_nonces, list_of_classes, generator)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        nonce = HmacTimingCheck.slot_of(list_of_nonces, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE)
        private_key.sign_with_nonce(digest, nonce, format: Beryl::Crypto::V1::SignatureFormat::FixedWidth)
      end

      HmacTimingCheck.report("P-256 signing, nonce 1 against random nonces", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "the RFC 6979 nonce takes the same time for the private key 1 and for random keys" do
      measurement, generator = PublicKeyTimingCheck.new_measurement(37_u64)
      list_of_scalars = Bytes.new(PublicKeyTimingCheck::BATCH_SIZE * PublicKeyTimingCheck::SCALAR_BYTESIZE)
      digest_integer = Random::Secure.random_bytes(32)
      digest_integer[0] &= 0x7f_u8

      fill_batch = ->(list_of_classes : Array(Bool)) do
        PublicKeyTimingCheck.fill_p256_scalars(list_of_scalars, list_of_classes, generator)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        SignatureNonce.generate(HmacTimingCheck.slot_of(list_of_scalars, slot, PublicKeyTimingCheck::SCALAR_BYTESIZE),
          digest_integer, P256::Arithmetic::GROUP_ORDER)
      end

      HmacTimingCheck.report("RFC 6979 nonce for P-256, key 1 against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end
  end
end
