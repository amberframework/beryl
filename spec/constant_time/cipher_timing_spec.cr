require "./hmac_timing_spec"

# Constant-time check of the ciphers, by timing (see `TimingLeakMeasurement`).
#
#     crystal-alpha spec --release --tag constant_time
#
# Each example times one operation on inputs from two classes and requires
# that the two sets of timings cannot be told apart. The classes differ only
# in secret bytes: a fixed key against random keys, or a forged message that
# is wrong in its first tag byte against one that is wrong in its last.
#
# A message with the right tag against one with a wrong tag is not a pair
# for this check: the right one goes on to be decrypted, which takes longer
# by design, and whether a message was accepted is what `decrypt` returns.
module CipherTimingCheck
  BATCH_SIZE        = TimingLeakMeasurement::BATCH_SIZE
  MESSAGE_BYTESIZE  = 64
  ROUND_KEY_WORDS   = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_WORD_COUNT
  HASH_STATE_WORDS  = Beryl::Crypto::V1::GaloisHash::STATE_WORD_COUNT
  AES_KEY_BYTESIZE  = 32
  AES_ROUND_COUNT   = 14
  POLY_KEY_BYTESIZE = 32

  def self.new_measurement(stream : UInt64) : {TimingLeakMeasurement, Random::PCG32}
    generator = Random::PCG32.new(Random::Secure.rand(UInt64), stream)
    {TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator), generator}
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

  # Lays out one forged message per slot: a copy of *sealed* with one bit
  # flipped in the first tag byte (first class) or the last (second class).
  def self.fill_forgeries(storage : Bytes, sealed : Bytes, tag_bytesize : Int32, list_of_classes : Array(Bool)) : Nil
    list_of_classes.each_with_index do |is_second_class, slot|
      forgery = HmacTimingCheck.slot_of(storage, slot, sealed.size)
      sealed.copy_to(forgery)
      forgery[is_second_class ? sealed.size - 1 : sealed.size - tag_bytesize] ^= 0x01_u8
    end
  end
end

private alias BitslicedAES = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard

if RequestedSpecTag.includes?("constant_time")
  describe "cipher timing", tags: "constant_time" do
    it "the AES key schedule takes the same time for an all-zero key and for random keys" do
      measurement, generator = CipherTimingCheck.new_measurement(11_u64)
      list_of_keys = Bytes.new(CipherTimingCheck::BATCH_SIZE * CipherTimingCheck::AES_KEY_BYTESIZE)
      round_keys = Slice(UInt64).new(CipherTimingCheck::ROUND_KEY_WORDS, 0_u64)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_keys, CipherTimingCheck::AES_KEY_BYTESIZE, list_of_classes, generator, 0_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        BitslicedAES.expand_key(HmacTimingCheck.slot_of(list_of_keys, slot, CipherTimingCheck::AES_KEY_BYTESIZE), round_keys)
      end

      HmacTimingCheck.report("AES-256 key schedule, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "AES encrypts and decrypts a block in the same time under an all-zero key and under random keys" do
      {% for direction in %w[encrypt decrypt] %}
        measurement, generator = CipherTimingCheck.new_measurement({{ direction == "encrypt" ? 12_u64 : 13_u64 }})
        list_of_keys = Bytes.new(CipherTimingCheck::BATCH_SIZE * CipherTimingCheck::AES_KEY_BYTESIZE)
        list_of_round_keys = Slice(UInt64).new(CipherTimingCheck::BATCH_SIZE * CipherTimingCheck::ROUND_KEY_WORDS, 0_u64)
        block = Random::Secure.random_bytes(16)
        output = Bytes.new(16)

        fill_batch = ->(list_of_classes : Array(Bool)) do
          CipherTimingCheck.fill_fixed_against_random(list_of_keys, CipherTimingCheck::AES_KEY_BYTESIZE, list_of_classes, generator, 0_u8)
          CipherTimingCheck::BATCH_SIZE.times do |slot|
            BitslicedAES.expand_key(
              HmacTimingCheck.slot_of(list_of_keys, slot, CipherTimingCheck::AES_KEY_BYTESIZE),
              list_of_round_keys[slot * CipherTimingCheck::ROUND_KEY_WORDS, CipherTimingCheck::ROUND_KEY_WORDS]
            )
          end
        end
        prepare = ->(slot : Int32) { nil }
        measurement.run(fill_batch, prepare) do |slot|
          BitslicedAES.{{ direction.id }}_blocks(
            list_of_round_keys[slot * CipherTimingCheck::ROUND_KEY_WORDS, CipherTimingCheck::ROUND_KEY_WORDS],
            CipherTimingCheck::AES_ROUND_COUNT, block, output
          )
        end

        HmacTimingCheck.report("AES-256 block {{ direction.id }}ion, all-zero key against random keys", measurement)
        measurement.shows_no_leak?.should be_true
      {% end %}
    end

    it "AES encrypts a block in the same time for an all-zero block and for random blocks" do
      measurement, generator = CipherTimingCheck.new_measurement(14_u64)
      list_of_blocks = Bytes.new(CipherTimingCheck::BATCH_SIZE * 16)
      round_keys = Slice(UInt64).new(CipherTimingCheck::ROUND_KEY_WORDS, 0_u64)
      BitslicedAES.expand_key(Random::Secure.random_bytes(32), round_keys)
      output = Bytes.new(16)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_blocks, 16, list_of_classes, generator, 0_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        BitslicedAES.encrypt_blocks(round_keys, CipherTimingCheck::AES_ROUND_COUNT, HmacTimingCheck.slot_of(list_of_blocks, slot, 16), output)
      end

      HmacTimingCheck.report("AES-256 block encryption, all-zero block against random blocks", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "GHASH takes the same time under an all-zero hash key and under random hash keys" do
      measurement, generator = CipherTimingCheck.new_measurement(15_u64)
      list_of_hash_keys = Bytes.new(CipherTimingCheck::BATCH_SIZE * 16)
      list_of_hash_states = Slice(UInt64).new(CipherTimingCheck::BATCH_SIZE * CipherTimingCheck::HASH_STATE_WORDS, 0_u64)
      message = Random::Secure.random_bytes(CipherTimingCheck::MESSAGE_BYTESIZE)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_hash_keys, 16, list_of_classes, generator, 0_u8)
        CipherTimingCheck::BATCH_SIZE.times do |slot|
          Beryl::Crypto::V1::GaloisHash.load_key(
            list_of_hash_states[slot * CipherTimingCheck::HASH_STATE_WORDS, CipherTimingCheck::HASH_STATE_WORDS],
            HmacTimingCheck.slot_of(list_of_hash_keys, slot, 16)
          )
        end
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        Beryl::Crypto::V1::GaloisHash.absorb(
          list_of_hash_states[slot * CipherTimingCheck::HASH_STATE_WORDS, CipherTimingCheck::HASH_STATE_WORDS], message
        )
      end

      HmacTimingCheck.report("GHASH of 64 bytes, all-zero hash key against random hash keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "Poly1305 takes the same time under an all-ones key and under random keys" do
      measurement, generator = CipherTimingCheck.new_measurement(16_u64)
      list_of_keys = Bytes.new(CipherTimingCheck::BATCH_SIZE * CipherTimingCheck::POLY_KEY_BYTESIZE)
      message = Bytes.new(CipherTimingCheck::MESSAGE_BYTESIZE, 0xff_u8)
      tag = Bytes.new(16)

      # An all-ones key and message drive every limb to its largest value,
      # the case where a carry or a final subtraction would show.
      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_keys, CipherTimingCheck::POLY_KEY_BYTESIZE, list_of_classes, generator, 0xff_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        Beryl::Crypto::V1::Poly1305OneTimeAuthenticator.authenticate(
          HmacTimingCheck.slot_of(list_of_keys, slot, CipherTimingCheck::POLY_KEY_BYTESIZE), message, tag
        )
      end

      HmacTimingCheck.report("Poly1305 of 64 bytes, all-ones key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "ChaCha20 takes the same time under an all-zero key and under random keys" do
      measurement, generator = CipherTimingCheck.new_measurement(17_u64)
      list_of_keys = Bytes.new(CipherTimingCheck::BATCH_SIZE * 32)
      nonce = Random::Secure.random_bytes(12)
      message = Random::Secure.random_bytes(CipherTimingCheck::MESSAGE_BYTESIZE)
      output = Bytes.new(CipherTimingCheck::MESSAGE_BYTESIZE)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_keys, 32, list_of_classes, generator, 0_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(HmacTimingCheck.slot_of(list_of_keys, slot, 32), nonce, 1_u32, message, output)
      end

      HmacTimingCheck.report("ChaCha20 of 64 bytes, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    {% for cipher in [{"ChaCha20-Poly1305", "Beryl::Crypto::V1::ChaCha20Poly1305.new(Random::Secure.random_bytes(32))", 21},
                      {"XChaCha20-Poly1305", "Beryl::Crypto::V1::XChaCha20Poly1305.new(Random::Secure.random_bytes(32))", 22},
                      {"AES-256-GCM", "Beryl::Crypto::V1::AESGCM.new(Random::Secure.random_bytes(32))", 23}] %}
      it "{{ cipher[0].id }} refuses a forgery in the same time whether its first tag byte or its last is wrong" do
        measurement, generator = CipherTimingCheck.new_measurement({{ cipher[2] }}_u64)
        cipher = {{ cipher[1].id }}
        nonce = Random::Secure.random_bytes(cipher.nonce_bytesize)
        sealed = cipher.encrypt(Random::Secure.random_bytes(CipherTimingCheck::MESSAGE_BYTESIZE), nonce: nonce, associated_data: "header")
        list_of_forgeries = Bytes.new(CipherTimingCheck::BATCH_SIZE * sealed.size)
        plaintext = Bytes.new(CipherTimingCheck::MESSAGE_BYTESIZE)
        accepted_count = 0

        fill_batch = ->(list_of_classes : Array(Bool)) do
          CipherTimingCheck.fill_forgeries(list_of_forgeries, sealed, cipher.tag_bytesize, list_of_classes)
        end
        prepare = ->(slot : Int32) { nil }
        measurement.run(fill_batch, prepare) do |slot|
          is_accepted = cipher.decrypt(HmacTimingCheck.slot_of(list_of_forgeries, slot, sealed.size), into: plaintext, nonce: nonce, associated_data: "header")
          accepted_count += 1 if is_accepted
        end

        accepted_count.should eq(0)
        HmacTimingCheck.report("{{ cipher[0].id }} decrypt of a forgery, first tag byte wrong against last tag byte wrong", measurement)
        measurement.shows_no_leak?.should be_true
      end
    {% end %}

    it "the CBC padding check takes the same time for well-formed padding and for random bytes" do
      measurement, generator = CipherTimingCheck.new_measurement(31_u64)
      list_of_blocks = Bytes.new(CipherTimingCheck::BATCH_SIZE * 16)
      padding_bytesize_sum = 0_u32

      # First class: sixteen bytes of 0x10, a whole block of padding. Second
      # class: random bytes, malformed about 254 times in 255.
      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_against_random(list_of_blocks, 16, list_of_classes, generator, 0x10_u8)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        padding_bytesize_sum &+= Beryl::Crypto::Compatibility::CipherBlockChaining.padding_bytesize(HmacTimingCheck.slot_of(list_of_blocks, slot, 16))
      end

      padding_bytesize_sum.should be > 0_u32
      HmacTimingCheck.report("CBC padding check, a block of padding against random bytes", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "the harness reports a comparison that stops at the first wrong byte" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 41_u64)
      measurement = TimingLeakMeasurement.new(Math.min(HmacTimingCheck.measurements_per_class, 500_000), generator)
      sealed = Random::Secure.random_bytes(80)
      list_of_forgeries = Bytes.new(CipherTimingCheck::BATCH_SIZE * sealed.size)
      mismatch_count = 0

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_forgeries(list_of_forgeries, sealed, 80, list_of_classes)
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        forgery = HmacTimingCheck.slot_of(list_of_forgeries, slot, sealed.size)
        mismatch_count += 1 unless forgery == sealed
      end

      mismatch_count.should be > 0
      HmacTimingCheck.report("planted leak (a comparison with an early exit), first byte wrong against last byte wrong", measurement)
      measurement.shows_no_leak?.should be_false
    end
  end
end
