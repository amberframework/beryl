require "./cipher_timing_spec"

# Constant-time check of RSA, by timing (see `TimingLeakMeasurement`).
#
#     crystal-alpha spec --release --tag rsa_constant_time spec/constant_time/rsa_timing_spec.cr
#
# The examples carry the tags `constant_time` and `rsa_constant_time`. An RSA
# private operation takes about a millisecond, a thousand times longer than
# the other timed calls, so it runs at its own count: 200,000 measurements
# per class by default, BERYL_CONSTANT_TIME_MEASUREMENTS overrides it, and
# the other timing specs run with `--tag constant_time --tag ~rsa_constant_time`.
#
# - The private operation (the Chinese remainder exponentiation and the check
#   with the public exponent) on one fixed input against random inputs, all
#   below the modulus, under a 2,048-bit key.
# - OAEP decoding of well-formed encodings against encodings that fail at
#   different places (the first byte, the label digest, a byte before the
#   separator, no separator at all), and of encodings that fail at the
#   first byte against ones that fail at the last.
module RsaTimingCheck
  DEFAULT_MEASUREMENTS_PER_CLASS = 200_000
  BATCH_SIZE                     = TimingLeakMeasurement::BATCH_SIZE

  # The number of encodings of each kind the OAEP checks draw from.
  ENCODING_POOL_SIZE = 256

  def self.measurements_per_class : Int32
    ENV["BERYL_CONSTANT_TIME_MEASUREMENTS"]?.try(&.to_i) || DEFAULT_MEASUREMENTS_PER_CLASS
  end

  def self.new_measurement(stream : UInt64) : {TimingLeakMeasurement, Random::PCG32}
    generator = Random::PCG32.new(Random::Secure.rand(UInt64), stream)
    {TimingLeakMeasurement.new(measurements_per_class, generator), generator}
  end

  # Returns random bytes of the modulus size whose first byte is zero, so
  # the value is below any modulus of that size.
  def self.random_input_below_modulus(bytesize : Int32, generator : Random::PCG32) : Bytes
    input = Bytes.new(bytesize)
    generator.random_bytes(input)
    input[0] = 0_u8
    input
  end

  # Returns a well-formed OAEP encoding of a random message of random length.
  def self.well_formed_encoding(label_digest : Bytes, encoded_bytesize : Int32, generator : Random::PCG32) : Bytes
    largest_message_bytesize = encoded_bytesize - 2 * label_digest.size - 2
    message = Bytes.new(generator.rand(0..largest_message_bytesize))
    generator.random_bytes(message)
    seed = Bytes.new(label_digest.size)
    generator.random_bytes(seed)
    Beryl::Crypto::V1::RSA::MessageEncoding.encode_oaep(Beryl::Crypto::V1::SHA256, message, label_digest, seed, encoded_bytesize)
  end

  # Returns an encoding that fails in the way numbered *kind*: 0, the first
  # byte is not zero; 1, the label digest differs; 2, a byte other than
  # 0x00 and 0x01 comes before the separator; 3, there is no separator.
  def self.malformed_encoding(kind : Int32, label_digest : Bytes, encoded_bytesize : Int32, generator : Random::PCG32) : Bytes
    digest_bytesize = label_digest.size
    data_block = Bytes.new(encoded_bytesize - digest_bytesize - 1)
    label_digest.copy_to(data_block)
    separator_index = generator.rand((digest_bytesize + 1)...(data_block.size - 1))
    data_block[separator_index] = 0x01_u8
    generator.random_bytes(data_block[separator_index + 1, data_block.size - separator_index - 1])
    first_byte = 0_u8
    case kind
    when 0 then first_byte = generator.rand(1..255).to_u8
    when 1 then data_block[generator.rand(0...digest_bytesize)] ^= 0x01_u8
    when 2 then data_block[generator.rand(digest_bytesize...separator_index)] = generator.rand(2..255).to_u8
    else        data_block[separator_index] = 0x00_u8; data_block[digest_bytesize..].fill(0_u8)
    end
    mask_into_encoding(first_byte, data_block, digest_bytesize, generator)
  end

  # Masks *data_block* under a random seed (RFC 8017 §7.1.1 steps 2.d to
  # 2.i) and returns the encoding with *first_byte* in front.
  def self.mask_into_encoding(first_byte : UInt8, data_block : Bytes, digest_bytesize : Int32, generator : Random::PCG32) : Bytes
    encoding = Bytes.new(1 + digest_bytesize + data_block.size)
    encoding[0] = first_byte
    masked_seed = encoding[1, digest_bytesize]
    generator.random_bytes(masked_seed)
    masked_data_block = encoding[1 + digest_bytesize, data_block.size]
    data_block.copy_to(masked_data_block)
    Beryl::Crypto::V1::RSA::MessageEncoding.mask_with_mgf1(Beryl::Crypto::V1::SHA256, masked_seed, masked_data_block)
    Beryl::Crypto::V1::RSA::MessageEncoding.mask_with_mgf1(Beryl::Crypto::V1::SHA256, masked_data_block, masked_seed)
    encoding
  end

  # OAEP decoding that refuses a nonzero first byte at once: the planted
  # leak, the early exit that the attack of Manger (2001) measures.
  def self.leaky_decode_oaep(encoded : Bytes, label_digest : Bytes) : UInt32
    return 0_u32 unless encoded[0] == 0_u8

    Beryl::Crypto::V1::RSA::MessageEncoding.decode_oaep(Beryl::Crypto::V1::SHA256, encoded, label_digest, 1_u64)
  end

  # Times OAEP decoding of encodings drawn from *first_pool* (first class)
  # and *second_pool* (second class), reporting under *description*.
  def self.check_oaep_decoding(description : String, stream : UInt64, first_pool : Array(Bytes), second_pool : Array(Bytes),
                               label_digest : Bytes, is_leaky : Bool = false) : TimingLeakMeasurement
    measurement, generator = new_measurement(stream)
    encoded_bytesize = first_pool.first.size
    batch = Bytes.new(BATCH_SIZE * encoded_bytesize)
    work = Bytes.new(encoded_bytesize)
    fill_batch = ->(list_of_classes : Array(Bool)) do
      list_of_classes.each_with_index do |is_second_class, slot|
        pool = is_second_class ? second_pool : first_pool
        pool[generator.rand(pool.size)].copy_to(HmacTimingCheck.slot_of(batch, slot, encoded_bytesize))
      end
      nil
    end
    prepare = ->(slot : Int32) do
      HmacTimingCheck.slot_of(batch, slot, encoded_bytesize).copy_to(work)
      nil
    end
    measurement.run(fill_batch, prepare) do |slot|
      if is_leaky
        leaky_decode_oaep(work, label_digest)
      else
        Beryl::Crypto::V1::RSA::MessageEncoding.decode_oaep(Beryl::Crypto::V1::SHA256, work, label_digest, 1_u64)
      end
    end
    HmacTimingCheck.report(description, measurement)
    measurement
  end
end

if RequestedSpecTag.includes?("constant_time") || RequestedSpecTag.includes?("rsa_constant_time")
  describe "RSA timing", tags: ["constant_time", "rsa_constant_time"] do
    it "the private operation takes the same time for a fixed input and for random inputs (2,048 bits)" do
      test_file = Wycheproof::TestFile(Wycheproof::RsaOaepTestGroup).from_json(
        VectorFile.read("wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json")
      )
      private_key = RsaKeyComponents.from_wycheproof(test_file.list_of_test_groups.first.private_key).private_key
      modulus_bytesize = private_key.modulus_bytesize
      measurement, generator = RsaTimingCheck.new_measurement(31_u64)
      fixed_input = RsaTimingCheck.random_input_below_modulus(modulus_bytesize, generator)
      list_of_inputs = Bytes.new(RsaTimingCheck::BATCH_SIZE * modulus_bytesize)
      random_source = Bytes.new(list_of_inputs.size)
      output = Bytes.new(modulus_bytesize)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        CipherTimingCheck.fill_fixed_value_against_random(list_of_inputs, fixed_input, random_source, list_of_classes, generator)
        RsaTimingCheck::BATCH_SIZE.times { |slot| list_of_inputs[slot * modulus_bytesize] = 0_u8 }
        nil
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        private_key.compute_private_operation(HmacTimingCheck.slot_of(list_of_inputs, slot, modulus_bytesize), output)
      end

      HmacTimingCheck.report("RSA-2048 private operation, fixed input against random inputs", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "OAEP decoding takes the same time for well-formed encodings and for encodings broken at any place" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 32_u64)
      label_digest = Beryl::Crypto::V1::SHA256.digest(Bytes.empty)
      well_formed = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) { RsaTimingCheck.well_formed_encoding(label_digest, 256, generator) }
      malformed = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) do |index|
        RsaTimingCheck.malformed_encoding(index % 4, label_digest, 256, generator)
      end
      well_formed.each { |encoding| Beryl::Crypto::V1::RSA::MessageEncoding.decode_oaep(Beryl::Crypto::V1::SHA256, encoding.dup, label_digest, 1_u64).should_not eq(0_u32) }
      malformed.each { |encoding| Beryl::Crypto::V1::RSA::MessageEncoding.decode_oaep(Beryl::Crypto::V1::SHA256, encoding.dup, label_digest, 1_u64).should eq(0_u32) }

      measurement = RsaTimingCheck.check_oaep_decoding("RSA-2048 OAEP decoding, well-formed against malformed encodings",
        33_u64, well_formed, malformed, label_digest)
      measurement.shows_no_leak?.should be_true
    end

    it "OAEP decoding takes the same time for an encoding broken at its first byte and one broken before its separator" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 34_u64)
      label_digest = Beryl::Crypto::V1::SHA256.digest(Bytes.empty)
      broken_first = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) { RsaTimingCheck.malformed_encoding(0, label_digest, 256, generator) }
      broken_late = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) do |index|
        RsaTimingCheck.malformed_encoding(2 + index % 2, label_digest, 256, generator)
      end

      measurement = RsaTimingCheck.check_oaep_decoding("RSA-2048 OAEP decoding, broken at the first byte against broken before the separator",
        35_u64, broken_first, broken_late, label_digest)
      measurement.shows_no_leak?.should be_true
    end

    it "the harness reports OAEP decoding that refuses a bad first byte at once" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 36_u64)
      label_digest = Beryl::Crypto::V1::SHA256.digest(Bytes.empty)
      well_formed = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) { RsaTimingCheck.well_formed_encoding(label_digest, 256, generator) }
      broken_first = Array(Bytes).new(RsaTimingCheck::ENCODING_POOL_SIZE) { RsaTimingCheck.malformed_encoding(0, label_digest, 256, generator) }

      measurement = RsaTimingCheck.check_oaep_decoding("planted leak (OAEP decoding with an early exit), well-formed against broken at the first byte",
        37_u64, well_formed, broken_first, label_digest, is_leaky: true)
      measurement.shows_no_leak?.should be_false
    end
  end
end
