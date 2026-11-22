require "../spec_helper"

# Constant-time check of HMAC, by timing (see `TimingLeakMeasurement`).
#
#     crystal-alpha spec --release --tag constant_time
#
# 10,000,000 measurements per class by default
# (BERYL_CONSTANT_TIME_MEASUREMENTS overrides it). A debug build is not
# what ships and is not worth timing; build with --release.
module HmacTimingCheck
  DEFAULT_MEASUREMENTS_PER_CLASS = 10_000_000
  BATCH_SIZE                     = TimingLeakMeasurement::BATCH_SIZE
  TAG_BYTESIZE                   = 32
  KEY_BYTESIZE                   = 32

  def self.measurements_per_class : Int32
    ENV["BERYL_CONSTANT_TIME_MEASUREMENTS"]?.try(&.to_i) || DEFAULT_MEASUREMENTS_PER_CLASS
  end

  def self.report(description : String, measurement : TimingLeakMeasurement) : Nil
    STDOUT.puts "constant time, #{description}: #{measurement.measurements_per_class} measurements per class, " \
                "largest |t| = #{measurement.largest_absolute_t.round(2)} (a leak shows as #{TimingLeakMeasurement::LEAK_THRESHOLD} or more)"
  end

  # Returns slot number *slot* of a batch laid out end to end in *storage*.
  def self.slot_of(storage : Bytes, slot : Int32, bytesize : Int32) : Bytes
    storage[slot * bytesize, bytesize]
  end
end

private alias HMACSHA256 = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256)

if RequestedSpecTag.includes?("constant_time")
  describe "HMAC timing", tags: "constant_time" do
    key = Random::Secure.random_bytes(HmacTimingCheck::KEY_BYTESIZE)
    message = Random::Secure.random_bytes(48)
    correct_tag = HMACSHA256.authenticate(message, key: key)

    it "verify takes the same time for the right tag and for a random tag" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 1_u64)
      authentication = HMACSHA256.new(key)
      list_of_candidate_tags = Bytes.new(HmacTimingCheck::BATCH_SIZE * HmacTimingCheck::TAG_BYTESIZE)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        generator.random_bytes(list_of_candidate_tags)
        list_of_classes.each_with_index do |is_second_class, slot|
          next if is_second_class
          correct_tag.copy_to(HmacTimingCheck.slot_of(list_of_candidate_tags, slot, HmacTimingCheck::TAG_BYTESIZE))
        end
        nil
      end
      prepare = ->(slot : Int32) do
        authentication.reset
        authentication.update(message)
        nil
      end
      measurement.run(fill_batch, prepare) do |slot|
        authentication.verify(HmacTimingCheck.slot_of(list_of_candidate_tags, slot, HmacTimingCheck::TAG_BYTESIZE))
      end

      HmacTimingCheck.report("verify, right tag against random tag", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "verify takes the same time for a tag that matches up to its last byte and one that fails at its first" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 2_u64)
      authentication = HMACSHA256.new(key)
      list_of_candidate_tags = Bytes.new(HmacTimingCheck::BATCH_SIZE * HmacTimingCheck::TAG_BYTESIZE)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        list_of_classes.each_with_index do |is_second_class, slot|
          candidate_tag = HmacTimingCheck.slot_of(list_of_candidate_tags, slot, HmacTimingCheck::TAG_BYTESIZE)
          correct_tag.copy_to(candidate_tag)
          candidate_tag[is_second_class ? 0 : HmacTimingCheck::TAG_BYTESIZE - 1] ^= 0x01_u8
        end
        nil
      end
      prepare = ->(slot : Int32) do
        authentication.reset
        authentication.update(message)
        nil
      end
      measurement.run(fill_batch, prepare) do |slot|
        authentication.verify(HmacTimingCheck.slot_of(list_of_candidate_tags, slot, HmacTimingCheck::TAG_BYTESIZE))
      end

      HmacTimingCheck.report("verify, last byte wrong against first byte wrong", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "keying takes the same time for an all-zero key and for random keys" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 3_u64)
      list_of_keys = Bytes.new(HmacTimingCheck::BATCH_SIZE * HmacTimingCheck::KEY_BYTESIZE)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        generator.random_bytes(list_of_keys)
        list_of_classes.each_with_index do |is_second_class, slot|
          next if is_second_class
          HmacTimingCheck.slot_of(list_of_keys, slot, HmacTimingCheck::KEY_BYTESIZE).fill(0_u8)
        end
        nil
      end
      prepare = ->(slot : Int32) { nil }
      measurement.run(fill_batch, prepare) do |slot|
        HMACSHA256.new(HmacTimingCheck.slot_of(list_of_keys, slot, HmacTimingCheck::KEY_BYTESIZE))
      end

      HmacTimingCheck.report("keying, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "authenticating takes the same time under an all-zero key and under random keys" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 4_u64)
      list_of_keys = Bytes.new(HmacTimingCheck::BATCH_SIZE * HmacTimingCheck::KEY_BYTESIZE)
      tag = Bytes.new(HmacTimingCheck::TAG_BYTESIZE)
      authentication = HMACSHA256.new(key)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      fill_batch = ->(list_of_classes : Array(Bool)) do
        generator.random_bytes(list_of_keys)
        list_of_classes.each_with_index do |is_second_class, slot|
          next if is_second_class
          HmacTimingCheck.slot_of(list_of_keys, slot, HmacTimingCheck::KEY_BYTESIZE).fill(0_u8)
        end
        nil
      end
      prepare = ->(slot : Int32) do
        authentication = HMACSHA256.new(HmacTimingCheck.slot_of(list_of_keys, slot, HmacTimingCheck::KEY_BYTESIZE))
        nil
      end
      measurement.run(fill_batch, prepare) do |slot|
        authentication.update(message)
        authentication.final(tag)
      end

      HmacTimingCheck.report("update and final, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end
  end
end
