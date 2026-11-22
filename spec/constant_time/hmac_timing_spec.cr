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

  def self.measurements_per_class : Int32
    ENV["BERYL_CONSTANT_TIME_MEASUREMENTS"]?.try(&.to_i) || DEFAULT_MEASUREMENTS_PER_CLASS
  end

  def self.report(description : String, measurement : TimingLeakMeasurement) : Nil
    STDOUT.puts "constant time, #{description}: #{measurement.measurements_per_class} measurements per class, " \
                "largest |t| = #{measurement.largest_absolute_t.round(2)} (a leak shows as #{TimingLeakMeasurement::LEAK_THRESHOLD} or more)"
  end
end

private alias HMACSHA256 = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256)

if RequestedSpecTag.includes?("constant_time")
  describe "HMAC timing", tags: "constant_time" do
    key = Random::Secure.random_bytes(32)
    message = Random::Secure.random_bytes(48)
    correct_tag = HMACSHA256.authenticate(message, key: key)

    it "verify takes the same time for the right tag and for a random tag" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 1_u64)
      authentication = HMACSHA256.new(key)
      candidate_tag = Bytes.new(32)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      prepare = ->(is_second_class : Bool) do
        authentication.reset
        authentication.update(message)
        if is_second_class
          generator.random_bytes(candidate_tag)
        else
          correct_tag.copy_to(candidate_tag)
        end
        nil
      end
      measurement.run(prepare) { authentication.verify(candidate_tag) }

      HmacTimingCheck.report("verify, right tag against random tag", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "verify takes the same time for a tag that matches up to its last byte and one that fails at its first" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 2_u64)
      authentication = HMACSHA256.new(key)
      candidate_tag = Bytes.new(32)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      prepare = ->(is_second_class : Bool) do
        authentication.reset
        authentication.update(message)
        correct_tag.copy_to(candidate_tag)
        candidate_tag[is_second_class ? 0 : 31] ^= 0x01_u8
        nil
      end
      measurement.run(prepare) { authentication.verify(candidate_tag) }

      HmacTimingCheck.report("verify, last byte wrong against first byte wrong", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "verify takes the same time for a tag of the right length and one of the wrong length" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 3_u64)
      authentication = HMACSHA256.new(key)
      candidate_storage = Bytes.new(32)
      candidate_tag = candidate_storage
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      prepare = ->(is_second_class : Bool) do
        authentication.reset
        authentication.update(message)
        generator.random_bytes(candidate_storage)
        candidate_tag = is_second_class ? candidate_storage[0, 31] : candidate_storage
        nil
      end
      measurement.run(prepare) { authentication.verify(candidate_tag) }

      HmacTimingCheck.report("verify, 32-byte tag against 31-byte tag", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "keying takes the same time for a fixed key and for random keys" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 4_u64)
      candidate_key = Bytes.new(32)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      prepare = ->(is_second_class : Bool) do
        if is_second_class
          generator.random_bytes(candidate_key)
        else
          candidate_key.fill(0_u8)
        end
        nil
      end
      measurement.run(prepare) { HMACSHA256.new(candidate_key) }

      HmacTimingCheck.report("keying, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end

    it "authenticating takes the same time for a fixed key and for random keys" do
      generator = Random::PCG32.new(Random::Secure.rand(UInt64), 5_u64)
      candidate_key = Bytes.new(32)
      tag = Bytes.new(32)
      authentication = HMACSHA256.new(candidate_key)
      measurement = TimingLeakMeasurement.new(HmacTimingCheck.measurements_per_class, generator)

      prepare = ->(is_second_class : Bool) do
        if is_second_class
          generator.random_bytes(candidate_key)
        else
          candidate_key.fill(0_u8)
        end
        authentication = HMACSHA256.new(candidate_key)
        nil
      end
      measurement.run(prepare) do
        authentication.update(message)
        authentication.final(tag)
      end

      HmacTimingCheck.report("update and final, all-zero key against random keys", measurement)
      measurement.shows_no_leak?.should be_true
    end
  end
end
