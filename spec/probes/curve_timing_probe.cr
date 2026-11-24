# Timing probe for the curve operations, run outside the spec runner so one
# build can time any case by name (fixed class against random class, dudect,
# see `TimingLeakMeasurement`).
#
#     crystal-alpha build --release -Dwithout_openssl spec/probes/curve_timing_probe.cr -o curve_timing_probe
#     ./curve_timing_probe <case> <measurements per class>
#
# Cases come in pairs: the special secret the spec times (scalar 1, an
# all-zero scalar) and a control, a fixed random secret against random
# secrets, which runs the same code with operands as dense as the random
# class's. A leak in the special case alone points at the operand values;
# a leak in both points at the harness or the machine.
require "../../src/beryl/crypto"
require "../support/timing_leak_measurement"

module CurveTimingProbe
  alias X25519 = Beryl::Crypto::V1::X25519
  alias P256 = Beryl::Crypto::V1::P256
  alias P256Field = Beryl::Crypto::FieldArithmetic::P256FieldWithAssembly

  BATCH_SIZE      = TimingLeakMeasurement::BATCH_SIZE
  SCALAR_BYTESIZE = 32

  @[NoInline]
  def self.timed_multiply_generator(scalar : Bytes) : P256::Arithmetic::Point
    P256::Arithmetic.multiply_generator(scalar)
  end

  @[NoInline]
  def self.timed_multiply_constant_time(scalar : Bytes, multiples : StaticArray(P256::Arithmetic::Point, 16)) : P256::Arithmetic::Point
    P256::Arithmetic.multiply_constant_time(scalar, multiples)
  end

  @[NoInline]
  def self.timed_x25519(scalar : Bytes, peer_u : Bytes) : Bytes
    X25519.scalar_multiply(scalar, peer_u)
  end

  # 64 field multiplications in a chain, so one measurement is long enough
  # for the clock.
  @[NoInline]
  def self.timed_field_chain(first : StaticArray(UInt64, 4), second : StaticArray(UInt64, 4)) : StaticArray(UInt64, 4)
    product = first
    64.times { product = P256Field.mul(product, second) }
    product
  end

  def self.slot_of(storage : Bytes, slot : Int32) : Bytes
    storage[slot * SCALAR_BYTESIZE, SCALAR_BYTESIZE]
  end

  def self.random_p256_scalar(generator : Random::PCG32) : Bytes
    scalar = Bytes.new(SCALAR_BYTESIZE)
    loop do
      generator.random_bytes(scalar)
      return scalar if P256::PrivateKey.in_range_bit(scalar) == 1
    end
  end

  # Lays out one scalar per slot: *fixed* for the first class, a fresh
  # random one (below n when *below_order*) for the second.
  def self.fill(storage : Bytes, list_of_classes : Array(Bool), generator : Random::PCG32, fixed : Bytes, below_order : Bool) : Nil
    list_of_classes.each_with_index do |is_second_class, slot|
      destination = slot_of(storage, slot)
      if !is_second_class
        fixed.copy_to(destination)
      elsif below_order
        random_p256_scalar(generator).copy_to(destination)
      else
        generator.random_bytes(destination)
      end
    end
  end

  def self.run(case_name : String, measurements_per_class : Int32) : Float64
    generator = Random::PCG32.new(Random::Secure.rand(UInt64), 7_u64)
    measurement = TimingLeakMeasurement.new(measurements_per_class, generator)
    storage = Bytes.new(BATCH_SIZE * SCALAR_BYTESIZE)
    prepare = ->(slot : Int32) { nil }
    sink = 0_u64

    one = Bytes.new(SCALAR_BYTESIZE)
    one[SCALAR_BYTESIZE - 1] = 1_u8
    zero = Bytes.new(SCALAR_BYTESIZE)

    case case_name
    when "p256-generator-one", "p256-generator-fixed"
      fixed = case_name.ends_with?("one") ? one : random_p256_scalar(generator)
      fill_batch = ->(list_of_classes : Array(Bool)) { fill(storage, list_of_classes, generator, fixed, true) }
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_multiply_generator(slot_of(storage, slot)).x[0] }
    when "p256-ecdh-one", "p256-ecdh-fixed"
      fixed = case_name.ends_with?("one") ? one : random_p256_scalar(generator)
      multiples = P256::Arithmetic.multiples_of(P256::PrivateKey.generate.public_key.point)
      fill_batch = ->(list_of_classes : Array(Bool)) { fill(storage, list_of_classes, generator, fixed, true) }
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_multiply_constant_time(slot_of(storage, slot), multiples).x[0] }
    when "x25519-zero", "x25519-fixed"
      fixed = case_name.ends_with?("zero") ? zero : Random::Secure.random_bytes(SCALAR_BYTESIZE)
      peer_u = X25519::PrivateKey.generate.public_key.to_slice
      fill_batch = ->(list_of_classes : Array(Bool)) { fill(storage, list_of_classes, generator, fixed, false) }
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_x25519(slot_of(storage, slot), peer_u)[0] }
    when "field-mul-zero", "field-mul-fixed"
      second = StaticArray(UInt64, 4).new { generator.next_u.to_u64 << 32 | generator.next_u }
      list_of_first = Array(StaticArray(UInt64, 4)).new(BATCH_SIZE) { StaticArray(UInt64, 4).new(0_u64) }
      fixed_first = StaticArray(UInt64, 4).new(0_u64)
      if case_name.ends_with?("fixed")
        fixed_first = StaticArray(UInt64, 4).new { generator.next_u.to_u64 << 32 | generator.next_u }
        fixed_first[3] &= 0x7fffffffffffffff_u64
      end
      fill_batch = ->(list_of_classes : Array(Bool)) do
        list_of_classes.each_with_index do |is_second_class, slot|
          value = fixed_first
          if is_second_class
            value = StaticArray(UInt64, 4).new { generator.next_u.to_u64 << 32 | generator.next_u }
            value[3] &= 0x7fffffffffffffff_u64
          end
          list_of_first[slot] = value
        end
        nil
      end
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_field_chain(list_of_first[slot], second)[0] }
    else
      abort "unknown case #{case_name}"
    end

    STDOUT.puts "case #{case_name}: #{measurements_per_class} measurements per class, |t| = #{measurement.largest_absolute_t.round(2)}, fixed minus random #{measurement.mean_difference_nanoseconds.round(1)} ns (sink #{sink & 1})"
    measurement.largest_absolute_t
  end
end

measurements_per_class = (ARGV[1]? || "1000000").to_i
CurveTimingProbe.run(ARGV[0]? || abort("usage: curve_timing_probe <case> [measurements per class]"), measurements_per_class)
