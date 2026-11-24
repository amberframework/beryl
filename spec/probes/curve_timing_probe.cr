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

  # 16 doublings in a chain.
  @[NoInline]
  def self.timed_doublings(point : P256::Arithmetic::Point) : P256::Arithmetic::Point
    16.times { point = point.double }
    point
  end

  # 16 mixed additions of *entry* in a chain, kept or dropped by *is_zero*.
  @[NoInline]
  def self.timed_mixed_additions(point : P256::Arithmetic::Point, entry : P256::Arithmetic::AffinePoint, is_zero : UInt64) : P256::Arithmetic::Point
    16.times { point = point.add_affine(entry, is_zero) }
    point
  end

  def self.random_point(generator : Random::PCG32) : P256::Arithmetic::Point
    P256::Arithmetic.multiply_generator(random_p256_scalar(generator))
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
    batch_value = Bytes.new(SCALAR_BYTESIZE)
    if below_order
      random_p256_scalar(generator).copy_to(batch_value)
    else
      generator.random_bytes(batch_value)
    end
    one_per_batch = ENV["BERYL_SECOND_CLASS_PER_BATCH"]? == "1"
    list_of_classes.each_with_index do |is_second_class, slot|
      destination = slot_of(storage, slot)
      if !is_second_class
        fixed.copy_to(destination)
      elsif one_per_batch
        batch_value.copy_to(destination)
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
    when "x25519-zero", "x25519-fixed", "x25519-ones"
      fixed = case case_name
              when "x25519-zero" then zero
              when "x25519-ones" then Bytes.new(SCALAR_BYTESIZE, 0xff_u8)
              else                    Random::Secure.random_bytes(SCALAR_BYTESIZE)
              end
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
    when "double-neutral", "double-fixed"
      fixed_point = case_name.ends_with?("neutral") ? P256::Arithmetic::Point.neutral : random_point(generator)
      list_of_points = Array(P256::Arithmetic::Point).new(BATCH_SIZE, fixed_point)
      fill_batch = ->(list_of_classes : Array(Bool)) do
        list_of_classes.each_with_index { |is_second_class, slot| list_of_points[slot] = is_second_class ? random_point(generator) : fixed_point }
        nil
      end
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_doublings(list_of_points[slot]).x[0] }
    when "add-zero-entry", "add-fixed-entry"
      running = random_point(generator)
      table = P256::Arithmetic.generator_window_tables
      fixed_entry = case_name == "add-zero-entry" ? P256::Arithmetic::AffinePoint.new(StaticArray(UInt64, 4).new(0_u64), StaticArray(UInt64, 4).new(0_u64)) : table[3][5]
      fixed_is_zero = case_name == "add-zero-entry" ? 1_u64 : 0_u64
      list_of_entries = Array(P256::Arithmetic::AffinePoint).new(BATCH_SIZE, fixed_entry)
      list_of_is_zero = Array(UInt64).new(BATCH_SIZE, 0_u64)
      fill_batch = ->(list_of_classes : Array(Bool)) do
        list_of_classes.each_with_index do |is_second_class, slot|
          list_of_entries[slot] = is_second_class ? table[generator.rand(40) + 1][generator.rand(16)] : fixed_entry
          list_of_is_zero[slot] = is_second_class ? 0_u64 : fixed_is_zero
        end
        nil
      end
      measurement.run(fill_batch, prepare) { |slot| sink &+= timed_mixed_additions(running, list_of_entries[slot], list_of_is_zero[slot]).x[0] }
    when "chacha-zero", "chacha-fixed"
      fixed = case_name == "chacha-zero" ? zero : Random::Secure.random_bytes(SCALAR_BYTESIZE)
      nonce = Random::Secure.random_bytes(12)
      message = Random::Secure.random_bytes(64)
      output = Bytes.new(64)
      fill_batch = ->(list_of_classes : Array(Bool)) { fill(storage, list_of_classes, generator, fixed, false) }
      measurement.run(fill_batch, prepare) do |slot|
        Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(slot_of(storage, slot), nonce, 1_u32, message, output)
        sink &+= output[0]
      end
    else
      abort "unknown case #{case_name}"
    end

    STDOUT.puts "case #{case_name}: #{measurements_per_class} measurements per class, |t| = #{measurement.largest_absolute_t.round(2)}, fixed minus random #{measurement.mean_difference_nanoseconds.round(1)} ns (sink #{sink & 1})"
    measurement.largest_absolute_t
  end
end

measurements_per_class = (ARGV[1]? || "1000000").to_i
CurveTimingProbe.run(ARGV[0]? || abort("usage: curve_timing_probe <case> [measurements per class]"), measurements_per_class)
