require "../field_arithmetic"
require "../constant_time_selection"

module Beryl::Crypto::V1
  # :nodoc:
  #
  # An integer modulo p = 2^255 - 19, held in fiat-crypto's five 51-bit
  # limbs and kept within fiat-crypto's tight bounds after every operation,
  # so any operation may follow any other. X25519 calls the field functions
  # directly instead, with the bounds worked out by hand, because the ladder
  # is its whole running time.
  struct Curve25519FieldElement
    private alias Field = Beryl::Crypto::FieldArithmetic::Curve25519Field

    getter limbs : Field::Limbs

    def initialize(@limbs : Field::Limbs)
    end

    def self.zero : self
      new(Field::Limbs.new(0_u64))
    end

    def self.one : self
      limbs = Field::Limbs.new(0_u64)
      limbs[0] = 1_u64
      new(limbs)
    end

    def self.from_small(value : UInt64) : self
      limbs = Field::Limbs.new(0_u64)
      limbs[0] = value
      new(limbs)
    end

    # Reads 32 little-endian bytes, ignoring the top bit of the last byte
    # (RFC 7748 §5, RFC 8032 §5.1.3). A value of p or more is taken modulo p.
    def self.from_bytes(bytes : Bytes) : self
      buffer = StaticArray(UInt8, 32).new(0_u8)
      32.times { |index| buffer[index] = bytes.unsafe_fetch(index) }
      buffer[31] &= 0x7f_u8
      new(Field.from_bytes(buffer))
    end

    # Returns the canonical 32-byte little-endian encoding (less than p).
    def to_bytes : StaticArray(UInt8, 32)
      Field.to_bytes(@limbs)
    end

    def +(other : self) : self
      Curve25519FieldElement.new(Field.carry(Field.add(@limbs, other.limbs)))
    end

    def -(other : self) : self
      Curve25519FieldElement.new(Field.carry(Field.sub(@limbs, other.limbs)))
    end

    def - : self
      Curve25519FieldElement.new(Field.carry(Field.opp(@limbs)))
    end

    def *(other : self) : self
      Curve25519FieldElement.new(Field.carry_mul(@limbs, other.limbs))
    end

    def square : self
      Curve25519FieldElement.new(Field.carry_square(@limbs))
    end

    # Squares *count* times in a row.
    def square_times(count : Int32) : self
      limbs = @limbs
      count.times { limbs = Field.carry_square(limbs) }
      Curve25519FieldElement.new(limbs)
    end

    # Returns *other* when *bit* is 1, else self.
    def select(bit : UInt64, other : self) : self
      Curve25519FieldElement.new(Field.selectznz(bit, @limbs, other.limbs))
    end

    # Returns 1 when the value is zero modulo p, else 0.
    def zero_bit : UInt64
      encoded = to_bytes
      ConstantTimeSelection.all_zero_bit(encoded.to_slice)
    end

    # Returns the low bit of the canonical encoding ("negative" in RFC 8032).
    def low_bit : UInt64
      to_bytes[0].to_u64 & 1_u64
    end

    def equal_bit(other : self) : UInt64
      (self - other).zero_bit
    end

    # Returns self^(p - 2), the inverse (zero for zero), by ref10's chain of
    # 254 squarings and 11 multiplications.
    def invert : self
      z2 = square             # 2
      z8 = z2.square_times(2) # 8
      z9 = self * z8          # 9
      z11 = z2 * z9           # 11
      z22 = z11.square        # 22
      z_5_0 = z9 * z22        # 2^5 - 2^0
      z_10_0 = z_5_0.square_times(5) * z_5_0
      z_20_0 = z_10_0.square_times(10) * z_10_0
      z_40_0 = z_20_0.square_times(20) * z_20_0
      z_50_0 = z_40_0.square_times(10) * z_10_0
      z_100_0 = z_50_0.square_times(50) * z_50_0
      z_200_0 = z_100_0.square_times(100) * z_100_0
      z_250_0 = z_200_0.square_times(50) * z_50_0
      z_250_0.square_times(5) * z11 # 2^255 - 21
    end

    # Returns self^((p - 5) / 8) = self^(2^252 - 3), the core of the square
    # root in RFC 8032 §5.1.3, by ref10's chain.
    def power_two_to_252_minus_three : self
      z2 = square
      z8 = z2.square_times(2)
      z9 = self * z8
      z11 = z2 * z9
      z22 = z11.square
      z_5_0 = z9 * z22
      z_10_0 = z_5_0.square_times(5) * z_5_0
      z_20_0 = z_10_0.square_times(10) * z_10_0
      z_40_0 = z_20_0.square_times(20) * z_20_0
      z_50_0 = z_40_0.square_times(10) * z_10_0
      z_100_0 = z_50_0.square_times(50) * z_50_0
      z_200_0 = z_100_0.square_times(100) * z_100_0
      z_250_0 = z_200_0.square_times(50) * z_50_0
      z_250_0.square_times(2) * self # 2^252 - 4 + 1
    end
  end
end
