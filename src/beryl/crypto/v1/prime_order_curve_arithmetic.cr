require "../field_arithmetic"
require "../constant_time_selection"
require "../secret_wiping"

module Beryl::Crypto::V1
  # :nodoc:
  #
  # Writes the arithmetic of a short Weierstrass curve y^2 = x^3 - 3x + b of
  # prime order (P-256, P-384) into the module it is called in, on the
  # fiat-crypto field *field* and scalar field *scalar_field*, both in the
  # Montgomery domain on 64-bit words.
  #
  # Points are projective (X : Y : Z), x = X/Z, y = Y/Z, with the neutral
  # element (0 : 1 : 0). Addition and doubling are the complete formulas of
  # Renes, Costello and Batina 2016 (https://eprint.iacr.org/2015/1060,
  # Algorithms 4 and 6, a = -3), written after RustCrypto's `primeorder`:
  # they are right for every pair of points, so no secret input reaches a
  # special case. Constant-time scalar multiplication uses a fixed window of
  # four bits with the table of 16 multiples scanned in full. Inversion and
  # square roots are fixed exponentiations (Fermat), whose exponents are
  # public.
  #
  # Integers outside the Montgomery domain are big-endian `Bytes` of
  # *bytesize* bytes, as SEC 1 and FIPS 186-5 write them.
  macro define_prime_order_curve_arithmetic(field, scalar_field, bytesize, field_prime, group_order, curve_b, generator_x, generator_y)
    alias Field = {{ field }}
    alias ScalarField = {{ scalar_field }}
    alias Limbs = Field::Limbs

    BYTESIZE       = {{ bytesize }}
    LIMB_COUNT     = {{ bytesize }} // 8
    FIELD_PRIME    = {{ field_prime }}.hexbytes
    GROUP_ORDER    = {{ group_order }}.hexbytes

    # p - 2, (p + 1) / 4 and n - 2, the public exponents of inversion and
    # of the square root (p = 3 mod 4 for both curves).
    FIELD_INVERSE_EXPONENT = big_endian_minus_small(FIELD_PRIME, 2_u8)

    def self.field_inverse_exponent : Bytes
      FIELD_INVERSE_EXPONENT
    end
    SQUARE_ROOT_EXPONENT = big_endian_quarter_of_successor(FIELD_PRIME)

    def self.square_root_exponent : Bytes
      SQUARE_ROOT_EXPONENT
    end
    SCALAR_INVERSE_EXPONENT = big_endian_minus_small(GROUP_ORDER, 2_u8)

    def self.scalar_inverse_exponent : Bytes
      SCALAR_INVERSE_EXPONENT
    end

    CURVE_B = field_element_from_big_endian({{ curve_b }}.hexbytes)
    GENERATOR = begin
      Point.new(field_element_from_big_endian({{ generator_x }}.hexbytes),
        field_element_from_big_endian({{ generator_y }}.hexbytes), Field.set_one)
    end

    def self.generator : Point
      GENERATOR
    end

    # The multiples 0G, 1G, ..., 15G for the fixed window.
    GENERATOR_MULTIPLES = multiples_of(generator)

    def self.generator_multiples : StaticArray(Point, 16)
      GENERATOR_MULTIPLES
    end

    # For each 4-bit window of a scalar, the 16 multiples of G that window
    # can add: entry j of table i is [j * 16^(2 * BYTESIZE - 1 - i)]G, so
    # table 0 serves the most significant window. Built once, on first use.
    GENERATOR_WINDOW_TABLES = begin
      list_of_tables = Array(StaticArray(Point, 16)).new(BYTESIZE * 2)
      base = generator
      (BYTESIZE * 2).times do
        list_of_tables << multiples_of(base)
        4.times { base = base.double }
      end
      list_of_tables.reverse!
    end

    def self.generator_window_tables : Array(StaticArray(Point, 16))
      GENERATOR_WINDOW_TABLES
    end

    # Returns *value* - *small* for a big-endian *value* larger than *small*.
    def self.big_endian_minus_small(value : Bytes, small : UInt8) : Bytes
      result = value.dup
      borrow = small.to_i32
      (result.size - 1).downto(0) do |index|
        difference = result[index].to_i32 - borrow
        borrow = difference < 0 ? 1 : 0
        result[index] = (difference & 0xff).to_u8
      end
      result
    end

    # Returns (value + 1) / 4 for a big-endian odd *value*.
    def self.big_endian_quarter_of_successor(value : Bytes) : Bytes
      successor = value.dup
      carry = 1
      (successor.size - 1).downto(0) do |index|
        sum = successor[index].to_i32 + carry
        carry = sum >> 8
        successor[index] = (sum & 0xff).to_u8
      end
      quarter = Bytes.new(successor.size)
      remainder = carry # the bit above the top byte
      successor.size.times do |index|
        current = (remainder << 8) | successor[index].to_i32
        quarter[index] = (current >> 2).to_u8
        remainder = current & 3
      end
      quarter
    end

    # Packs a big-endian integer (below the modulus) into fiat-crypto limbs,
    # outside the Montgomery domain.
    def self.limbs_from_big_endian(encoded : Bytes) : Limbs
      limbs = Limbs.new(0_u64)
      BYTESIZE.times do |offset|
        byte = encoded.unsafe_fetch(BYTESIZE - 1 - offset).to_u64
        limbs[offset >> 3] |= byte << ((offset & 7) * 8)
      end
      limbs
    end

    def self.limbs_to_big_endian(limbs : Limbs) : Bytes
      Bytes.new(BYTESIZE) do |index|
        offset = BYTESIZE - 1 - index
        (limbs[offset >> 3] >> ((offset & 7) * 8)).to_u8!
      end
    end

    def self.field_element_from_big_endian(encoded : Bytes) : Limbs
      Field.to_montgomery(limbs_from_big_endian(encoded))
    end

    def self.field_element_to_big_endian(element : Limbs) : Bytes
      limbs_to_big_endian(Field.from_montgomery(element))
    end

    # Returns 1 when the big-endian *encoded* is below *modulus*, else 0.
    def self.below_bit(encoded : Bytes, modulus : Bytes) : UInt64
      ConstantTimeSelection.big_endian_less_than_bit(encoded, modulus)
    end

    # Reduces a big-endian integer below 2^(8 * BYTESIZE) modulo the group
    # order n by one conditional subtraction (2^(8 * BYTESIZE) < 2n for both
    # curves), in constant time; the result is outside the Montgomery domain.
    def self.reduce_once_modulo_order(encoded : Bytes) : Limbs
      value = limbs_from_big_endian(encoded)
      order = limbs_from_big_endian(GROUP_ORDER)
      difference = Limbs.new(0_u64)
      borrow = 0_u64
      LIMB_COUNT.times do |index|
        limb, borrow = Field.subborrowx_u64(borrow, value[index], order[index])
        difference[index] = limb
      end
      # Keep the difference unless the subtraction borrowed.
      Field.selectznz(borrow, difference, value)
    end

    # Raises *base* (Montgomery domain of the field prime) to the public
    # big-endian *exponent*, four bits at a time: 15 multiplications build
    # base^1 to base^15, then each 4-bit digit costs four squarings and one
    # multiplication (none for a zero digit, which is public).
    def self.field_power(base : Limbs, exponent : Bytes) : Limbs
      powers = StaticArray(Limbs, 16).new(Field.set_one)
      1.upto(15) { |index| powers[index] = Field.mul(powers[index - 1], base) }
      result = Field.set_one
      exponent.each do |byte|
        {4, 0}.each do |shift|
          4.times { result = Field.square(result) }
          digit = (byte >> shift) & 0xf
          result = Field.mul(result, powers[digit]) unless digit == 0
        end
      end
      result
    end

    # `field_power` modulo the group order.
    def self.scalar_power(base : Limbs, exponent : Bytes) : Limbs
      powers = StaticArray(Limbs, 16).new(ScalarField.set_one)
      1.upto(15) { |index| powers[index] = ScalarField.mul(powers[index - 1], base) }
      result = ScalarField.set_one
      exponent.each do |byte|
        {4, 0}.each do |shift|
          4.times { result = ScalarField.square(result) }
          digit = (byte >> shift) & 0xf
          result = ScalarField.mul(result, powers[digit]) unless digit == 0
        end
      end
      result
    end

    def self.field_invert(element : Limbs) : Limbs
      field_power(element, field_inverse_exponent)
    end

    # Returns 1 when two field elements are equal, else 0.
    def self.field_equal_bit(first : Limbs, second : Limbs) : UInt64
      ConstantTimeSelection.equal_bit(Field.nonzero(Field.sub(first, second)), 0_u64)
    end

    def self.field_zero_bit(element : Limbs) : UInt64
      ConstantTimeSelection.equal_bit(Field.nonzero(element), 0_u64)
    end

    # x^3 - 3x + b.
    def self.curve_right_side(x : Limbs) : Limbs
      x_cubed = Field.mul(Field.square(x), x)
      three_x = Field.add(Field.add(x, x), x)
      Field.add(Field.sub(x_cubed, three_x), CURVE_B)
    end

    struct Point
      getter x : Limbs
      getter y : Limbs
      getter z : Limbs

      def initialize(@x : Limbs, @y : Limbs, @z : Limbs)
      end

      def self.neutral : Point
        Point.new(Limbs.new(0_u64), Field.set_one, Limbs.new(0_u64))
      end

      # Renes-Costello-Batina 2016, Algorithm 4 (a = -3).
      def add(other : Point) : Point
        b = CURVE_B
        xx = Field.mul(@x, other.x)
        yy = Field.mul(@y, other.y)
        zz = Field.mul(@z, other.z)
        xy_pairs = Field.sub(Field.mul(Field.add(@x, @y), Field.add(other.x, other.y)), Field.add(xx, yy))
        yz_pairs = Field.sub(Field.mul(Field.add(@y, @z), Field.add(other.y, other.z)), Field.add(yy, zz))
        xz_pairs = Field.sub(Field.mul(Field.add(@x, @z), Field.add(other.x, other.z)), Field.add(xx, zz))

        bzz_part = Field.sub(xz_pairs, Field.mul(b, zz))
        bzz3_part = Field.add(Field.add(bzz_part, bzz_part), bzz_part)
        yy_minus_bzz3 = Field.sub(yy, bzz3_part)
        yy_plus_bzz3 = Field.add(yy, bzz3_part)

        zz3 = Field.add(Field.add(zz, zz), zz)
        bxz_part = Field.sub(Field.mul(b, xz_pairs), Field.add(zz3, xx))
        bxz3_part = Field.add(Field.add(bxz_part, bxz_part), bxz_part)
        xx3_minus_zz3 = Field.sub(Field.add(Field.add(xx, xx), xx), zz3)

        Point.new(
          Field.sub(Field.mul(yy_plus_bzz3, xy_pairs), Field.mul(yz_pairs, bxz3_part)),
          Field.add(Field.mul(yy_plus_bzz3, yy_minus_bzz3), Field.mul(xx3_minus_zz3, bxz3_part)),
          Field.add(Field.mul(yy_minus_bzz3, yz_pairs), Field.mul(xy_pairs, xx3_minus_zz3)),
        )
      end

      # Renes-Costello-Batina 2016, Algorithm 6 (a = -3).
      def double : Point
        b = CURVE_B
        xx = Field.square(@x)
        yy = Field.square(@y)
        zz = Field.square(@z)
        xy = Field.mul(@x, @y)
        xy2 = Field.add(xy, xy)
        xz = Field.mul(@x, @z)
        xz2 = Field.add(xz, xz)

        bzz_part = Field.sub(Field.mul(b, zz), xz2)
        bzz3_part = Field.add(Field.add(bzz_part, bzz_part), bzz_part)
        yy_minus_bzz3 = Field.sub(yy, bzz3_part)
        yy_plus_bzz3 = Field.add(yy, bzz3_part)
        y_fragment = Field.mul(yy_plus_bzz3, yy_minus_bzz3)
        x_fragment = Field.mul(yy_minus_bzz3, xy2)

        zz3 = Field.add(Field.add(zz, zz), zz)
        bxz2_part = Field.sub(Field.mul(b, xz2), Field.add(zz3, xx))
        bxz6_part = Field.add(Field.add(bxz2_part, bxz2_part), bxz2_part)
        xx3_minus_zz3 = Field.sub(Field.add(Field.add(xx, xx), xx), zz3)

        new_y = Field.add(y_fragment, Field.mul(xx3_minus_zz3, bxz6_part))
        yz = Field.mul(@y, @z)
        yz2 = Field.add(yz, yz)
        new_x = Field.sub(x_fragment, Field.mul(bxz6_part, yz2))
        yz2_yy = Field.mul(yz2, yy)
        yz4_yy = Field.add(yz2_yy, yz2_yy)
        Point.new(new_x, new_y, Field.add(yz4_yy, yz4_yy))
      end

      def negate : Point
        Point.new(@x, Field.opp(@y), @z)
      end

      # Returns *other* when *bit* is 1, else self.
      def replace_if(bit : UInt64, other : Point) : Point
        Point.new(Field.selectznz(bit, @x, other.x), Field.selectznz(bit, @y, other.y), Field.selectznz(bit, @z, other.z))
      end
    end

    # Returns 1 for the neutral element, else 0.
    def self.neutral_bit(point : Point) : UInt64
      field_zero_bit(point.z)
    end

    # Returns the affine coordinates of *point* in the Montgomery domain.
    # The neutral element has none; its result is (0, 0).
    def self.to_affine(point : Point) : {Limbs, Limbs}
      inverse_z = field_invert(point.z)
      {Field.mul(point.x, inverse_z), Field.mul(point.y, inverse_z)}
    end

    def self.multiples_of(point : Point) : StaticArray(Point, 16)
      multiples = StaticArray(Point, 16).new(Point.neutral)
      multiples[1] = point
      2.upto(15) do |index|
        multiples[index] = index.even? ? multiples[index // 2].double : multiples[index - 1].add(point)
      end
      multiples
    end

    # Returns [scalar]point for a big-endian *scalar* of BYTESIZE bytes, in
    # constant time.
    def self.multiply_constant_time(scalar : Bytes, multiples : StaticArray(Point, 16)) : Point
      result = Point.neutral
      (BYTESIZE * 2).times do |window_index|
        4.times { result = result.double }
        nibble = (scalar.unsafe_fetch(window_index >> 1).to_u64 >> (window_index.even? ? 4 : 0)) & 0xf_u64
        selected = Point.neutral
        16.times do |candidate|
          selected = selected.replace_if(ConstantTimeSelection.equal_bit(candidate.to_u64, nibble), multiples[candidate])
        end
        result = result.add(selected)
      end
      result
    end

    # Returns [scalar]G for a big-endian *scalar* of BYTESIZE bytes, in
    # constant time: one addition per 4-bit window from that window of
    # the precomputed tables, each picked by scanning all 16 entries, and
    # no doubling.
    def self.multiply_generator(scalar : Bytes) : Point
      list_of_tables = generator_window_tables
      result = Point.neutral
      (BYTESIZE * 2).times do |window_index|
        nibble = (scalar.unsafe_fetch(window_index >> 1).to_u64 >> (window_index.even? ? 4 : 0)) & 0xf_u64
        table = list_of_tables.unsafe_fetch(window_index)
        selected = Point.neutral
        16.times do |candidate|
          selected = selected.replace_if(ConstantTimeSelection.equal_bit(candidate.to_u64, nibble), table[candidate])
        end
        result = result.add(selected)
      end
      result
    end

    # Returns [first_scalar]G + [second_scalar]point, in variable time: for
    # signature verification, where every input is public.
    def self.multiply_and_add_public(first_scalar : Bytes, point : Point, second_scalar : Bytes) : Point
      point_multiples = multiples_of(point)
      base_multiples = generator_multiples
      result = Point.neutral
      (BYTESIZE * 2).times do |window_index|
        4.times { result = result.double }
        shift = window_index.even? ? 4 : 0
        first_nibble = (first_scalar[window_index >> 1] >> shift) & 0xf_u8
        second_nibble = (second_scalar[window_index >> 1] >> shift) & 0xf_u8
        result = result.add(base_multiples[first_nibble]) unless first_nibble == 0
        result = result.add(point_multiples[second_nibble]) unless second_nibble == 0
      end
      result
    end

    # Decodes a SEC 1 §2.3.4 point: 0x04 || X || Y or 0x02/0x03 || X.
    # Returns nil for any other form, a coordinate not below p, a point off
    # the curve, or the point at infinity. The input is public.
    def self.decode_point(encoded : Bytes) : Point?
      return nil if encoded.empty?

      form = encoded[0]
      return decode_uncompressed_point(encoded) if form == 0x04_u8 && encoded.size == 1 + 2 * BYTESIZE
      return decode_compressed_point(encoded) if (form == 0x02_u8 || form == 0x03_u8) && encoded.size == 1 + BYTESIZE

      nil
    end

    private def self.decode_uncompressed_point(encoded : Bytes) : Point?
      encoded_x = encoded[1, BYTESIZE]
      encoded_y = encoded[1 + BYTESIZE, BYTESIZE]
      return nil unless below_bit(encoded_x, FIELD_PRIME) == 1 && below_bit(encoded_y, FIELD_PRIME) == 1

      x = field_element_from_big_endian(encoded_x)
      y = field_element_from_big_endian(encoded_y)
      return nil unless field_equal_bit(Field.square(y), curve_right_side(x)) == 1

      Point.new(x, y, Field.set_one)
    end

    private def self.decode_compressed_point(encoded : Bytes) : Point?
      encoded_x = encoded[1, BYTESIZE]
      return nil unless below_bit(encoded_x, FIELD_PRIME) == 1

      x = field_element_from_big_endian(encoded_x)
      right_side = curve_right_side(x)
      y = field_power(right_side, square_root_exponent)
      return nil unless field_equal_bit(Field.square(y), right_side) == 1

      y_is_odd = field_element_to_big_endian(y)[BYTESIZE - 1] & 1
      y = Field.opp(y) unless y_is_odd == (encoded[0] & 1)
      Point.new(x, y, Field.set_one)
    end

    # Returns the SEC 1 uncompressed encoding 0x04 || X || Y.
    def self.encode_uncompressed(point : Point) : Bytes
      x, y = to_affine(point)
      encoded = Bytes.new(1 + 2 * BYTESIZE)
      encoded[0] = 0x04_u8
      field_element_to_big_endian(x).copy_to(encoded[1, BYTESIZE])
      field_element_to_big_endian(y).copy_to(encoded[1 + BYTESIZE, BYTESIZE])
      encoded
    end

    # Returns the SEC 1 compressed encoding 0x02/0x03 || X.
    def self.encode_compressed(point : Point) : Bytes
      x, y = to_affine(point)
      encoded = Bytes.new(1 + BYTESIZE)
      encoded[0] = 0x02_u8 | (field_element_to_big_endian(y)[BYTESIZE - 1] & 1)
      field_element_to_big_endian(x).copy_to(encoded[1, BYTESIZE])
      encoded
    end

    # The x coordinate of *point* reduced modulo n, outside the Montgomery
    # domain (the r of ECDSA).
    def self.x_coordinate_modulo_order(point : Point) : Limbs
      x, _ = to_affine(point)
      reduce_once_modulo_order(field_element_to_big_endian(x))
    end

    # Returns the leftmost bits of a digest as an integer below
    # 2^(8 * BYTESIZE) (FIPS 186-5 §6.4.1 step 4, RFC 6979 bits2int), as
    # BYTESIZE big-endian bytes. The orders of both curves fill whole bytes.
    def self.digest_to_integer(digest : Bytes) : Bytes
      return digest[0, BYTESIZE].dup unless digest.size < BYTESIZE

      integer = Bytes.new(BYTESIZE)
      digest.copy_to(integer[BYTESIZE - digest.size, digest.size])
      integer
    end
  end
end
