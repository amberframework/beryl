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

    # For each 4-bit window of a scalar, counted from the least significant,
    # the 15 nonzero multiples of G that window can add, in affine
    # coordinates: entry j of table i is [j * 16^i]G (entry 0 is unused).
    # Built once, when first used, with a single inversion.
    GENERATOR_WINDOW_TABLES = begin
      list_of_points = [] of Point
      base = generator
      (BYTESIZE * 2).times do
        multiples = multiples_of(base)
        16.times { |index| list_of_points << multiples[index] }
        4.times { base = base.double }
      end
      list_of_affine = to_affine_together(list_of_points)
      Array(StaticArray(AffinePoint, 16)).new(BYTESIZE * 2) do |window|
        StaticArray(AffinePoint, 16).new { |index| list_of_affine[window * 16 + index] }
      end
    end

    def self.generator_window_tables : Array(StaticArray(AffinePoint, 16))
      GENERATOR_WINDOW_TABLES
    end

    # The odd multiples G, 3G, ..., 63G in affine coordinates, for the
    # width-7 signed digits of signature verification.
    GENERATOR_ODD_MULTIPLES = begin
      list_of_points = [] of Point
      twice_generator = generator.double
      current = generator
      32.times do
        list_of_points << current
        current = current.add_public(twice_generator)
      end
      to_affine_together(list_of_points)
    end

    def self.generator_odd_multiples : Array(AffinePoint)
      GENERATOR_ODD_MULTIPLES
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

    # A point in affine coordinates (x, y), both in the Montgomery domain.
    # The tables of multiples of G hold these; the point at infinity has
    # no affine coordinates, and a table entry for it is never read.
    record AffinePoint, x : Limbs, y : Limbs

    # A point in Jacobian coordinates (X : Y : Z), x = X/Z^2, y = Y/Z^3;
    # Z = 0 is the point at infinity. Doubling is the a = -3 formula
    # dbl-2001-b of the Explicit-Formulas Database (3M + 5S); it has no
    # exceptional case on a curve of prime order, where no point has y = 0,
    # and it keeps Z = 0 at infinity. Addition (add-1998-cmo-2, 12M + 4S)
    # and mixed addition with an affine point (8M + 3S) give the right sum
    # for every pair except a point added to itself, where they return
    # infinity; `add` and `add_affine` choose the other operand when one is
    # infinity by mask. The scalar multiplications below never add a point
    # to itself, because a scalar below the group order n never makes two
    # equal operands (each says why); `add_public` and `add_affine_public`,
    # for verification, branch to a doubling instead, which is allowed there
    # because every input is public.
    #
    # The prime-order curves of BoringSSL and OpenSSL (`p256.c`,
    # `ecp_nistz256.c`) use the same coordinates and the same argument.
    struct Point
      getter x : Limbs
      getter y : Limbs
      getter z : Limbs

      def initialize(@x : Limbs, @y : Limbs, @z : Limbs)
      end

      def self.neutral : Point
        Point.new(Field.set_one, Field.set_one, Limbs.new(0_u64))
      end

      def self.from_affine(point : AffinePoint) : Point
        Point.new(point.x, point.y, Field.set_one)
      end

      # Returns 1 for the point at infinity, else 0.
      def neutral_bit : UInt64
        ConstantTimeSelection.equal_bit(Field.nonzero(@z), 0_u64)
      end

      # Returns 1 when two field elements are equal, else 0.
      def self.equal_bit(first : Limbs, second : Limbs) : UInt64
        ConstantTimeSelection.equal_bit(Field.nonzero(Field.sub(first, second)), 0_u64)
      end

      def double : Point
        delta = Field.square(@z)
        gamma = Field.square(@y)
        beta = Field.mul(@x, gamma)
        alpha_part = Field.mul(Field.sub(@x, delta), Field.add(@x, delta))
        alpha = Field.add(Field.add(alpha_part, alpha_part), alpha_part)
        beta_2 = Field.add(beta, beta)
        beta_4 = Field.add(beta_2, beta_2)
        beta_8 = Field.add(beta_4, beta_4)
        new_x = Field.sub(Field.square(alpha), beta_8)
        y_z = Field.mul(@y, @z)
        new_z = Field.add(y_z, y_z)
        gamma_squared = Field.square(gamma)
        gamma_squared_2 = Field.add(gamma_squared, gamma_squared)
        gamma_squared_4 = Field.add(gamma_squared_2, gamma_squared_2)
        gamma_squared_8 = Field.add(gamma_squared_4, gamma_squared_4)
        new_y = Field.sub(Field.mul(alpha, Field.sub(beta_4, new_x)), gamma_squared_8)
        Point.new(new_x, new_y, new_z)
      end

      # The sum with *other*, in constant time, for any pair except a point
      # and itself (which gives infinity).
      def add(other : Point) : Point
        sum = add_unchecked(other)
        sum = sum.replace_if(neutral_bit, other)
        sum.replace_if(other.neutral_bit, self)
      end

      # The sum with the affine *other*, or self when *other_is_neutral* is
      # 1, in constant time, for any pair except a point and itself.
      def add_affine(other : AffinePoint, other_is_neutral : UInt64) : Point
        sum = add_affine_unchecked(other)
        sum = sum.replace_if(neutral_bit, Point.from_affine(other))
        sum.replace_if(other_is_neutral, self)
      end

      # The sum with *other* for public points: branches on infinity and on
      # equal points.
      def add_public(other : Point) : Point
        return other if neutral_bit == 1
        return self if other.neutral_bit == 1

        z1_squared = Field.square(@z)
        z2_squared = Field.square(other.z)
        u1 = Field.mul(@x, z2_squared)
        u2 = Field.mul(other.x, z1_squared)
        s1 = Field.mul(@y, Field.mul(other.z, z2_squared))
        s2 = Field.mul(other.y, Field.mul(@z, z1_squared))
        if Point.equal_bit(u1, u2) == 1
          return Point.equal_bit(s1, s2) == 1 ? double : Point.neutral
        end

        finish_addition(u1, s1, Field.sub(u2, u1), Field.sub(s2, s1), Field.mul(@z, other.z))
      end

      # The sum with the affine *other* for public points.
      def add_affine_public(other : AffinePoint) : Point
        return Point.from_affine(other) if neutral_bit == 1

        z1_squared = Field.square(@z)
        u2 = Field.mul(other.x, z1_squared)
        s2 = Field.mul(other.y, Field.mul(@z, z1_squared))
        if Point.equal_bit(@x, u2) == 1
          return Point.equal_bit(@y, s2) == 1 ? double : Point.neutral
        end

        finish_addition(@x, @y, Field.sub(u2, @x), Field.sub(s2, @y), @z)
      end

      private def add_unchecked(other : Point) : Point
        z1_squared = Field.square(@z)
        z2_squared = Field.square(other.z)
        u1 = Field.mul(@x, z2_squared)
        u2 = Field.mul(other.x, z1_squared)
        s1 = Field.mul(@y, Field.mul(other.z, z2_squared))
        s2 = Field.mul(other.y, Field.mul(@z, z1_squared))
        finish_addition(u1, s1, Field.sub(u2, u1), Field.sub(s2, s1), Field.mul(@z, other.z))
      end

      private def add_affine_unchecked(other : AffinePoint) : Point
        z1_squared = Field.square(@z)
        u2 = Field.mul(other.x, z1_squared)
        s2 = Field.mul(other.y, Field.mul(@z, z1_squared))
        finish_addition(@x, @y, Field.sub(u2, @x), Field.sub(s2, @y), @z)
      end

      # X3 = R^2 - H^3 - 2·U1·H^2, Y3 = R·(U1·H^2 - X3) - S1·H^3,
      # Z3 = Z1·Z2·H, from U1 = X1·Z2^2, S1 = Y1·Z2^3, H = U2 - U1 and
      # R = S2 - S1.
      @[AlwaysInline]
      private def finish_addition(u1 : Limbs, s1 : Limbs, h : Limbs, r : Limbs, z1_z2 : Limbs) : Point
        h_squared = Field.square(h)
        h_cubed = Field.mul(h, h_squared)
        v = Field.mul(u1, h_squared)
        new_x = Field.sub(Field.sub(Field.square(r), h_cubed), Field.add(v, v))
        new_y = Field.sub(Field.mul(r, Field.sub(v, new_x)), Field.mul(s1, h_cubed))
        Point.new(new_x, new_y, Field.mul(z1_z2, h))
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
      inverse_z_squared = Field.square(inverse_z)
      {Field.mul(point.x, inverse_z_squared), Field.mul(point.y, Field.mul(inverse_z, inverse_z_squared))}
    end

    # The affine form of each point of *list_of_points* (public, none at
    # infinity except where an entry is never read), with one inversion
    # for all of them (Montgomery's trick).
    def self.to_affine_together(list_of_points : Array(Point)) : Array(AffinePoint)
      one = Field.set_one
      list_of_prefix_products = Array(Limbs).new(list_of_points.size)
      running = one
      list_of_points.each do |point|
        list_of_prefix_products << running
        running = Field.mul(running, point.z) unless neutral_bit(point) == 1
      end
      inverse = field_invert(running)
      list_of_affine = Array(AffinePoint).new(list_of_points.size, AffinePoint.new(Limbs.new(0_u64), Limbs.new(0_u64)))
      (list_of_points.size - 1).downto(0) do |index|
        point = list_of_points[index]
        next if neutral_bit(point) == 1

        inverse_z = Field.mul(inverse, list_of_prefix_products[index])
        inverse = Field.mul(inverse, point.z)
        inverse_z_squared = Field.square(inverse_z)
        list_of_affine[index] = AffinePoint.new(Field.mul(point.x, inverse_z_squared),
          Field.mul(point.y, Field.mul(inverse_z, inverse_z_squared)))
      end
      list_of_affine
    end

# 0P, 1P, ..., 15P. Each odd entry is the one before it plus P; the two
# are never equal, since [i]P = P would need i = 1 mod n, and the group
# order n is far above 15. Each even entry is a doubling.
    def self.multiples_of(point : Point) : StaticArray(Point, 16)
      multiples = StaticArray(Point, 16).new(Point.neutral)
      multiples[1] = point
      2.upto(15) do |index|
        multiples[index] = index.even? ? multiples[index // 2].double : multiples[index - 1].add(point)
      end
      multiples
    end

    # Returns [scalar]point for a big-endian *scalar* of BYTESIZE bytes
    # below the group order n, in constant time, with *multiples* =
    # `multiples_of(point)`: from the most significant 4-bit window, four
    # doublings and then the addition of the window's multiple, picked by
    # scanning all 16. Before the addition the sum is [16·h]P, where h is
    # the scalar's part above the window; it is infinity when h = 0 and
    # never equals the window's multiple [d]P otherwise, since
    # 16 <= 16·h <= scalar < n and d < 16.
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

# Returns [scalar]G for a big-endian *scalar* of BYTESIZE bytes below
# the group order n, in constant time, with no doubling: from the least
# significant 4-bit window up, the window's multiple [d·16^i]G, picked
# from the precomputed table by scanning all 15 entries, is added in
# affine form, and a zero window adds nothing (by mask). The sum before
# window i is [scalar mod 16^i]G, and scalar mod 16^i < 16^i <= d·16^i
# <= scalar < n, so the two operands are never equal.
    def self.multiply_generator(scalar : Bytes) : Point
      list_of_tables = generator_window_tables
      result = Point.neutral
      window_count = BYTESIZE * 2
      window_count.times do |window_index|
        byte = scalar.unsafe_fetch(BYTESIZE - 1 - (window_index >> 1)).to_u64
        nibble = (byte >> (window_index.odd? ? 4 : 0)) & 0xf_u64
        table = list_of_tables.unsafe_fetch(window_index)
        selected_x = Limbs.new(0_u64)
        selected_y = Limbs.new(0_u64)
        1.upto(15) do |candidate|
          is_candidate = ConstantTimeSelection.equal_bit(candidate.to_u64, nibble)
          entry = table.unsafe_fetch(candidate)
          selected_x = Field.selectznz(is_candidate, selected_x, entry.x)
          selected_y = Field.selectznz(is_candidate, selected_y, entry.y)
        end
        result = result.add_affine(AffinePoint.new(selected_x, selected_y), ConstantTimeSelection.equal_bit(nibble, 0_u64))
      end
      result
    end

    # The width-*width* signed digits of a public big-endian *scalar*
    # (non-adjacent form): every nonzero digit is odd and below
    # 2^(width - 1) in size, and at most one of any *width* digits in a row
    # is nonzero. Digit i weighs 2^i.
    def self.signed_digits(scalar : Bytes, width : Int32) : Array(Int32)
      words = Array(UInt64).new(LIMB_COUNT + 1, 0_u64)
      BYTESIZE.times do |offset|
        words[offset >> 3] |= scalar[BYTESIZE - 1 - offset].to_u64 << ((offset & 7) * 8)
      end
      list_of_digits = Array(Int32).new(BYTESIZE * 8 + 1, 0)
      window_mask = (1_u64 << width) - 1
      position = 0
      until words.all?(&.zero?)
        if words[0].odd?
          digit = (words[0] & window_mask).to_i32
          digit -= 1 << width if digit >= 1 << (width - 1)
          if digit > 0
            borrow = digit.to_u64
            words.size.times do |index|
              before = words[index]
              words[index] = before &- borrow
              borrow = before < borrow ? 1_u64 : 0_u64
            end
          else
            carry = (-digit).to_u64
            words.size.times do |index|
              words[index] = words[index] &+ carry
              carry = words[index] < carry ? 1_u64 : 0_u64
            end
          end
          list_of_digits[position] = digit
        end
        (words.size - 1).times { |index| words[index] = (words[index] >> 1) | (words[index + 1] << 63) }
        words[words.size - 1] >>= 1
        position += 1
      end
      list_of_digits
    end

    # Returns [first_scalar]G + [second_scalar]point, in variable time, for
    # signature verification, where every input is public: both scalars in
    # signed digits (width 7 for G, from the precomputed odd multiples; width
    # 5 for the point), one shared run of doublings.
    def self.multiply_and_add_public(first_scalar : Bytes, point : Point, second_scalar : Bytes) : Point
      first_digits = signed_digits(first_scalar, 7)
      second_digits = signed_digits(second_scalar, 5)
      generator_multiples = generator_odd_multiples
      point_multiples = Array(Point).new(8, point)
      twice_point = point.double
      1.upto(7) { |index| point_multiples[index] = point_multiples[index - 1].add_public(twice_point) }

      result = Point.neutral
      (first_digits.size - 1).downto(0) do |position|
        result = result.double unless neutral_bit(result) == 1
        first_digit = first_digits[position]
        if first_digit != 0
          multiple = generator_multiples[first_digit.abs >> 1]
          multiple = AffinePoint.new(multiple.x, Field.opp(multiple.y)) if first_digit < 0
          result = result.add_affine_public(multiple)
        end
        second_digit = second_digits[position]
        if second_digit != 0
          multiple = point_multiples[second_digit.abs >> 1]
          multiple = multiple.negate if second_digit < 0
          result = result.add_public(multiple)
        end
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
