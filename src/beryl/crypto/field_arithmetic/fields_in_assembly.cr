require "./p256_field"
require "./p256_scalar_field"
require "./p384_field"
require "./p384_scalar_field"

module Beryl::Crypto::FieldArithmetic
  # :nodoc:
  #
  # Montgomery multiplication, squaring, addition and subtraction written in
  # assembly for AArch64 and x86-64, for the prime-order curves (milestone
  # F3 of plans/BERYL_TLS_CRYPTO.md). The fiat-crypto translations are
  # correct and constant time, but LLVM compiles their carry chains through
  # 128-bit integers into about twice the instructions a hand-written chain
  # of `adds`/`adcs` (or `add`/`adc`) needs.
  #
  # Each function returns exactly what the fiat-crypto function of the same
  # name returns, for every input inside fiat-crypto's input bounds (every
  # value of every limb), so the curve code may use either.
  # spec/field_arithmetic/fiat_crypto_equality.cr checks that against
  # fiat-crypto's own C, as it checks the translations. Why the results
  # match bit for bit: a word-by-word Montgomery multiplication adds the
  # unique multiple M·p, 0 <= M < 2^(64n), that makes a·b + M·p divisible by
  # 2^(64n) (M is fixed by a·b mod 2^(64n) alone), divides, and subtracts
  # p once when the quotient is at least p. Whether the product is reduced
  # word by word as it is formed or after it is complete, the quotient is
  # the same integer, and so is the result.
  #
  # Constant time: the assembly has no branch and no memory address computed
  # from data; a result is chosen with `csel` (AArch64) or `cmovnc` (x86-64),
  # which do not branch. `mul`, `umulh` and `mulq` take a fixed time on the
  # processors Beryl supports (with Data Independent Timing on, on Arm).
  # `scripts/check_secret_flow.rb` checks the text of every statement.
  #
  # -Dberyl_portable_curves builds the fiat-crypto translations alone, as CI
  # does once to keep that path tested.
  module FieldsInAssembly
    {% if (flag?(:aarch64) || flag?(:x86_64)) && !flag?(:beryl_portable_curves) %}
      AVAILABLE = true
    {% else %}
      AVAILABLE = false
    {% end %}

    # Defines, in the module it is called in, the fiat-crypto functions the
    # curve code uses that have no assembly: they are fast already.
    macro forward_to_fiat_crypto(fiat_module)
      @[AlwaysInline]
      def self.set_one : Limbs
        {{ fiat_module }}.set_one
      end

      @[AlwaysInline]
      def self.selectznz(condition : UInt64, zero_case : Limbs, nonzero_case : Limbs) : Limbs
        {{ fiat_module }}.selectznz(condition, zero_case, nonzero_case)
      end

      @[AlwaysInline]
      def self.nonzero(element : Limbs) : UInt64
        {{ fiat_module }}.nonzero(element)
      end

      @[AlwaysInline]
      def self.to_montgomery(element : Limbs) : Limbs
        {{ fiat_module }}.to_montgomery(element)
      end

      @[AlwaysInline]
      def self.from_montgomery(element : Limbs) : Limbs
        {{ fiat_module }}.from_montgomery(element)
      end

      @[AlwaysInline]
      def self.subborrowx_u64(borrow : UInt64, first : UInt64, second : UInt64) : {UInt64, UInt64}
        {{ fiat_module }}.subborrowx_u64(borrow, first, second)
      end
    end

    # The text of an AArch64 Montgomery multiplication modulo the P-256
    # prime, on operands: $0 to $7 the eight words of the product (the low
    # four end as the result), $8 to $11 scratch, $12 to $15 the words of a
    # and $16 to $19 the words of b (both little-endian). *square* builds
    # a squaring instead, which forms each cross product a_i·a_j once and
    # doubles the sum; it reads only $12 to $15.
    #
    # The low half of the product is reduced word by word: for P-256,
    # -p^-1 = 1 mod 2^64, so the multiplier of each step is the low word w
    # itself, and w·p = w·2^256 - w·2^224 + w·2^192 + w·2^96 - w needs no
    # multiplication: adding it and dropping the low word adds w·2^32 to
    # the next word and w·(2^64 - 2^32 + 1) = (w << 64) - (w << 32) + w to
    # the two above it. The reduced low half (below p + 1) plus the high
    # half is below 2^257, and one conditional subtraction of p ends it.
    macro p256_aarch64_statement(square, first_factor, second_factor)
      {%
        product = (0..7).map { |index| "$#{index}" }
        scratch = (8..11).map { |index| "$#{index}" }
        a_words = (12..15).map { |index| "$#{index}" }
        b_words = (16..19).map { |index| "$#{index}" }
        lines = [] of StringLiteral
      %}
      {% if square %}
        {%
          lines << "mul #{product[1].id}, #{a_words[0].id}, #{a_words[1].id}"
          lines << "umulh #{scratch[0].id}, #{a_words[0].id}, #{a_words[1].id}"
          lines << "mul #{product[2].id}, #{a_words[0].id}, #{a_words[2].id}"
          lines << "umulh #{scratch[1].id}, #{a_words[0].id}, #{a_words[2].id}"
          lines << "mul #{product[3].id}, #{a_words[0].id}, #{a_words[3].id}"
          lines << "umulh #{product[4].id}, #{a_words[0].id}, #{a_words[3].id}"
          lines << "adds #{product[2].id}, #{product[2].id}, #{scratch[0].id}"
          lines << "adcs #{product[3].id}, #{product[3].id}, #{scratch[1].id}"
          lines << "adc #{product[4].id}, #{product[4].id}, xzr"
          lines << "mul #{scratch[0].id}, #{a_words[1].id}, #{a_words[2].id}"
          lines << "umulh #{scratch[1].id}, #{a_words[1].id}, #{a_words[2].id}"
          lines << "mul #{scratch[2].id}, #{a_words[1].id}, #{a_words[3].id}"
          lines << "umulh #{product[5].id}, #{a_words[1].id}, #{a_words[3].id}"
          lines << "adds #{scratch[1].id}, #{scratch[1].id}, #{scratch[2].id}"
          lines << "adc #{product[5].id}, #{product[5].id}, xzr"
          lines << "adds #{product[3].id}, #{product[3].id}, #{scratch[0].id}"
          lines << "adcs #{product[4].id}, #{product[4].id}, #{scratch[1].id}"
          lines << "adc #{product[5].id}, #{product[5].id}, xzr"
          lines << "mul #{scratch[0].id}, #{a_words[2].id}, #{a_words[3].id}"
          lines << "umulh #{product[6].id}, #{a_words[2].id}, #{a_words[3].id}"
          lines << "adds #{product[5].id}, #{product[5].id}, #{scratch[0].id}"
          lines << "adc #{product[6].id}, #{product[6].id}, xzr"
          lines << "adds #{product[1].id}, #{product[1].id}, #{product[1].id}"
        %}
        {% for index in 2..6 %}
          {% lines << "adcs #{product[index].id}, #{product[index].id}, #{product[index].id}" %}
        {% end %}
        {%
          lines << "adc #{product[7].id}, xzr, xzr"
          lines << "mul #{product[0].id}, #{a_words[0].id}, #{a_words[0].id}"
          lines << "umulh #{scratch[0].id}, #{a_words[0].id}, #{a_words[0].id}"
          lines << "mul #{scratch[1].id}, #{a_words[1].id}, #{a_words[1].id}"
          lines << "umulh #{scratch[2].id}, #{a_words[1].id}, #{a_words[1].id}"
          lines << "adds #{product[1].id}, #{product[1].id}, #{scratch[0].id}"
          lines << "adcs #{product[2].id}, #{product[2].id}, #{scratch[1].id}"
          lines << "adcs #{product[3].id}, #{product[3].id}, #{scratch[2].id}"
          lines << "mul #{scratch[0].id}, #{a_words[2].id}, #{a_words[2].id}"
          lines << "umulh #{scratch[1].id}, #{a_words[2].id}, #{a_words[2].id}"
          lines << "mul #{scratch[2].id}, #{a_words[3].id}, #{a_words[3].id}"
          lines << "umulh #{scratch[3].id}, #{a_words[3].id}, #{a_words[3].id}"
          lines << "adcs #{product[4].id}, #{product[4].id}, #{scratch[0].id}"
          lines << "adcs #{product[5].id}, #{product[5].id}, #{scratch[1].id}"
          lines << "adcs #{product[6].id}, #{product[6].id}, #{scratch[2].id}"
          lines << "adc #{product[7].id}, #{product[7].id}, #{scratch[3].id}"
        %}
      {% else %}
        {% for column in 0..3 %}
          {% lines << "mul #{product[column].id}, #{a_words[0].id}, #{b_words[column].id}" %}
        {% end %}
        {% for column in 0..3 %}
          {% lines << "umulh #{scratch[column].id}, #{a_words[0].id}, #{b_words[column].id}" %}
        {% end %}
        {%
          lines << "adds #{product[1].id}, #{product[1].id}, #{scratch[0].id}"
          lines << "adcs #{product[2].id}, #{product[2].id}, #{scratch[1].id}"
          lines << "adcs #{product[3].id}, #{product[3].id}, #{scratch[2].id}"
          lines << "adc #{product[4].id}, #{scratch[3].id}, xzr"
        %}
        {% for row in 1..3 %}
          {% for column in 0..3 %}
            {% lines << "mul #{scratch[column].id}, #{a_words[row].id}, #{b_words[column].id}" %}
          {% end %}
          {% lines << "adds #{product[row].id}, #{product[row].id}, #{scratch[0].id}" %}
          {% for column in 1..3 %}
            {% lines << "adcs #{product[row + column].id}, #{product[row + column].id}, #{scratch[column].id}" %}
          {% end %}
          {% lines << "adc #{product[row + 4].id}, xzr, xzr" %}
          {% for column in 0..3 %}
            {% lines << "umulh #{scratch[column].id}, #{a_words[row].id}, #{b_words[column].id}" %}
          {% end %}
          {% lines << "adds #{product[row + 1].id}, #{product[row + 1].id}, #{scratch[0].id}" %}
          {% for column in 1..2 %}
            {% lines << "adcs #{product[row + 1 + column].id}, #{product[row + 1 + column].id}, #{scratch[column].id}" %}
          {% end %}
          {% lines << "adc #{product[row + 4].id}, #{product[row + 4].id}, #{scratch[3].id}" %}
        {% end %}
      {% end %}
      {% low = [product[0], product[1], product[2], product[3]] %}
      {% for step in 0..3 %}
        {%
          word = low[0]
          lines << "lsl #{scratch[0].id}, #{word.id}, #32"
          lines << "lsr #{scratch[1].id}, #{word.id}, #32"
          lines << "subs #{scratch[2].id}, #{word.id}, #{scratch[0].id}"
          lines << "sbc #{scratch[3].id}, #{word.id}, #{scratch[1].id}"
          lines << "adds #{low[1].id}, #{low[1].id}, #{scratch[0].id}"
          lines << "adcs #{low[2].id}, #{low[2].id}, #{scratch[1].id}"
          lines << "adcs #{low[3].id}, #{low[3].id}, #{scratch[2].id}"
          lines << "adc #{word.id}, #{scratch[3].id}, xzr"
          low = [low[1], low[2], low[3], low[0]]
        %}
      {% end %}
      {%
        lines << "adds #{product[0].id}, #{product[0].id}, #{product[4].id}"
        lines << "adcs #{product[1].id}, #{product[1].id}, #{product[5].id}"
        lines << "adcs #{product[2].id}, #{product[2].id}, #{product[6].id}"
        lines << "adcs #{product[3].id}, #{product[3].id}, #{product[7].id}"
        lines << "adc #{product[4].id}, xzr, xzr"
        lines << "mov #{product[5].id}, #0xffffffff"
        lines << "lsl #{product[6].id}, #{product[5].id}, #32"
        lines << "add #{product[6].id}, #{product[6].id}, #1"
        lines << "adds #{scratch[0].id}, #{product[0].id}, #1"
        lines << "sbcs #{scratch[1].id}, #{product[1].id}, #{product[5].id}"
        lines << "sbcs #{scratch[2].id}, #{product[2].id}, xzr"
        lines << "sbcs #{scratch[3].id}, #{product[3].id}, #{product[6].id}"
        lines << "sbcs xzr, #{product[4].id}, xzr"
      %}
      {% for index in 0..3 %}
        {% lines << "csel #{product[index].id}, #{product[index].id}, #{scratch[index].id}, lo" %}
      {% end %}
      product_0 = product_1 = product_2 = product_3 = product_4 = product_5 = product_6 = product_7 = 0_u64
      scratch_0 = scratch_1 = scratch_2 = scratch_3 = 0_u64
      asm({{ lines.join("\n") }} : "=&r"(product_0), "=&r"(product_1), "=&r"(product_2), "=&r"(product_3),
                                   "=&r"(product_4), "=&r"(product_5), "=&r"(product_6), "=&r"(product_7),
                                   "=&r"(scratch_0), "=&r"(scratch_1), "=&r"(scratch_2), "=&r"(scratch_3)
                                 : "r"({{ first_factor }}.unsafe_fetch(0)), "r"({{ first_factor }}.unsafe_fetch(1)), "r"({{ first_factor }}.unsafe_fetch(2)), "r"({{ first_factor }}.unsafe_fetch(3)),
                                   "r"({{ second_factor }}.unsafe_fetch(0)), "r"({{ second_factor }}.unsafe_fetch(1)), "r"({{ second_factor }}.unsafe_fetch(2)), "r"({{ second_factor }}.unsafe_fetch(3))
                                 : "cc")
      StaticArray[product_0, product_1, product_2, product_3]
    end

    # The text of an x86-64 Montgomery multiplication modulo the P-256 prime
    # on memory: $0 points at the result, $1 at a, $2 at b. The product
    # words live in r8 to r15; rax, rdx and rcx are scratch. The reduction
    # is the one described for AArch64.
    macro p256_x86_64_statement(result, a, b)
      {%
        product = %w(%r8 %r9 %r10 %r11 %r12 %r13 %r14 %r15)
        lines = [] of StringLiteral
        lines << "movq 0($1), %rax"
        lines << "mulq 0($2)"
        lines << "movq %rax, #{product[0].id}"
        lines << "movq %rdx, #{product[1].id}"
      %}
      {% for column in 1..3 %}
        {%
          lines << "movq 0($1), %rax"
          lines << "mulq #{8 * column}($2)"
          lines << "addq %rax, #{product[column].id}"
          lines << "adcq $$0, %rdx"
          lines << "movq %rdx, #{product[column + 1].id}"
        %}
      {% end %}
      {% for row in 1..3 %}
        {%
          lines << "movq #{8 * row}($1), %rax"
          lines << "mulq 0($2)"
          lines << "addq %rax, #{product[row].id}"
          lines << "adcq $$0, %rdx"
          lines << "movq %rdx, %rcx"
        %}
        {% for column in 1..3 %}
          {%
            lines << "movq #{8 * row}($1), %rax"
            lines << "mulq #{8 * column}($2)"
            lines << "addq %rcx, %rax"
            lines << "adcq $$0, %rdx"
            lines << "addq %rax, #{product[row + column].id}"
            lines << "adcq $$0, %rdx"
            lines << "movq %rdx, %rcx"
          %}
        {% end %}
        {% lines << "movq %rcx, #{product[row + 4].id}" %}
      {% end %}
      {% low = [product[0], product[1], product[2], product[3]] %}
      {% for step in 0..3 %}
        {%
          word = low[0]
          lines << "movq #{word.id}, %rax"
          lines << "shlq $$32, %rax"
          lines << "movq #{word.id}, %rdx"
          lines << "shrq $$32, %rdx"
          lines << "movq #{word.id}, %rcx"
          lines << "subq %rax, %rcx"
          lines << "sbbq %rdx, #{word.id}"
          lines << "addq %rax, #{low[1].id}"
          lines << "adcq %rdx, #{low[2].id}"
          lines << "adcq %rcx, #{low[3].id}"
          lines << "adcq $$0, #{word.id}"
          low = [low[1], low[2], low[3], low[0]]
        %}
      {% end %}
      {%
        lines << "addq #{product[4].id}, #{product[0].id}"
        lines << "adcq #{product[5].id}, #{product[1].id}"
        lines << "adcq #{product[6].id}, #{product[2].id}"
        lines << "adcq #{product[7].id}, #{product[3].id}"
        lines << "movl $$0, %ecx"
        lines << "adcq $$0, %rcx"
      %}
      {% for index in 0..3 %}
        {% lines << "movq #{product[index].id}, #{product[index + 4].id}" %}
      {% end %}
      {%
        lines << "movl $$0xffffffff, %eax"
        lines << "movabsq $$0xffffffff00000001, %rdx"
        lines << "subq $$-1, #{product[4].id}"
        lines << "sbbq %rax, #{product[5].id}"
        lines << "sbbq $$0, #{product[6].id}"
        lines << "sbbq %rdx, #{product[7].id}"
        lines << "sbbq $$0, %rcx"
      %}
      {% for index in 0..3 %}
        {% lines << "cmovncq #{product[index + 4].id}, #{product[index].id}" %}
      {% end %}
      {% for index in 0..3 %}
        {% lines << "movq #{product[index].id}, #{8 * index}($0)" %}
      {% end %}
      asm({{ lines.join("\n") }}
        :: "r"(pointerof({{ result }})), "r"(pointerof({{ a }})), "r"(pointerof({{ b }}))
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", "cc")
    end

    # The text of an AArch64 Montgomery multiplication modulo any odd
    # modulus of *word_count* words, word by word (coarsely integrated
    # operand scanning): $0 points at the result, $1 at a, $2 at b, $3 at
    # the modulus, and $4 holds -p^-1 mod 2^64. Registers x0 to x17 and
    # x19 to x22 are scratch: the words of b, the running sum (word_count + 2
    # words) and four temporaries. The sum stays below 2p < 2^(64n + 1)
    # between steps, so one conditional subtraction ends it.
    macro montgomery_aarch64_statement(word_count, result, first_factor, second_factor, modulus, negated_inverse)
      {%
        registers = %w(x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x19 x20 x21 x22)
        b_words = registers[0...word_count]
        sum = registers[word_count...(2 * word_count + 2)]
        temporary = registers[(2 * word_count + 2)...(2 * word_count + 6)]
        a_word = temporary[0]
        product = temporary[1]
        multiplier = temporary[2]
        modulus_word = temporary[3]
        lines = [] of StringLiteral
      %}
      {% for index in 0...word_count %}
        {% lines << "ldr #{b_words[index].id}, [$2, ##{8 * index}]" %}
      {% end %}
      {% for index in 0...(word_count + 2) %}
        {% lines << "mov #{sum[index].id}, xzr" %}
      {% end %}
      {% for row in 0...word_count %}
        {% lines << "ldr #{a_word.id}, [$1, ##{8 * row}]" %}
        {% for column in 0...word_count %}
          {% lines << "mul #{product.id}, #{a_word.id}, #{b_words[column].id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column].id}, #{sum[column].id}, #{product.id}" %}
        {% end %}
        {% lines << "adcs #{sum[word_count].id}, #{sum[word_count].id}, xzr" %}
        {% lines << "adc #{sum[word_count + 1].id}, xzr, xzr" %}
        {% for column in 0...word_count %}
          {% lines << "umulh #{product.id}, #{a_word.id}, #{b_words[column].id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column + 1].id}, #{sum[column + 1].id}, #{product.id}" %}
        {% end %}
        {% lines << "adc #{sum[word_count + 1].id}, #{sum[word_count + 1].id}, xzr" %}
        {% lines << "mul #{multiplier.id}, #{sum[0].id}, $4" %}
        {% for column in 0...word_count %}
          {% lines << "ldr #{modulus_word.id}, [$3, ##{8 * column}]" %}
          {% lines << "mul #{product.id}, #{multiplier.id}, #{modulus_word.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column].id}, #{sum[column].id}, #{product.id}" %}
        {% end %}
        {% lines << "adcs #{sum[word_count].id}, #{sum[word_count].id}, xzr" %}
        {% lines << "adc #{sum[word_count + 1].id}, #{sum[word_count + 1].id}, xzr" %}
        {% for column in 0...word_count %}
          {% lines << "ldr #{modulus_word.id}, [$3, ##{8 * column}]" %}
          {% lines << "umulh #{product.id}, #{multiplier.id}, #{modulus_word.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column + 1].id}, #{sum[column + 1].id}, #{product.id}" %}
        {% end %}
        {% lines << "adc #{sum[word_count + 1].id}, #{sum[word_count + 1].id}, xzr" %}
        {% sum = sum[1..-1] + [sum[0]] %}
      {% end %}
      {% for column in 0...word_count %}
        {% lines << "ldr #{modulus_word.id}, [$3, ##{8 * column}]" %}
        {% lines << "#{(column == 0 ? "subs" : "sbcs").id} #{b_words[column].id}, #{sum[column].id}, #{modulus_word.id}" %}
      {% end %}
      {% lines << "sbcs xzr, #{sum[word_count].id}, xzr" %}
      {% for column in 0...word_count %}
        {% lines << "csel #{sum[column].id}, #{sum[column].id}, #{b_words[column].id}, lo" %}
        {% lines << "str #{sum[column].id}, [$0, ##{8 * column}]" %}
      {% end %}
      asm({{ lines.join("\n") }}
        :: "r"(pointerof({{ result }})), "r"(pointerof({{ first_factor }})), "r"(pointerof({{ second_factor }})), "r"(pointerof({{ modulus }})), "r"({{ negated_inverse }})
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x19", "x20", "x21", "x22", "memory", "cc")
    end
  end

  # :nodoc:
  #
  # The P-256 field as the curve code uses it: fiat-crypto's `P256Field`,
  # with multiplication, squaring, addition, subtraction and negation in
  # assembly where `FieldsInAssembly` has them.
  module P256FieldWithAssembly
    alias Limbs = P256Field::Limbs

    {% if flag?(:aarch64) && !flag?(:beryl_portable_curves) %}
      @[AlwaysInline]
      def self.mul(a : Limbs, b : Limbs) : Limbs
        FieldsInAssembly.p256_aarch64_statement(false, a, b)
      end

      @[AlwaysInline]
      def self.square(a : Limbs) : Limbs
        FieldsInAssembly.p256_aarch64_statement(true, a, a)
      end

      # fiat-crypto's `add`: a + b, less p unless that borrows.
      @[AlwaysInline]
      def self.add(a : Limbs, b : Limbs) : Limbs
        sum_0 = sum_1 = sum_2 = sum_3 = carry = 0_u64
        difference_0 = difference_1 = difference_2 = difference_3 = prime_1 = prime_3 = 0_u64
        asm("adds $0, $11, $15
          adcs $1, $12, $16
          adcs $2, $13, $17
          adcs $3, $14, $18
          adc $4, xzr, xzr
          mov $9, #0xffffffff
          lsl $10, $9, #32
          add $10, $10, #1
          adds $5, $0, #1
          sbcs $6, $1, $9
          sbcs $7, $2, xzr
          sbcs $8, $3, $10
          sbcs xzr, $4, xzr
          csel $0, $0, $5, lo
          csel $1, $1, $6, lo
          csel $2, $2, $7, lo
          csel $3, $3, $8, lo" : "=&r"(sum_0), "=&r"(sum_1), "=&r"(sum_2), "=&r"(sum_3), "=&r"(carry),
                                 "=&r"(difference_0), "=&r"(difference_1), "=&r"(difference_2), "=&r"(difference_3),
                                 "=&r"(prime_1), "=&r"(prime_3)
                               : "r"(a.unsafe_fetch(0)), "r"(a.unsafe_fetch(1)), "r"(a.unsafe_fetch(2)), "r"(a.unsafe_fetch(3)),
                                 "r"(b.unsafe_fetch(0)), "r"(b.unsafe_fetch(1)), "r"(b.unsafe_fetch(2)), "r"(b.unsafe_fetch(3))
                               : "cc")
        StaticArray[sum_0, sum_1, sum_2, sum_3]
      end

      # fiat-crypto's `sub`: a - b, plus p when that borrows.
      @[AlwaysInline]
      def self.sub(a : Limbs, b : Limbs) : Limbs
        difference_0 = difference_1 = difference_2 = difference_3 = mask = masked_1 = masked_3 = low_bit = 0_u64
        asm("subs $0, $8, $12
          sbcs $1, $9, $13
          sbcs $2, $10, $14
          sbcs $3, $11, $15
          sbc $4, xzr, xzr
          and $5, $4, #0xffffffff
          and $7, $4, #1
          orr $6, $7, $5, lsl #32
          adds $0, $0, $4
          adcs $1, $1, $5
          adcs $2, $2, xzr
          adc $3, $3, $6" : "=&r"(difference_0), "=&r"(difference_1), "=&r"(difference_2), "=&r"(difference_3),
                            "=&r"(mask), "=&r"(masked_1), "=&r"(masked_3), "=&r"(low_bit)
                          : "r"(a.unsafe_fetch(0)), "r"(a.unsafe_fetch(1)), "r"(a.unsafe_fetch(2)), "r"(a.unsafe_fetch(3)),
                            "r"(b.unsafe_fetch(0)), "r"(b.unsafe_fetch(1)), "r"(b.unsafe_fetch(2)), "r"(b.unsafe_fetch(3))
                          : "cc")
        StaticArray[difference_0, difference_1, difference_2, difference_3]
      end

      @[AlwaysInline]
      def self.opp(a : Limbs) : Limbs
        sub(Limbs.new(0_u64), a)
      end
    {% elsif flag?(:x86_64) && !flag?(:beryl_portable_curves) %}
      def self.mul(a : Limbs, b : Limbs) : Limbs
        result = uninitialized Limbs
        FieldsInAssembly.p256_x86_64_statement(result, a, b)
        result
      end

      @[AlwaysInline]
      def self.square(a : Limbs) : Limbs
        mul(a, a)
      end

      @[AlwaysInline]
      def self.add(a : Limbs, b : Limbs) : Limbs
        P256Field.add(a, b)
      end

      @[AlwaysInline]
      def self.sub(a : Limbs, b : Limbs) : Limbs
        P256Field.sub(a, b)
      end

      @[AlwaysInline]
      def self.opp(a : Limbs) : Limbs
        P256Field.opp(a)
      end
    {% else %}
      @[AlwaysInline]
      def self.mul(a : Limbs, b : Limbs) : Limbs
        P256Field.mul(a, b)
      end

      @[AlwaysInline]
      def self.square(a : Limbs) : Limbs
        P256Field.square(a)
      end

      @[AlwaysInline]
      def self.add(a : Limbs, b : Limbs) : Limbs
        P256Field.add(a, b)
      end

      @[AlwaysInline]
      def self.sub(a : Limbs, b : Limbs) : Limbs
        P256Field.sub(a, b)
      end

      @[AlwaysInline]
      def self.opp(a : Limbs) : Limbs
        P256Field.opp(a)
      end
    {% end %}

    FieldsInAssembly.forward_to_fiat_crypto(P256Field)
  end

  {% for fiat_module, settings in {P256ScalarField: {4, "0xccd1c8aaee00bc4f", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"},
                                   P384Field:       {6, "0x100000001", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"},
                                   P384ScalarField: {6, "0x6ed46089e88fdc45", "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"}} %}
    {% word_count = settings[0] %}
    # :nodoc:
    #
    # fiat-crypto's `{{ fiat_module }}`, with multiplication and squaring in
    # assembly on AArch64 (`FieldsInAssembly.montgomery_aarch64_statement`).
    module {{ fiat_module }}WithAssembly
      alias Limbs = {{ fiat_module }}::Limbs

      # The modulus as little-endian words, and -modulus^-1 mod 2^64, which
      # the assembly reads (spec/beryl/crypto/fields_in_assembly_spec.cr
      # checks both).
      MODULUS_WORDS = StaticArray[{% for index in 0...word_count %}{{ ("0x" + settings[2][((word_count - 1 - index) * 16)...((word_count - index) * 16)] + "_u64").id }}, {% end %}]
      NEGATED_MODULUS_INVERSE = {{ (settings[1] + "_u64").id }}

      {% if flag?(:aarch64) && !flag?(:beryl_portable_curves) %}
        def self.mul(a : Limbs, b : Limbs) : Limbs
          result = uninitialized Limbs
          modulus = MODULUS_WORDS
          FieldsInAssembly.montgomery_aarch64_statement({{ word_count }}, result, a, b, modulus, NEGATED_MODULUS_INVERSE)
          result
        end

        @[AlwaysInline]
        def self.square(a : Limbs) : Limbs
          mul(a, a)
        end
      {% else %}
        @[AlwaysInline]
        def self.mul(a : Limbs, b : Limbs) : Limbs
          {{ fiat_module }}.mul(a, b)
        end

        @[AlwaysInline]
        def self.square(a : Limbs) : Limbs
          {{ fiat_module }}.square(a)
        end
      {% end %}

      @[AlwaysInline]
      def self.add(a : Limbs, b : Limbs) : Limbs
        {{ fiat_module }}.add(a, b)
      end

      @[AlwaysInline]
      def self.sub(a : Limbs, b : Limbs) : Limbs
        {{ fiat_module }}.sub(a, b)
      end

      @[AlwaysInline]
      def self.opp(a : Limbs) : Limbs
        {{ fiat_module }}.opp(a)
      end

      FieldsInAssembly.forward_to_fiat_crypto({{ fiat_module }})
    end
  {% end %}
end
