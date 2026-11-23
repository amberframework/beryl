module Beryl::Crypto::V1
  # :nodoc:
  #
  # Montgomery multiplication for RSA written in AArch64 assembly
  # (milestone F3 of plans/BERYL_TLS_CRYPTO.md), one copy for each word
  # count `MontgomeryArithmetic` specializes. It computes what
  # `MontgomeryArithmetic.multiply` computes, word by word (coarsely
  # integrated operand scanning): for each word of b, add a·b[i] and then
  # u·m, where u = sum[0]·(-m^-1) mod 2^64 clears the low word, and move the
  # sum down a word; one subtraction of m, kept or dropped by `csel`, ends
  # it. The result is the same integer, so the two are interchangeable,
  # and spec/beryl/crypto/v1/montgomery_arithmetic_spec.cr compares them.
  #
  # Two forms:
  # - 16 words (the primes of a 2,048-bit key): the running sum lives in
  #   registers and the carries in the processor's carry flag, so each
  #   word product costs a `mul` or `umulh` and an `adcs`; squaring, most
  #   of the work of an exponentiation, has its own copy
  #   (`square_16_words_statement`).
  # - more words: the sum lives in memory (`scratch`), and the carries in
  #   registers.
  #
  # Constant time: one loop, over the words of b, whose count is the word
  # count (public); no other branch, and no address computed from data.
  # `scripts/check_secret_flow.rb` checks the text.
  module MontgomeryMultiplicationInAssembly
    {% if flag?(:aarch64) && !flag?(:beryl_portable_rsa) %}
      AVAILABLE = true
    {% else %}
      AVAILABLE = false
    {% end %}

    # Registers: x0 to x17 and x19 to x22 hold the sum (18 words) and four
    # temporaries; $0 points at the result, $1 at a, $2 at b, $3 at the
    # modulus, and $4 holds -m^-1 mod 2^64.
    macro multiply_16_words_statement(result, first_factor, second_factor, modulus, negated_inverse)
      {%
        registers = %w(x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x19 x20 x21 x22)
        sum = registers[0...18]
        b_word = registers[18]
        product = registers[19]
        multiplier = registers[20]
        loaded = registers[21]
        lines = [] of StringLiteral
      %}
      {% for index in 0...18 %}
        {% lines << "mov #{sum[index].id}, xzr" %}
      {% end %}
      {% for row in 0...16 %}
        {% lines << "ldr #{b_word.id}, [$2, ##{8 * row}]" %}
        {% for column in 0...16 %}
          {% lines << "ldr #{loaded.id}, [$1, ##{8 * column}]" %}
          {% lines << "mul #{product.id}, #{b_word.id}, #{loaded.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column].id}, #{sum[column].id}, #{product.id}" %}
        {% end %}
        {% lines << "adcs #{sum[16].id}, #{sum[16].id}, xzr" %}
        {% lines << "adc #{sum[17].id}, xzr, xzr" %}
        {% for column in 0...16 %}
          {% lines << "ldr #{loaded.id}, [$1, ##{8 * column}]" %}
          {% lines << "umulh #{product.id}, #{b_word.id}, #{loaded.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column + 1].id}, #{sum[column + 1].id}, #{product.id}" %}
        {% end %}
        {% lines << "adc #{sum[17].id}, #{sum[17].id}, xzr" %}
        {% lines << "mul #{multiplier.id}, #{sum[0].id}, $4" %}
        {% for column in 0...16 %}
          {% lines << "ldr #{loaded.id}, [$3, ##{8 * column}]" %}
          {% lines << "mul #{product.id}, #{multiplier.id}, #{loaded.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column].id}, #{sum[column].id}, #{product.id}" %}
        {% end %}
        {% lines << "adcs #{sum[16].id}, #{sum[16].id}, xzr" %}
        {% lines << "adc #{sum[17].id}, #{sum[17].id}, xzr" %}
        {% for column in 0...16 %}
          {% lines << "ldr #{loaded.id}, [$3, ##{8 * column}]" %}
          {% lines << "umulh #{product.id}, #{multiplier.id}, #{loaded.id}" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column + 1].id}, #{sum[column + 1].id}, #{product.id}" %}
        {% end %}
        {% lines << "adc #{sum[17].id}, #{sum[17].id}, xzr" %}
        {% sum = sum[1..-1] + [sum[0]] %}
      {% end %}
      {% for column in 0...16 %}
        {% lines << "ldr #{loaded.id}, [$3, ##{8 * column}]" %}
        {% lines << "#{(column == 0 ? "subs" : "sbcs").id} #{product.id}, #{sum[column].id}, #{loaded.id}" %}
        {% lines << "str #{product.id}, [$0, ##{8 * column}]" %}
      {% end %}
      {% lines << "sbcs xzr, #{sum[16].id}, xzr" %}
      {% for column in 0...16 %}
        {% lines << "ldr #{loaded.id}, [$0, ##{8 * column}]" %}
        {% lines << "csel #{sum[column].id}, #{sum[column].id}, #{loaded.id}, lo" %}
        {% lines << "str #{sum[column].id}, [$0, ##{8 * column}]" %}
      {% end %}
      asm({{ lines.join("\n") }}
        :: "r"({{ result }}), "r"({{ first_factor }}), "r"({{ second_factor }}), "r"({{ modulus }}), "r"({{ negated_inverse }})
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x19", "x20", "x21", "x22", "memory", "cc")
    end

    # Montgomery squaring of a 16-word number, a·a/R mod m: about a quarter
    # fewer word products than `multiply_16_words_statement`, since each
    # product a[i]·a[j] with i < j is formed once and doubled. Three steps,
    # with the 32-word square in *scratch*:
    # 1. the products a[i]·a[j], i < j, row by row, the running sum in
    #    registers as in the multiplication (each row finishes one word);
    # 2. doubling, and the squares a[i]·a[i] added on the diagonal;
    # 3. Montgomery reduction of the low 16 words alone, the multiples of m
    #    in registers, then the high 16 words added and one subtraction of m
    #    kept or dropped by `csel`. Reduction is linear, so this equals
    #    reducing all 32 words; the result is the same integer as the
    #    multiplication's, below m.
    # Registers: x0 to x17 the running sum, x19 to x22 temporaries; $0
    # points at the result, $1 at a, $2 at the modulus, $3 holds
    # -m^-1 mod 2^64 and $4 points at 32 words of scratch.
    macro square_16_words_statement(result, factor, modulus, negated_inverse, scratch)
      {%
        sum = %w(x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17)
        lines = [] of StringLiteral
      %}
      {% for index in 0...16 %}
        {% lines << "mov #{sum[index].id}, xzr" %}
      {% end %}
      {% lines << "str xzr, [$4]" %}
      {% window = sum[0...17] %}
      {% for row in 0...15 %}
        {% lines << "ldr x22, [$1, ##{8 * row}]" %}
        {% for column in (row + 1)...16 %}
          {% lines << "ldr x19, [$1, ##{8 * column}]" %}
          {% lines << "mul x20, x22, x19" %}
          {% lines << "#{(column == row + 1 ? "adds" : "adcs").id} #{window[column - 1].id}, #{window[column - 1].id}, x20" %}
        {% end %}
        {% lines << "adcs #{window[15].id}, #{window[15].id}, xzr" %}
        {% lines << "adc #{window[16].id}, xzr, xzr" %}
        {% for column in (row + 1)...16 %}
          {% lines << "ldr x19, [$1, ##{8 * column}]" %}
          {% lines << "umulh x20, x22, x19" %}
          {% lines << "#{(column == row + 1 ? "adds" : "adcs").id} #{window[column].id}, #{window[column].id}, x20" %}
        {% end %}
        {% lines << "adc #{window[16].id}, #{window[16].id}, xzr" %}
        {% lines << "str #{window[0].id}, [$4, ##{8 * (row + 1)}]" %}
        {% window = window[1..-1] + [window[0]] %}
      {% end %}
      {% for index in 0...16 %}
        {% lines << "str #{window[index].id}, [$4, ##{8 * (16 + index)}]" %}
      {% end %}
      {% for index in 0...32 %}
        {% lines << "ldr x19, [$4, ##{8 * index}]" %}
        {% lines << "#{(index == 0 ? "adds" : "adcs").id} x19, x19, x19" %}
        {% lines << "str x19, [$4, ##{8 * index}]" %}
      {% end %}
      {% for index in 0...16 %}
        {% lines << "ldr x22, [$1, ##{8 * index}]" %}
        {% lines << "mul x20, x22, x22" %}
        {% lines << "umulh x21, x22, x22" %}
        {% lines << "ldr x19, [$4, ##{16 * index}]" %}
        {% lines << "#{(index == 0 ? "adds" : "adcs").id} x19, x19, x20" %}
        {% lines << "str x19, [$4, ##{16 * index}]" %}
        {% lines << "ldr x19, [$4, ##{16 * index + 8}]" %}
        {% lines << "adcs x19, x19, x21" %}
        {% lines << "str x19, [$4, ##{16 * index + 8}]" %}
      {% end %}
      {% for index in 0...16 %}
        {% lines << "ldr #{sum[index].id}, [$4, ##{8 * index}]" %}
      {% end %}
      {% lines << "mov #{sum[16].id}, xzr" %}
      {% lines << "mov #{sum[17].id}, xzr" %}
      {% for row in 0...16 %}
        {% lines << "mul x21, #{sum[0].id}, $3" %}
        {% for column in 0...16 %}
          {% lines << "ldr x19, [$2, ##{8 * column}]" %}
          {% lines << "mul x20, x21, x19" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column].id}, #{sum[column].id}, x20" %}
        {% end %}
        {% lines << "adcs #{sum[16].id}, #{sum[16].id}, xzr" %}
        {% lines << "adc #{sum[17].id}, #{sum[17].id}, xzr" %}
        {% for column in 0...16 %}
          {% lines << "ldr x19, [$2, ##{8 * column}]" %}
          {% lines << "umulh x20, x21, x19" %}
          {% lines << "#{(column == 0 ? "adds" : "adcs").id} #{sum[column + 1].id}, #{sum[column + 1].id}, x20" %}
        {% end %}
        {% lines << "adc #{sum[17].id}, #{sum[17].id}, xzr" %}
        {% sum = sum[1..-1] + [sum[0]] %}
      {% end %}
      {% for index in 0...16 %}
        {% lines << "ldr x19, [$4, ##{8 * (16 + index)}]" %}
        {% lines << "#{(index == 0 ? "adds" : "adcs").id} #{sum[index].id}, #{sum[index].id}, x19" %}
      {% end %}
      {% lines << "adc #{sum[16].id}, #{sum[16].id}, xzr" %}
      {% for column in 0...16 %}
        {% lines << "ldr x19, [$2, ##{8 * column}]" %}
        {% lines << "#{(column == 0 ? "subs" : "sbcs").id} x20, #{sum[column].id}, x19" %}
        {% lines << "str x20, [$0, ##{8 * column}]" %}
      {% end %}
      {% lines << "sbcs xzr, #{sum[16].id}, xzr" %}
      {% for column in 0...16 %}
        {% lines << "ldr x19, [$0, ##{8 * column}]" %}
        {% lines << "csel #{sum[column].id}, #{sum[column].id}, x19, lo" %}
        {% lines << "str #{sum[column].id}, [$0, ##{8 * column}]" %}
      {% end %}
      asm({{ lines.join("\n") }}
        :: "r"({{ result }}), "r"({{ factor }}), "r"({{ modulus }}), "r"({{ negated_inverse }}), "r"({{ scratch }})
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x19", "x20", "x21", "x22", "memory", "cc")
    end

    # Registers: x0 to x6 and x9 to x14 are temporaries (x11 the word of b,
    # x12 and x14 the two carries, x13 the multiplier, x10 the count of
    # words of b left, x9 the pointer to the next one); $0 points at the
    # result, $1 at a, $2 at b, $3 at the modulus, $4 holds -m^-1 mod 2^64
    # and $5 points at the sum, *word_count* + 1 words. Each column adds
    # a[j]·b[i] and u·m[j] with their carries in registers and stores the
    # word one place down, which divides the sum by 2^64. (On Apple M4 this
    # ran at about 2.7 cycles per word product; the carry-flag chains of the
    # 16-word statement, with the sum loaded and stored around each
    # addition, ran at about 4.5.)
    macro multiply_in_memory_statement(word_count, result, first_factor, second_factor, modulus, negated_inverse, sum)
      {% lines = [] of StringLiteral %}
      {% for index in 0..word_count %}
        {% lines << "str xzr, [$5, ##{8 * index}]" %}
      {% end %}
      {%
        lines << "mov x9, $2"
        lines << "mov x10, ##{word_count}"
        lines << "1:"
        lines << "ldr x11, [x9], #8"
        lines << "ldr x0, [$1]"
        lines << "ldr x1, [$5]"
        lines << "mul x2, x0, x11"
        lines << "umulh x3, x0, x11"
        lines << "adds x2, x2, x1"
        lines << "adc x12, x3, xzr"
        lines << "mul x13, x2, $4"
        lines << "ldr x4, [$3]"
        lines << "mul x5, x13, x4"
        lines << "umulh x6, x13, x4"
        lines << "adds xzr, x5, x2"
        lines << "adc x14, x6, xzr"
      %}
      {% for column in 1...word_count %}
        {%
          lines << "ldr x0, [$1, ##{8 * column}]"
          lines << "ldr x1, [$5, ##{8 * column}]"
          lines << "ldr x4, [$3, ##{8 * column}]"
          lines << "mul x2, x0, x11"
          lines << "umulh x3, x0, x11"
          lines << "adds x2, x2, x1"
          lines << "adc x3, x3, xzr"
          lines << "adds x2, x2, x12"
          lines << "adc x12, x3, xzr"
          lines << "mul x5, x13, x4"
          lines << "umulh x6, x13, x4"
          lines << "adds x5, x5, x2"
          lines << "adc x6, x6, xzr"
          lines << "adds x5, x5, x14"
          lines << "adc x14, x6, xzr"
          lines << "str x5, [$5, ##{8 * (column - 1)}]"
        %}
      {% end %}
      {%
        lines << "ldr x1, [$5, ##{8 * word_count}]"
        lines << "adds x12, x12, x14"
        lines << "adc x2, xzr, xzr"
        lines << "adds x12, x12, x1"
        lines << "adc x2, x2, xzr"
        lines << "str x12, [$5, ##{8 * (word_count - 1)}]"
        lines << "str x2, [$5, ##{8 * word_count}]"
        lines << "subs x10, x10, #1"
        lines << "b.ne 1b"
      %}
      {% for column in 0...word_count %}
        {% lines << "ldr x0, [$5, ##{8 * column}]" %}
        {% lines << "ldr x4, [$3, ##{8 * column}]" %}
        {% lines << "#{(column == 0 ? "subs" : "sbcs").id} x0, x0, x4" %}
        {% lines << "str x0, [$0, ##{8 * column}]" %}
      {% end %}
      {% lines << "ldr x1, [$5, ##{8 * word_count}]" %}
      {% lines << "sbcs xzr, x1, xzr" %}
      {% for column in 0...word_count %}
        {% lines << "ldr x0, [$5, ##{8 * column}]" %}
        {% lines << "ldr x4, [$0, ##{8 * column}]" %}
        {% lines << "csel x0, x0, x4, lo" %}
        {% lines << "str x0, [$0, ##{8 * column}]" %}
      {% end %}
      asm({{ lines.join("\n") }}
        :: "r"({{ result }}), "r"({{ first_factor }}), "r"({{ second_factor }}), "r"({{ modulus }}), "r"({{ negated_inverse }}), "r"({{ sum }})
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x9", "x10", "x11", "x12", "x13", "x14", "memory", "cc")
    end

    {% if flag?(:aarch64) && !flag?(:beryl_portable_rsa) %}
      # Sets result to a·b/R mod m for 16-word numbers; *result* may be *a*
      # or *b*.
      def self.multiply_16(result_pointer : UInt64*, a_pointer : UInt64*, b_pointer : UInt64*, modulus_pointer : UInt64*,
                           negated_inverse : UInt64) : Nil
        multiply_16_words_statement(result_pointer, a_pointer, b_pointer, modulus_pointer, negated_inverse)
      end

      # Sets result to a·a/R mod m for 16-word numbers, with *scratch_pointer*
      # to 32 words; *result* may be *a*.
      def self.square_16(result_pointer : UInt64*, a_pointer : UInt64*, modulus_pointer : UInt64*, negated_inverse : UInt64,
                         scratch_pointer : UInt64*) : Nil
        square_16_words_statement(result_pointer, a_pointer, modulus_pointer, negated_inverse, scratch_pointer)
      end

      {% for word_count in [24, 32, 48, 64] %}
        # Sets result to a·b/R mod m for {{ word_count }}-word numbers, with
        # *sum_pointer* to {{ word_count + 1 }} words of scratch; *result*
        # may be *a* or *b*.
        def self.multiply_{{ word_count }}(result_pointer : UInt64*, a_pointer : UInt64*, b_pointer : UInt64*, modulus_pointer : UInt64*,
                                           negated_inverse : UInt64, sum_pointer : UInt64*) : Nil
          multiply_in_memory_statement({{ word_count }}, result_pointer, a_pointer, b_pointer, modulus_pointer, negated_inverse, sum_pointer)
        end
      {% end %}
    {% end %}
  end
end
