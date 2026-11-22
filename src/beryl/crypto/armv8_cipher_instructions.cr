module Beryl::Crypto
  # :nodoc:
  #
  # AES, GHASH and ChaCha20 written with the instructions of ARMv8
  # processors: `aese`, `aesmc`, `aesd` and `aesimc` for AES, `pmull` and
  # `pmull2` (carry-less multiplication) for GHASH, and the Advanced SIMD
  # instructions for ChaCha20 (Arm Architecture Reference Manual C7.2). Each
  # macro expands, at its call site, to one block of assembly that works on
  # whole blocks; the callers in `V1::GaloisCounterModeWithProcessorInstructions`,
  # `V1::ChaCha20WithVectorInstructions` and
  # `Compatibility::CipherBlockChainingWithProcessorInstructions` handle the
  # partial blocks and choose the round count.
  #
  # Crystal has no vector types, so the instructions cannot be reached as
  # LLVM intrinsics; the assembly is written out here instead, as in
  # `Armv8HashInstructions`. Every statement has at most one branch, which
  # closes its loop on the count of groups left, and reads and writes memory
  # only at fixed offsets from its inputs, so its timing depends on the sizes
  # it is given and on nothing a key or a message holds.
  # `scripts/check_secret_flow.rb` checks exactly that. The AES and
  # carry-less multiply instructions take the same time whatever their
  # operands hold, which is why they replace the bitsliced AES and the
  # integer-multiply GHASH where the processor has them.
  #
  # GHASH works on blocks with their bytes reversed, so that the field's
  # bit order matches the processor's, and on hash key powers that were
  # multiplied by x once ("twisted") when they were prepared, which absorbs
  # the one-bit shift a reflected product needs. The reduction modulo
  # x^128 + x^7 + x^2 + x + 1 takes two carry-less multiplies by the
  # constant 0xc2 << 56. This is the method of Gueron and Kounavis, "Intel
  # Carry-Less Multiplication Instruction and its Usage for Computing the GCM
  # Mode" (2014), in the arrangement OpenSSL's `ghashv8-armx` uses; the
  # vectors and the differential against libcrypto check it.
  module Armv8CipherInstructions
    # Bytes in one table entry of hash key powers: the twisted power, then
    # the same power with its two 64-bit halves swapped. With both, the four
    # products of a block and a power are one carry-less multiply each.
    HASH_KEY_POWER_BYTESIZE = 32

    # Powers of the hash key kept: H to H^16, one per block of a group.
    HASH_KEY_POWER_COUNT = 16

    # Prepares the table of hash key powers at *hash_key_powers*
    # (`HASH_KEY_POWER_COUNT` entries of `HASH_KEY_POWER_BYTESIZE` bytes) from
    # the hash key at *hash_key* (16 bytes, the encryption of the zero
    # block). The highest power comes first: entry j holds H^(16 - j), so
    # that n blocks hashed together take the n entries from 16 - n on. No
    # loop: fifteen multiplies written out.
    macro prepare_hash_key_powers(hash_key, hash_key_powers)
      {% template = "
  .arch_extension aes
  mov x9, $0
  mov x10, $1
  ld1 {v17.16b}, [x9]
  rev64 v17.16b, v17.16b
  ext v3.16b, v17.16b, v17.16b, #8
  movi v19.16b, #0xe1
  shl v19.2d, v19.2d, #57
  ushr v18.2d, v19.2d, #63
  dup v17.4s, v17.s[1]
  ext v16.16b, v18.16b, v19.16b, #8
  ushr v18.2d, v3.2d, #63
  sshr v17.4s, v17.4s, #31
  and v18.16b, v18.16b, v16.16b
  shl v3.2d, v3.2d, #1
  ext v18.16b, v18.16b, v18.16b, #8
  and v16.16b, v16.16b, v17.16b
  orr v3.16b, v3.16b, v18.16b
  eor v20.16b, v3.16b, v16.16b
  ext v21.16b, v20.16b, v20.16b, #8
  stp q20, q21, [x10, #480]
  eor v21.16b, v21.16b, v20.16b
  mov v22.16b, v20.16b
" %}
      {% for power in 2..16 %}
        {% template = template + "
  pmull v0.1q, v22.1d, v20.1d
  pmull2 v2.1q, v22.2d, v20.2d
  ext v4.16b, v22.16b, v22.16b, #8
  eor v4.16b, v4.16b, v22.16b
  pmull v1.1q, v4.1d, v21.1d
  ext v5.16b, v0.16b, v2.16b, #8
  eor v6.16b, v0.16b, v2.16b
  eor v1.16b, v1.16b, v5.16b
  eor v1.16b, v1.16b, v6.16b
  pmull v6.1q, v0.1d, v19.1d
  mov v2.d[0], v1.d[1]
  mov v1.d[1], v0.d[0]
  eor v0.16b, v1.16b, v6.16b
  ext v6.16b, v0.16b, v0.16b, #8
  pmull v0.1q, v0.1d, v19.1d
  eor v6.16b, v6.16b, v2.16b
  eor v22.16b, v0.16b, v6.16b
  ext v23.16b, v22.16b, v22.16b, #8
  stp q22, q23, [x10, ##{(16 - power) * 32}]
" %}
      {% end %}
      asm({{ template }} :: "r"({{ hash_key }}), "r"({{ hash_key_powers }}) : "x9", "x10", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "memory")
    end

    # Counter mode: XORs the AES keystream of the counter block at
    # *counter_block* into whole blocks at *input* and writes them to
    # *output*. The last four bytes of the counter block count up as a
    # big-endian number that wraps at 2^32, and the counter block left behind
    # is the next one. *round_count* (10, 12 or 14) names how many of the
    # round keys at *round_keys* are used. *has_three_way_exclusive_or*: the
    # processor has `eor3` (the SHA3 extension), which XORs three registers
    # in one instruction.
    #
    # - *is_pipelined* false: *group_count* (at least 1) single blocks, one
    #   per pass.
    # - *is_pipelined* true: 2 * *group_count* + 1 groups of eight blocks
    #   (*group_count* at least 1), software pipelined. Two sets of eight
    #   registers take turns: while one set runs the second half of its
    #   rounds and is written out, the other starts the first half of its
    #   rounds on the next counters, and the two are interleaved round by
    #   round. The processor then always has independent AES instructions to
    #   start, where a group that runs all its rounds before the next group
    #   starts leaves it waiting on each round's latency. The first group
    #   starts before the loop and the last one finishes after it.
    #
    # Registers: x9 round keys, x10 counter block, x11 passes left, x12
    # input, x13 output, x16 and x17 the counter; v0 to v15 the blocks, v16
    # to v30 the round keys, v31 a message block. A counter block is the
    # stored block with its last word replaced. `aese` and `aesmc` stay side
    # by side so that the processor can fuse them.
    macro encrypt_counter_blocks(round_keys, counter_block, input, output, group_count, round_count, is_pipelined,
                                 has_three_way_exclusive_or)
      {% key_count = round_count + 1 %}
      {% template = "  .arch_extension sha3\n  .arch_extension aes\n  mov x9, $0\n  mov x10, $1\n  mov x12, $2\n  mov x13, $3\n  mov x11, $4\n" %}
      {% for start in [0, 4, 8, 12] %}
        {% if start < key_count %}
          {% count = key_count - start %}
          {% if count > 4 %}{% count = 4 %}{% end %}
          {% registers = [] of StringLiteral %}
          {% for offset in 0...count %}{% registers << "v#{16 + start + offset}.16b" %}{% end %}
          {% template = template + "  ld1 {#{registers.join(", ").id}}, [x9], ##{count * 16}\n" %}
        {% end %}
      {% end %}
      {% template = template + "  ldr w16, [x10, #12]\n  rev w16, w16\n" %}

      {% if is_pipelined %}
        # For each set of eight registers (from v0 and from v8): the lines
        # that load its counter blocks, its rounds before the split, and its
        # rounds after the split with the final round, the message XOR and
        # the stores.
        {% split = round_count // 2 %}
        {% list_of_counter_lines = {} of NumberLiteral => ArrayLiteral %}
        {% list_of_early_rounds = {} of NumberLiteral => ArrayLiteral %}
        {% list_of_late_rounds = {} of NumberLiteral => ArrayLiteral %}
        {% for base in [0, 8] %}
          {% lines = [] of StringLiteral %}
          {% for block in 0...8 %}
            {% lines << "  add w17, w16, ##{block}\n  rev w17, w17\n  ldr q#{base + block}, [x10]\n  mov v#{base + block}.s[3], w17" %}
          {% end %}
          {% lines << "  add w16, w16, #8" %}
          {% list_of_counter_lines[base] = lines %}
          {% rounds = [] of ArrayLiteral %}
          {% for round in 0...split %}
            {% lines = [] of StringLiteral %}
            {% for block in 0...8 %}
              {% lines << "  aese v#{base + block}.16b, v#{16 + round}.16b\n  aesmc v#{base + block}.16b, v#{base + block}.16b" %}
            {% end %}
            {% rounds << lines %}
          {% end %}
          {% list_of_early_rounds[base] = rounds %}
          {% rounds = [] of ArrayLiteral %}
          {% for round in split...(round_count - 1) %}
            {% lines = [] of StringLiteral %}
            {% for block in 0...8 %}
              {% lines << "  aese v#{base + block}.16b, v#{16 + round}.16b\n  aesmc v#{base + block}.16b, v#{base + block}.16b" %}
            {% end %}
            {% rounds << lines %}
          {% end %}
          {% lines = [] of StringLiteral %}
          {% for block in 0...8 %}
            {% line = "  aese v#{base + block}.16b, v#{16 + round_count - 1}.16b\n  ldr q31, [x12, ##{block * 16}]\n" %}
            {% if has_three_way_exclusive_or %}
              {% line = line + "  eor3 v#{base + block}.16b, v#{base + block}.16b, v#{16 + round_count}.16b, v31.16b" %}
            {% else %}
              {% line = line + "  eor v#{base + block}.16b, v#{base + block}.16b, v#{16 + round_count}.16b\n  eor v#{base + block}.16b, v#{base + block}.16b, v31.16b" %}
            {% end %}
            {% lines << line %}
          {% end %}
          {% lines << "  st1 {v#{base}.16b, v#{base + 1}.16b, v#{base + 2}.16b, v#{base + 3}.16b}, [x13], #64\n  st1 {v#{base + 4}.16b, v#{base + 5}.16b, v#{base + 6}.16b, v#{base + 7}.16b}, [x13], #64\n  add x12, x12, #128" %}
          {% rounds << lines %}
          {% list_of_late_rounds[base] = rounds %}
        {% end %}

        {% template = template + list_of_counter_lines[0].join("\n") + "\n" %}
        {% for lines in list_of_early_rounds[0] %}
          {% template = template + lines.join("\n") + "\n" %}
        {% end %}
        {% template = template + "1:\n" %}
        {% for roles in [[0, 8], [8, 0]] %}
          {% finishing = roles[0] %}
          {% starting = roles[1] %}
          {% template = template + list_of_counter_lines[starting].join("\n") + "\n" %}
          {% step_count = list_of_late_rounds[finishing].size %}
          {% if list_of_early_rounds[starting].size > step_count %}
            {% step_count = list_of_early_rounds[starting].size %}
          {% end %}
          {% for step in 0...step_count %}
            {% late_lines = list_of_late_rounds[finishing][step] %}
            {% early_lines = list_of_early_rounds[starting][step] %}
            {% for index in 0...9 %}
              {% if late_lines && late_lines[index] %}
                {% template = template + late_lines[index] + "\n" %}
              {% end %}
              {% if early_lines && early_lines[index] %}
                {% template = template + early_lines[index] + "\n" %}
              {% end %}
            {% end %}
          {% end %}
        {% end %}
        {% template = template + "  subs x11, x11, #1\n  b.ne 1b\n" %}
        {% for lines in list_of_late_rounds[0] %}
          {% template = template + lines.join("\n") + "\n" %}
        {% end %}
      {% else %}
        {% template = template + "1:\n  rev w17, w16\n  ldr q0, [x10]\n  mov v0.s[3], w17\n  add w16, w16, #1\n" %}
        {% for round in 0...(round_count - 1) %}
          {% template = template + "  aese v0.16b, v#{16 + round}.16b\n  aesmc v0.16b, v0.16b\n" %}
        {% end %}
        {% template = template + "  aese v0.16b, v#{16 + round_count - 1}.16b\n  ld1 {v31.16b}, [x12], #16\n" %}
        {% if has_three_way_exclusive_or %}
          {% template = template + "  eor3 v0.16b, v0.16b, v#{16 + round_count}.16b, v31.16b\n" %}
        {% else %}
          {% template = template + "  eor v0.16b, v0.16b, v#{16 + round_count}.16b\n  eor v0.16b, v0.16b, v31.16b\n" %}
        {% end %}
        {% template = template + "  st1 {v0.16b}, [x13], #16\n  subs x11, x11, #1\n  b.ne 1b\n" %}
      {% end %}
      {% template = template + "  rev w16, w16\n  str w16, [x10, #12]\n" %}
      asm({{ template }} :: "r"({{ round_keys }}), "r"({{ counter_block }}), "r"({{ input }}), "r"({{ output }}), "r"({{ group_count }})
        : "x9", "x10", "x11", "x12", "x13", "x16", "x17",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "memory", "cc")
    end

    # GHASH: mixes whole blocks at *input* into the accumulator at
    # *accumulator* (16 bytes, byte-reversed) with the hash key powers that
    # start at *first_hash_key_power*.
    #
    # - *blocks_per_group* 16: *group_count* groups of sixteen blocks, each
    #   multiplied by H^16 to H (the table from its first entry) and reduced
    #   once.
    # - *blocks_per_group* 1: *group_count* blocks (at most 16), multiplied
    #   by the powers from the entry *first_hash_key_power* points at on,
    #   summed, and reduced once at the end. The accumulator joins the first
    #   block only: v30 holds it for the first pass and zero after.
    #
    # A block is hashed as four carry-less multiplies of its byte-reversed
    # value by a power and by the same power with its halves swapped; the
    # sums of the low (v24), middle (v25) and high (v26) products are reduced
    # once, by moving the middle sum onto the product's middle words and
    # folding the upper half down with two multiplies by 0xc2 << 56 (v29).
    # In a group of sixteen, blocks 0 and 1 are hashed last: block 0 alone
    # waits for the accumulator, so the other products are ready by then.
    #
    # Registers: x8 hash key powers, x11 groups left, x12 input, x7 the
    # accumulator; v0 to v15 the blocks, v16 to v23 powers and products, v31
    # the accumulator.
    macro absorb_hash_blocks(accumulator, first_hash_key_power, input, group_count, blocks_per_group, has_three_way_exclusive_or)
      {% template = "  .arch_extension sha3\n  .arch_extension aes\n  mov x7, $0\n  mov x8, $1\n  mov x12, $2\n  mov x11, $3\n  ld1 {v31.16b}, [x7]\n  movi v29.16b, #0xe1\n  shl v29.2d, v29.2d, #57\n" %}
      {% if blocks_per_group == 16 %}
        {% template = template + "1:\n" %}
        {% for start in [0, 4, 8, 12] %}
          {% template = template + "  ld1 {v#{start}.16b, v#{start + 1}.16b, v#{start + 2}.16b, v#{start + 3}.16b}, [x12], #64\n" %}
        {% end %}
        {% for pair in [1, 2, 3, 4, 5, 6, 7, 0] %}
          {% first = pair * 2 %}
          {% second = pair * 2 + 1 %}
          {% template = template + "  rev64 v#{first}.16b, v#{first}.16b\n  rev64 v#{second}.16b, v#{second}.16b\n" %}
          {% if pair == 0 %}
            {% template = template + "  ext v23.16b, v31.16b, v31.16b, #8\n  eor v0.16b, v0.16b, v23.16b\n" %}
          {% end %}
          {% template = template + "  ldp q16, q17, [x8, ##{first * 32}]\n  ldp q18, q19, [x8, ##{second * 32}]
  pmull v20.1q, v#{first}.1d, v17.1d
  pmull2 v17.1q, v#{first}.2d, v17.2d
  pmull v21.1q, v#{second}.1d, v19.1d
  pmull2 v19.1q, v#{second}.2d, v19.2d
  pmull v22.1q, v#{first}.1d, v16.1d
  pmull2 v16.1q, v#{first}.2d, v16.2d
  pmull v23.1q, v#{second}.1d, v18.1d
  pmull2 v18.1q, v#{second}.2d, v18.2d
" %}
          {% if pair == 1 %}
            {% template = template + "  eor v26.16b, v20.16b, v21.16b\n  eor v24.16b, v17.16b, v19.16b\n  eor v25.16b, v22.16b, v16.16b\n  eor v25.16b, v25.16b, v23.16b\n  eor v25.16b, v25.16b, v18.16b\n" %}
          {% elsif has_three_way_exclusive_or %}
            {% template = template + "  eor3 v26.16b, v26.16b, v20.16b, v21.16b\n  eor3 v24.16b, v24.16b, v17.16b, v19.16b\n  eor3 v25.16b, v25.16b, v22.16b, v16.16b\n  eor3 v25.16b, v25.16b, v23.16b, v18.16b\n" %}
          {% else %}
            {% template = template + "  eor v26.16b, v26.16b, v20.16b\n  eor v26.16b, v26.16b, v21.16b\n  eor v24.16b, v24.16b, v17.16b\n  eor v24.16b, v24.16b, v19.16b\n" %}
            {% template = template + "  eor v25.16b, v25.16b, v22.16b\n  eor v25.16b, v25.16b, v16.16b\n  eor v25.16b, v25.16b, v23.16b\n  eor v25.16b, v25.16b, v18.16b\n" %}
          {% end %}
        {% end %}
      {% else %}
        {% template = template + "  movi v24.16b, #0\n  movi v25.16b, #0\n  movi v26.16b, #0\n  ext v30.16b, v31.16b, v31.16b, #8\n1:
  ld1 {v0.16b}, [x12], #16
  rev64 v0.16b, v0.16b
  eor v0.16b, v0.16b, v30.16b
  movi v30.16b, #0
  ldp q16, q17, [x8], #32
  pmull v20.1q, v0.1d, v17.1d
  pmull2 v17.1q, v0.2d, v17.2d
  pmull v22.1q, v0.1d, v16.1d
  pmull2 v16.1q, v0.2d, v16.2d
  eor v26.16b, v26.16b, v20.16b
  eor v24.16b, v24.16b, v17.16b
" %}
        {% if has_three_way_exclusive_or %}
          {% template = template + "  eor3 v25.16b, v25.16b, v22.16b, v16.16b\n" %}
        {% else %}
          {% template = template + "  eor v25.16b, v25.16b, v22.16b\n  eor v25.16b, v25.16b, v16.16b\n" %}
        {% end %}
        {% template = template + "  subs x11, x11, #1\n  b.ne 1b\n" %}
      {% end %}
      {% template = template + "  ext v20.16b, v24.16b, v26.16b, #8
  eor v25.16b, v25.16b, v20.16b
  pmull v20.1q, v24.1d, v29.1d
  mov v26.d[0], v25.d[1]
  mov v25.d[1], v24.d[0]
  eor v24.16b, v25.16b, v20.16b
  ext v20.16b, v24.16b, v24.16b, #8
  pmull v24.1q, v24.1d, v29.1d
" %}
      {% if has_three_way_exclusive_or %}
        {% template = template + "  eor3 v31.16b, v24.16b, v20.16b, v26.16b\n" %}
      {% else %}
        {% template = template + "  eor v20.16b, v20.16b, v26.16b\n  eor v31.16b, v24.16b, v20.16b\n" %}
      {% end %}
      {% if blocks_per_group == 16 %}
        {% template = template + "  subs x11, x11, #1\n  b.ne 1b\n" %}
      {% end %}
      {% template = template + "  st1 {v31.16b}, [x7]\n" %}
      asm({{ template }} :: "r"({{ accumulator }}), "r"({{ first_hash_key_power }}), "r"({{ input }}), "r"({{ group_count }})
        : "x7", "x8", "x11", "x12",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v29", "v30", "v31",
          "memory", "cc")
    end

    # Writes at *decryption_round_keys* the round keys of the equivalent
    # inverse cipher (FIPS 197 §5.3.5) for the *round_count* rounds of the
    # encryption round keys at *round_keys*: the last key first, the middle
    # keys through `aesimc`, the first key last. No loop.
    macro prepare_decryption_round_keys(round_keys, decryption_round_keys, round_count)
      {% template = "  mov x9, $0\n  mov x10, $1\n" %}
      {% for index in 0..round_count %}
        {% template = template + "  ldr q0, [x9, ##{(round_count - index) * 16}]\n" %}
        {% if index > 0 && index < round_count %}
          {% template = template + "  aesimc v0.16b, v0.16b\n" %}
        {% end %}
        {% template = template + "  str q0, [x10, ##{index * 16}]\n" %}
      {% end %}
      asm({{ template }} :: "r"({{ round_keys }}), "r"({{ decryption_round_keys }}) : "x9", "x10", "v0", "memory")
    end

    # CBC encryption (SP 800-38A §6.2) of *block_count* blocks (at least 1),
    # one after the other, since each depends on the last. *chaining_block*
    # holds the initialization vector or the last ciphertext block, and is
    # left holding the last ciphertext block written.
    #
    # The chain from one block to the next is the AES rounds alone: the
    # message block is XORed with the first and the last round key off the
    # chain, and the output of the last `aese` goes straight into the next
    # block's first `aese` (which XORs its operand in first).
    macro encrypt_chained_blocks(round_keys, chaining_block, input, output, block_count, round_count)
      {% key_count = round_count + 1 %}
      {% template = "  mov x9, $0\n  mov x10, $1\n  mov x12, $2\n  mov x13, $3\n  mov x11, $4\n" %}
      {% for start in [0, 4, 8, 12] %}
        {% if start < key_count %}
          {% count = key_count - start %}
          {% if count > 4 %}{% count = 4 %}{% end %}
          {% registers = [] of StringLiteral %}
          {% for offset in 0...count %}{% registers << "v#{16 + start + offset}.16b" %}{% end %}
          {% template = template + "  ld1 {#{registers.join(", ").id}}, [x9], ##{count * 16}\n" %}
        {% end %}
      {% end %}
      {% last = 16 + round_count %}
      {% template = template + "  ld1 {v0.16b}, [x10]
  eor v0.16b, v0.16b, v#{last}.16b
  eor v8.16b, v16.16b, v#{last}.16b
1:
  ld1 {v1.16b}, [x12], #16
  eor v1.16b, v1.16b, v8.16b
  aese v0.16b, v1.16b
  aesmc v0.16b, v0.16b
" %}
      {% for round in 1...(round_count - 1) %}
        {% template = template + "  aese v0.16b, v#{16 + round}.16b\n  aesmc v0.16b, v0.16b\n" %}
      {% end %}
      {% template = template + "  aese v0.16b, v#{16 + round_count - 1}.16b
  eor v2.16b, v0.16b, v#{last}.16b
  st1 {v2.16b}, [x13], #16
  subs x11, x11, #1
  b.ne 1b
  eor v0.16b, v0.16b, v#{last}.16b
  st1 {v0.16b}, [x10]
" %}
      asm({{ template }} :: "r"({{ round_keys }}), "r"({{ chaining_block }}), "r"({{ input }}), "r"({{ output }}), "r"({{ block_count }})
        : "x9", "x10", "x11", "x12", "x13", "v0", "v1", "v2", "v8",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30",
          "memory", "cc")
    end

    # CBC decryption of *group_count* groups of *blocks_per_group* blocks (8
    # or 1) with the round keys of the equivalent inverse cipher. The blocks
    # of a group are independent, so they run side by side. *chaining_block*
    # holds the initialization vector or the last ciphertext block, and is
    # left holding the last ciphertext block read.
    macro decrypt_chained_blocks(decryption_round_keys, chaining_block, input, output, group_count, round_count, blocks_per_group)
      {% key_count = round_count + 1 %}
      {% template = "  mov x9, $0\n  mov x10, $1\n  mov x12, $2\n  mov x13, $3\n  mov x11, $4\n" %}
      {% for start in [0, 4, 8, 12] %}
        {% if start < key_count %}
          {% count = key_count - start %}
          {% if count > 4 %}{% count = 4 %}{% end %}
          {% registers = [] of StringLiteral %}
          {% for offset in 0...count %}{% registers << "v#{16 + start + offset}.16b" %}{% end %}
          {% template = template + "  ld1 {#{registers.join(", ").id}}, [x9], ##{count * 16}\n" %}
        {% end %}
      {% end %}
      {% template = template + "  ld1 {v31.16b}, [x10]\n1:\n" %}
      {% if blocks_per_group == 8 %}
        {% template = template + "  ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x12], #64
  ld1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x12], #64
  mov v8.16b, v0.16b
  mov v9.16b, v1.16b
  mov v10.16b, v2.16b
  mov v11.16b, v3.16b
  mov v12.16b, v4.16b
  mov v13.16b, v5.16b
  mov v14.16b, v6.16b
  mov v15.16b, v7.16b
" %}
      {% else %}
        {% template = template + "  ld1 {v0.16b}, [x12], #16\n  mov v8.16b, v0.16b\n" %}
      {% end %}
      {% for round in 0...(round_count - 1) %}
        {% for block in 0...blocks_per_group %}
          {% template = template + "  aesd v#{block}.16b, v#{16 + round}.16b\n  aesimc v#{block}.16b, v#{block}.16b\n" %}
        {% end %}
      {% end %}
      {% for block in 0...blocks_per_group %}
        {% previous = block == 0 ? "v31" : "v#{8 + block - 1}" %}
        {% template = template + "  aesd v#{block}.16b, v#{16 + round_count - 1}.16b
  eor v#{block}.16b, v#{block}.16b, v#{16 + round_count}.16b
  eor v#{block}.16b, v#{block}.16b, #{previous.id}.16b
" %}
      {% end %}
      {% if blocks_per_group == 8 %}
        {% template = template + "  st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x13], #64
  st1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x13], #64
  mov v31.16b, v15.16b
" %}
      {% else %}
        {% template = template + "  st1 {v0.16b}, [x13], #16\n  mov v31.16b, v8.16b\n" %}
      {% end %}
      {% template = template + "  subs x11, x11, #1\n  b.ne 1b\n  st1 {v31.16b}, [x10]\n" %}
      asm({{ template }} :: "r"({{ decryption_round_keys }}), "r"({{ chaining_block }}), "r"({{ input }}), "r"({{ output }}), "r"({{ group_count }})
        : "x9", "x10", "x11", "x12", "x13",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
          "memory", "cc")
    end
  end
end
