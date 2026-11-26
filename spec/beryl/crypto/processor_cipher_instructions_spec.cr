require "../../spec_helper"

# The ciphers on the processor's instructions are checked against the
# portable code inside one program: each case below computes the same
# message both ways. On a processor without the instructions, and under
# `-Dberyl_portable_ciphers`, both sides run the portable code and the
# comparison holds trivially.
#
# The published vectors are short; these cases reach the lengths where the
# assembly changes path: the wide loops, the blocks left over after them,
# the chunks a long message is sealed in, and every partial last block.
module PortableCipherReference
  alias BitslicedAES = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard
  alias GaloisHash = Beryl::Crypto::V1::GaloisHash

  # AES-GCM (SP 800-38D) from the bitsliced AES and the integer-multiply
  # GHASH: the ciphertext followed by the full tag.
  def self.seal_with_galois_counter_mode(key : Bytes, nonce : Bytes, associated_data : Bytes, plaintext : Bytes) : Bytes
    round_count = BitslicedAES.round_count_for(key.size)
    round_keys = Slice(UInt64).new(BitslicedAES::ROUND_KEY_WORD_COUNT, 0_u64)
    BitslicedAES.expand_key(key, round_keys)
    hash_key = Bytes.new(16)
    BitslicedAES.encrypt_blocks(round_keys, round_count, hash_key, hash_key)
    key_state = Slice(UInt64).new(GaloisHash::STATE_WORD_COUNT, 0_u64)
    GaloisHash.load_key(key_state, hash_key)

    first_counter_block = Bytes.new(16)
    if nonce.size == 12
      nonce.copy_to(first_counter_block)
      first_counter_block[15] = 1_u8
    else
      state = key_state.dup
      GaloisHash.absorb(state, nonce)
      length_block = Bytes.new(16)
      IO::ByteFormat::BigEndian.encode(nonce.size.to_u64 * 8, length_block[8, 8])
      GaloisHash.absorb(state, length_block)
      GaloisHash.write_digest(state, first_counter_block)
    end

    message_counter_block = first_counter_block.dup
    counter = IO::ByteFormat::BigEndian.decode(UInt32, message_counter_block[12, 4])
    IO::ByteFormat::BigEndian.encode(counter &+ 1_u32, message_counter_block[12, 4])
    sealed = Bytes.new(plaintext.size + 16)
    BitslicedAES.xor_counter_keystream(round_keys, round_count, message_counter_block, plaintext, sealed[0, plaintext.size])

    state = key_state.dup
    GaloisHash.absorb(state, associated_data)
    GaloisHash.absorb(state, sealed[0, plaintext.size])
    length_block = Bytes.new(16)
    IO::ByteFormat::BigEndian.encode(associated_data.size.to_u64 * 8, length_block[0, 8])
    IO::ByteFormat::BigEndian.encode(plaintext.size.to_u64 * 8, length_block[8, 8])
    GaloisHash.absorb(state, length_block)
    tag = sealed[plaintext.size, 16]
    GaloisHash.write_digest(state, tag)
    tag_mask = first_counter_block.dup
    BitslicedAES.encrypt_blocks(round_keys, round_count, tag_mask, tag_mask)
    16.times { |index| tag[index] ^= tag_mask[index] }
    sealed
  end

  # ChaCha20-Poly1305 (RFC 8439 §2.8) from the scalar ChaCha20 and the
  # 44-bit-limb Poly1305: the ciphertext followed by the tag.
  def self.seal_with_chacha20_and_poly1305(key : Bytes, nonce : Bytes, associated_data : Bytes, plaintext : Bytes) : Bytes
    sealed = Bytes.new(plaintext.size + 16)
    Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(key, nonce, 1_u32, plaintext, sealed[0, plaintext.size])
    one_time_key = Bytes.new(32)
    Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(key, nonce, 0_u32, one_time_key, one_time_key)
    Beryl::Crypto::V1::Poly1305OneTimeAuthenticator.authenticate_encrypted_message(one_time_key, associated_data,
      sealed[0, plaintext.size], sealed[plaintext.size, 16])
    sealed
  end
end

# Message sizes that cross every boundary of the assembly paths: each size up
# to 600 bytes, and sizes around the multiples of the 128-byte and 256-byte
# groups, the 512-byte and 1024-byte ChaCha20 groups of AVX2 and AVX-512
# (whose first group carries 448 or 960 message bytes), the Poly1305 vector
# groups, and the 16 KiB sealing chunk.
LIST_OF_CIPHER_CHECK_BYTESIZES = (0..600).to_a +
                                 [959, 960, 961, 1023, 1024, 1025, 1087, 1088, 1089, 1471, 1472, 1473, 1535, 1536, 1537,
                                  1983, 1984, 1985, 2047, 2048, 2049, 3007, 3008, 3009, 4095, 4096, 4097,
                                  16_383, 16_384, 16_385, 16_384 + 127, 16_384 + 129, 32_767, 32_768, 32_769, 65_536 + 17, 100_000]

# The vector paths (VAES and VPCLMULQDQ on 512-bit or 256-bit registers)
# change course at other lengths: the 16 blocks a run needs to take them,
# their passes of 32 blocks, the single registers of four or two blocks
# after those, and the one to three blocks left for the AES-NI code. This
# run compares the path its processor takes; CI's runs under
# -Dberyl_without_avx512 and -Dberyl_without_avx2 compare the narrower
# ones.
LIST_OF_VECTOR_PATH_CHECK_BYTESIZES = [15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 66, 67].flat_map { |block_count|
  [block_count * 16 - 1, block_count * 16, block_count * 16 + 1]
} + [256 + 32 * 16, 512 * 2 + 48, 512 * 3 + 16 * 3 + 7, 16_384 + 512 + 16, 16_384 + 64 + 48 + 5, 1024 * 1024 + 16 * 35 + 9]

describe "Beryl ciphers on the processor's instructions" do
  it "states which instructions this run uses" do
    STDOUT.puts
    STDOUT.puts "AES instructions: #{Beryl::Crypto::ProcessorFeatures::HAS_AES_INSTRUCTIONS}, " \
                "carry-less multiply: #{Beryl::Crypto::ProcessorFeatures::HAS_CARRYLESS_MULTIPLY_INSTRUCTIONS}, " \
                "vector instructions: #{Beryl::Crypto::ProcessorFeatures::HAS_VECTOR_INSTRUCTIONS}, " \
                "three-way exclusive or: #{Beryl::Crypto::ProcessorFeatures::HAS_THREE_WAY_EXCLUSIVE_OR}"
    STDOUT.puts "AVX2: #{Beryl::Crypto::ProcessorFeatures::HAS_AVX2}, " \
                "AVX-512: #{Beryl::Crypto::ProcessorFeatures::HAS_AVX512}, " \
                "AVX-512 IFMA: #{Beryl::Crypto::ProcessorFeatures::HAS_AVX512_INTEGER_FUSED_MULTIPLY_ADD}, " \
                "VAES: #{Beryl::Crypto::ProcessorFeatures::HAS_VECTOR_AES}, " \
                "VPCLMULQDQ: #{Beryl::Crypto::ProcessorFeatures::HAS_VECTOR_CARRYLESS_MULTIPLY}, " \
                "MULX and ADX: #{Beryl::Crypto::ProcessorFeatures::HAS_WIDE_MULTIPLY_WITH_TWO_CARRY_CHAINS}"
  end

  {% for key_bytesize in [16, 24, 32] %}
    it "seals and opens AES-{{ key_bytesize * 8 }}-GCM as the portable code does, at every length that changes path" do
      generator = Random.new(0x6763_6d00 + {{ key_bytesize }})
      LIST_OF_CIPHER_CHECK_BYTESIZES.each do |message_bytesize|
        key = generator.random_bytes({{ key_bytesize }})
        nonce = generator.random_bytes(message_bytesize % 7 == 3 ? 1 + generator.rand(64) : 12)
        associated_data = generator.random_bytes(generator.rand(0..300))
        plaintext = generator.random_bytes(message_bytesize)

        cipher = Beryl::Crypto::V1::AESGCM.new(key)
        sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)
        expected = PortableCipherReference.seal_with_galois_counter_mode(key, nonce, associated_data, plaintext)
        fail "AES-{{ key_bytesize * 8 }}-GCM differs from the portable code at #{message_bytesize} bytes" unless sealed == expected

        cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should eq(plaintext)
        sealed[generator.rand(sealed.size)] ^= 1_u8 << generator.rand(8)
        cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should be_nil
      end
    end
  {% end %}

  it "seals and opens ChaCha20-Poly1305 and XChaCha20-Poly1305 as the portable code does, at every length that changes path" do
    generator = Random.new(0x6368_6100)
    LIST_OF_CIPHER_CHECK_BYTESIZES.each do |message_bytesize|
      key = generator.random_bytes(32)
      nonce = generator.random_bytes(12)
      associated_data = generator.random_bytes(generator.rand(0..300))
      plaintext = generator.random_bytes(message_bytesize)

      cipher = Beryl::Crypto::V1::ChaCha20Poly1305.new(key)
      sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)
      expected = PortableCipherReference.seal_with_chacha20_and_poly1305(key, nonce, associated_data, plaintext)
      fail "ChaCha20-Poly1305 differs from the portable code at #{message_bytesize} bytes" unless sealed == expected
      cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should eq(plaintext)
      untouched = Bytes.new(message_bytesize, 0x5a_u8)
      sealed[generator.rand(sealed.size)] ^= 1_u8 << generator.rand(8)
      cipher.decrypt(sealed, into: untouched, nonce: nonce, associated_data: associated_data).should be_false
      untouched.all?(0x5a_u8).should be_true

      extended_nonce = generator.random_bytes(24)
      subkey = Bytes.new(32)
      Beryl::Crypto::V1::ChaCha20StreamCipher.derive_subkey(key, extended_nonce[0, 16], subkey)
      short_nonce = Bytes.new(12)
      extended_nonce[16, 8].copy_to(short_nonce[4, 8])
      extended = Beryl::Crypto::V1::XChaCha20Poly1305.new(key)
      sealed = extended.encrypt(plaintext, nonce: extended_nonce, associated_data: associated_data)
      expected = PortableCipherReference.seal_with_chacha20_and_poly1305(subkey, short_nonce, associated_data, plaintext)
      fail "XChaCha20-Poly1305 differs from the portable code at #{message_bytesize} bytes" unless sealed == expected
      extended.decrypt(sealed, nonce: extended_nonce, associated_data: associated_data).should eq(plaintext)
    end
  end

  it "runs the ChaCha20 keystream and Poly1305 as the portable code does, at every length that changes path" do
    generator = Random.new(0x6b73_7472)
    LIST_OF_CIPHER_CHECK_BYTESIZES.each do |message_bytesize|
      key = generator.random_bytes(32)
      nonce = generator.random_bytes(12)
      initial_counter = generator.rand(UInt32::MAX // 2).to_u32
      message = generator.random_bytes(message_bytesize)
      expected = Bytes.new(message_bytesize)
      Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(key, nonce, initial_counter, message, expected)
      written = Bytes.new(message_bytesize)
      Beryl::Crypto::V1::ChaCha20WithVectorInstructions.xor_keystream(key, nonce, initial_counter, message, written)
      fail "the ChaCha20 keystream differs from the portable code at #{message_bytesize} bytes" unless written == expected

      associated_data = generator.random_bytes(generator.rand(0..40))
      expected_tag = Bytes.new(16)
      Beryl::Crypto::V1::Poly1305OneTimeAuthenticator.authenticate_encrypted_message(key, associated_data, message, expected_tag)
      tag = Bytes.new(16)
      Beryl::Crypto::V1::Poly1305WithWideMultiplication.authenticate_encrypted_message(key, associated_data, message, tag)
      fail "Poly1305 differs from the portable code at #{message_bytesize} bytes" unless tag == expected_tag
    end
  end

  it "runs Poly1305 as the portable code does on the largest key and message words" do
    [0xff_u8, 0xfe_u8, 0x00_u8].each do |message_byte|
      [64, 1024, 1040, 4096, 65_536 + 48].each do |message_bytesize|
        key = Bytes.new(32, 0xff_u8)
        message = Bytes.new(message_bytesize, message_byte)
        expected_tag = Bytes.new(16)
        Beryl::Crypto::V1::Poly1305OneTimeAuthenticator.authenticate_encrypted_message(key, Bytes.empty, message, expected_tag)
        tag = Bytes.new(16)
        Beryl::Crypto::V1::Poly1305WithWideMultiplication.authenticate_encrypted_message(key, Bytes.empty, message, tag)
        tag.should eq(expected_tag)
      end
    end
  end

  it "runs the ChaCha20 keystream across the end of the 32-bit block counter as the portable code does" do
    generator = Random.new(0x7772_6170)
    key = generator.random_bytes(32)
    nonce = generator.random_bytes(12)
    [0xffffff00_u32, 0xffffffe0_u32, 0xfffffff9_u32].each do |initial_counter|
      blocks_left = ((1_u64 << 32) - initial_counter).to_i32
      [1, 64 * blocks_left - 1, 64 * blocks_left].each do |message_bytesize|
        message = generator.random_bytes(message_bytesize)
        expected = Bytes.new(message_bytesize)
        Beryl::Crypto::V1::ChaCha20StreamCipher.xor_keystream(key, nonce, initial_counter, message, expected)
        written = Bytes.new(message_bytesize)
        Beryl::Crypto::V1::ChaCha20WithVectorInstructions.xor_keystream(key, nonce, initial_counter, message, written)
        written.should eq(expected)
      end
    end
  end

  {% for key_bytesize in [16, 24, 32] %}
    it "seals and opens AES-{{ key_bytesize * 8 }}-GCM as the portable code does at the edges of the vector loops ({{ key_bytesize }}-byte key)" do
      STDOUT.puts
      STDOUT.puts "AES-GCM vector register width in use: #{Beryl::Crypto::V1::GaloisCounterModeWithProcessorInstructions::VECTOR_REGISTER_BITSIZE} bits"
      generator = Random.new(0x7661_6573 + {{ key_bytesize }})
      (LIST_OF_CIPHER_CHECK_BYTESIZES + LIST_OF_VECTOR_PATH_CHECK_BYTESIZES).each do |message_bytesize|
        key = generator.random_bytes({{ key_bytesize }})
        nonce = generator.random_bytes(message_bytesize % 5 == 2 ? 1 + generator.rand(700) : 12)
        associated_data_bytesize = generator.rand(4) == 0 ? LIST_OF_VECTOR_PATH_CHECK_BYTESIZES.sample(generator) : generator.rand(0..40)
        associated_data = generator.random_bytes(associated_data_bytesize)
        plaintext = generator.random_bytes(message_bytesize)

        cipher = Beryl::Crypto::V1::AESGCM.new(key)
        sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)
        expected = PortableCipherReference.seal_with_galois_counter_mode(key, nonce, associated_data, plaintext)
        fail "AES-{{ key_bytesize * 8 }}-GCM differs from the portable code at #{message_bytesize} bytes (#{associated_data.size} of associated data)" unless sealed == expected

        cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should eq(plaintext)
        sealed[generator.rand(sealed.size)] ^= 1_u8 << generator.rand(8)
        cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should be_nil
      end
    end
  {% end %}

  it "opens AES-GCM on every opening path, in place too, and leaves the buffer untouched on a wrong tag" do
    generator = Random.new(0x6f70_656e)
    [16, 32].each do |key_bytesize|
      cipher = Beryl::Crypto::V1::AESGCM.new(generator.random_bytes(key_bytesize))
      [0, 1, 64, 239, 240, 1023, 1024, 1025, 2048 + 16 * 3 + 1, 16_384, 16_384 + 256, 17 * 1024, 17 * 1024 + 1, 40_000].each do |message_bytesize|
        nonce = generator.random_bytes(12)
        associated_data = generator.random_bytes(13)
        plaintext = generator.random_bytes(message_bytesize)
        sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)

        opened = Bytes.new(message_bytesize)
        cipher.decrypt(sealed, into: opened, nonce: nonce, associated_data: associated_data).should be_true
        opened.should eq(plaintext)

        in_place = sealed.dup
        cipher.decrypt(in_place, into: in_place[0, message_bytesize], nonce: nonce, associated_data: associated_data).should be_true
        in_place[0, message_bytesize].should eq(plaintext)

        sealed[generator.rand(sealed.size)] ^= 1_u8 << generator.rand(8)
        untouched = Bytes.new(message_bytesize, 0x5a_u8)
        cipher.decrypt(sealed, into: untouched, nonce: nonce, associated_data: associated_data).should be_false
        untouched.all?(0x5a_u8).should be_true
        in_place = sealed.dup
        cipher.decrypt(in_place, into: in_place[0, message_bytesize], nonce: nonce, associated_data: associated_data).should be_false
        in_place.should eq(sealed)
      end
    end
  end

  it "runs the AES-GCM counter across the end of its 32-bit word as the portable code does, on every path" do
    generator = Random.new(0x6374_7277)
    [16, 32].each do |key_bytesize|
      key = generator.random_bytes(key_bytesize)
      round_count = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.round_count_for(key_bytesize)
      portable_round_keys = Slice(UInt64).new(Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_WORD_COUNT, 0_u64)
      Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.expand_key(key, portable_round_keys)
      round_key_bytes = Bytes.new(Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_BYTESIZE)
      hash_key_powers = Bytes.new(Beryl::Crypto::V1::GaloisCounterModeWithProcessorInstructions::HASH_KEY_POWERS_BYTESIZE)
      Beryl::Crypto::V1::GaloisCounterModeWithProcessorInstructions.prepare(key, round_key_bytes, hash_key_powers)
      [0xffffffff_u32, 0xfffffff0_u32, 0xffffffe3_u32, 0xffffff81_u32].each do |initial_counter|
        [16 * 16, 16 * 33 + 5, 16 * 70, 16 * 200 + 3].each do |message_bytesize|
          counter_block = generator.random_bytes(16)
          IO::ByteFormat::BigEndian.encode(initial_counter, counter_block[12, 4])
          message = generator.random_bytes(message_bytesize)
          expected = Bytes.new(message_bytesize)
          expected_counter_block = counter_block.dup
          Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.xor_counter_keystream(portable_round_keys, round_count, expected_counter_block, message, expected)
          written = Bytes.new(message_bytesize)
          written_counter_block = counter_block.dup
          if Beryl::Crypto::ProcessorFeatures::HAS_GALOIS_COUNTER_MODE_INSTRUCTIONS
            Beryl::Crypto::V1::GaloisCounterModeWithProcessorInstructions.xor_counter_keystream(round_key_bytes, round_count, written_counter_block, message, written)
          else
            written.copy_from(expected)
          end
          written.should eq(expected)
          written_counter_block[0, 12].should eq(counter_block[0, 12])
        end
      end
    end
  end

  {% for key_bytesize in [16, 24, 32] %}
    it "encrypts and decrypts AES-{{ key_bytesize * 8 }}-CBC as the portable code does, at every length that changes path" do
      generator = Random.new(0x6362_6300 + {{ key_bytesize }})
      ((0..300).to_a + [1023, 1024, 2047, 2048, 4096, 16_383, 16_384, 100_000]).each do |message_bytesize|
        key = generator.random_bytes({{ key_bytesize }})
        initialization_vector = generator.random_bytes(16)
        plaintext = generator.random_bytes(message_bytesize)
        cipher = Beryl::Crypto::Compatibility::AESCBC.new(key)
        ciphertext = cipher.encrypt(plaintext, initialization_vector: initialization_vector)

        padding_bytesize = 16 - message_bytesize % 16
        expected = Bytes.new(message_bytesize + padding_bytesize, padding_bytesize.to_u8)
        plaintext.copy_to(expected)
        round_count = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.round_count_for(key.size)
        round_keys = Slice(UInt64).new(Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard::ROUND_KEY_WORD_COUNT, 0_u64)
        Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard.expand_key(key, round_keys)
        Beryl::Crypto::Compatibility::CipherBlockChaining.encrypt_in_place(round_keys, round_count, initialization_vector, expected)
        fail "AES-{{ key_bytesize * 8 }}-CBC differs from the portable code at #{message_bytesize} bytes" unless ciphertext == expected

        cipher.decrypt(ciphertext, initialization_vector: initialization_vector).should eq(plaintext)
      end
    end
  {% end %}
end
