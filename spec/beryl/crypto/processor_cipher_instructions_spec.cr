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
end

# Message sizes that cross every boundary of the assembly paths: each size up
# to 600 bytes, and sizes around the multiples of the 128-byte and 256-byte
# groups and the 16 KiB sealing chunk.
LIST_OF_CIPHER_CHECK_BYTESIZES = (0..600).to_a +
                                 [1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 16_383, 16_384, 16_385,
                                  16_384 + 127, 16_384 + 129, 32_767, 32_768, 32_769, 65_536 + 17, 100_000]

describe "Beryl ciphers on the processor's instructions" do
  it "states which instructions this run uses" do
    STDOUT.puts
    STDOUT.puts "AES instructions: #{Beryl::Crypto::ProcessorFeatures::HAS_AES_INSTRUCTIONS}, " \
                "carry-less multiply: #{Beryl::Crypto::ProcessorFeatures::HAS_CARRYLESS_MULTIPLY_INSTRUCTIONS}, " \
                "vector instructions: #{Beryl::Crypto::ProcessorFeatures::HAS_VECTOR_INSTRUCTIONS}, " \
                "three-way exclusive or: #{Beryl::Crypto::ProcessorFeatures::HAS_THREE_WAY_EXCLUSIVE_OR}"
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
end
