require "crypto/subtle"
require "../armv8_cipher_instructions"
require "../declassification"
require "../error"
require "../processor_features"
require "../secret_wiping"
require "../x86_64_cipher_instructions"
require "./chacha20_stream_cipher"
require "./poly1305_one_time_authenticator"
require "./poly1305_with_wide_multiplication"

module Beryl::Crypto::V1
  # :nodoc:
  #
  # ChaCha20 and ChaCha20-Poly1305 (RFC 8439) on the processor's vector
  # instructions: the assembly in `Armv8CipherInstructions` or
  # `X8664CipherInstructions` makes the keystream a group of blocks at a
  # time, and this module handles the state, the first group and the bytes
  # left after the last whole group.
  #
  # The first group of a message starts at block 0, whose first 32 bytes are
  # the Poly1305 key; the message's first bytes ride in the same group from
  # block 1. Sealing a short message, or opening one, therefore runs the
  # keystream once. A group that the message only partly fills runs on a
  # copy in a staging buffer, which is wiped afterwards.
  #
  # Every buffer is treated as secret. Sizes and the block counter are
  # public.
  module ChaCha20WithVectorInstructions
    BLOCK_BYTESIZE = 64

    # Bytes in one group of blocks the assembly makes in one pass: 64 times
    # `CHACHA20_BLOCKS_PER_GROUP` of the instruction module, written out as
    # a number because it sizes the staging buffers.
    {% if flag?(:aarch64) %}
      GROUP_BYTESIZE = 512
    {% elsif flag?(:x86_64) %}
      GROUP_BYTESIZE = 192
    {% else %}
      GROUP_BYTESIZE = 64
    {% end %}

    # Words in the ChaCha20 state.
    private STATE_WORD_COUNT = 16

    # Message bytes the first group carries after block 0.
    FIRST_GROUP_MESSAGE_BYTESIZE = GROUP_BYTESIZE - BLOCK_BYTESIZE

    private POLY1305_KEY_BYTESIZE = 32

    # XORs *input* into *output* with the keystream of *key* and *nonce*,
    # starting at block number *initial_counter*.
    def self.xor_keystream(key : Bytes, nonce : Bytes, initial_counter : UInt32, input : Bytes, output : Bytes) : Nil
      raise OutputSizeMismatch.new("a stream cipher writes as many bytes as it reads") unless input.size == output.size
      ensure_message_fits(initial_counter, input.size)

      state_storage = uninitialized UInt32[16]
      state = state_storage.to_slice
      load_state(key, nonce, initial_counter, state)
      xor_from_state(state, input, output)
      SecretWiping.wipe(state_storage.to_slice.to_unsafe_bytes)
    end

    # ChaCha20-Poly1305 sealing (RFC 8439 §2.8): encrypts *plaintext* into
    # *ciphertext* from block 1 and writes the full tag into *full_tag*.
    def self.seal(key : Bytes, nonce : Bytes, associated_data : Bytes, plaintext : Bytes, ciphertext : Bytes, full_tag : Bytes) : Nil
      raise OutputSizeMismatch.new("the ciphertext is as long as the plaintext") unless plaintext.size == ciphertext.size
      ensure_message_fits(1_u32, plaintext.size)

      with_first_group(key, nonce, plaintext) do |state, staging, first_bytesize|
        staging[BLOCK_BYTESIZE, first_bytesize].copy_to(ciphertext)
        xor_from_state(state, plaintext[first_bytesize..], ciphertext[first_bytesize..])
        authenticate(staging[0, POLY1305_KEY_BYTESIZE], associated_data, ciphertext, full_tag)
      end
    end

    # ChaCha20-Poly1305 opening: when *tag* is the first `tag.size` bytes of
    # the right tag, writes the plaintext of *ciphertext* into *plaintext*
    # and returns true; otherwise returns false and leaves *plaintext*
    # untouched.
    def self.open(key : Bytes, nonce : Bytes, associated_data : Bytes, ciphertext : Bytes, tag : Bytes, plaintext : Bytes) : Bool
      raise OutputSizeMismatch.new("the plaintext is as long as the ciphertext") unless plaintext.size == ciphertext.size
      ensure_message_fits(1_u32, ciphertext.size)

      is_authentic = false
      with_first_group(key, nonce, ciphertext) do |state, staging, first_bytesize|
        full_tag_storage = uninitialized UInt8[16]
        full_tag = full_tag_storage.to_slice
        authenticate(staging[0, POLY1305_KEY_BYTESIZE], associated_data, ciphertext, full_tag)
        tags_match = ::Crypto::Subtle.constant_time_compare(full_tag[0, tag.size], tag)
        SecretWiping.wipe(full_tag)
        is_authentic = Declassification.reveal(tags_match)
        if is_authentic
          staging[BLOCK_BYTESIZE, first_bytesize].copy_to(plaintext)
          xor_from_state(state, ciphertext[first_bytesize..], plaintext[first_bytesize..])
        end
      end
      is_authentic
    end

    # Writes into *full_tag* the ChaCha20-Poly1305 tag of *ciphertext* and
    # *associated_data*.
    def self.write_tag(key : Bytes, nonce : Bytes, associated_data : Bytes, ciphertext : Bytes, full_tag : Bytes) : Nil
      with_first_group(key, nonce, Bytes.empty) do |_state, staging, _first_bytesize|
        authenticate(staging[0, POLY1305_KEY_BYTESIZE], associated_data, ciphertext, full_tag)
      end
    end

    # The Poly1305 tag RFC 8439 §2.8 defines, on the wide multiply where the
    # processor has it.
    def self.authenticate(one_time_key : Bytes, associated_data : Bytes, ciphertext : Bytes, full_tag : Bytes) : Nil
      if ProcessorFeatures::HAS_WIDE_MULTIPLICATION
        Poly1305WithWideMultiplication.authenticate_encrypted_message(one_time_key, associated_data, ciphertext, full_tag)
      else
        Poly1305OneTimeAuthenticator.authenticate_encrypted_message(one_time_key, associated_data, ciphertext, full_tag)
      end
    end

    # Runs the first group of *message* (counter 0) in a staging buffer that
    # holds a zero block, then up to `FIRST_GROUP_MESSAGE_BYTESIZE` bytes of
    # *message*; yields the state, left at the next group, the staging
    # buffer, which now holds block 0's keystream and those bytes XORed with
    # theirs, and how many message bytes it carries. Wipes both afterwards.
    private def self.with_first_group(key : Bytes, nonce : Bytes, message : Bytes, & : Slice(UInt32), Bytes, Int32 -> Nil) : Nil
      state_storage = uninitialized UInt32[16]
      state = state_storage.to_slice
      load_state(key, nonce, 0_u32, state)
      staging_storage = StaticArray(UInt8, GROUP_BYTESIZE).new(0_u8)
      staging = staging_storage.to_slice
      first_bytesize = Math.min(message.size, FIRST_GROUP_MESSAGE_BYTESIZE)
      message[0, first_bytesize].copy_to(staging[BLOCK_BYTESIZE, first_bytesize])
      xor_groups(state, staging.to_unsafe, staging.to_unsafe, 1_u64)

      yield state, staging, first_bytesize

      SecretWiping.wipe(staging)
      SecretWiping.wipe(state.to_unsafe_bytes)
    end

    # XORs the keystream from the counter in *state* into *input*: whole
    # groups in place, then the bytes left over through a staging buffer.
    private def self.xor_from_state(state : Slice(UInt32), input : Bytes, output : Bytes) : Nil
      group_count = input.size // GROUP_BYTESIZE
      xor_groups(state, input.to_unsafe, output.to_unsafe, group_count.to_u64) if group_count > 0
      done = group_count * GROUP_BYTESIZE
      left_over = input.size - done
      return if left_over == 0

      staging_storage = StaticArray(UInt8, GROUP_BYTESIZE).new(0_u8)
      staging = staging_storage.to_slice
      input[done, left_over].copy_to(staging)
      xor_groups(state, staging.to_unsafe, staging.to_unsafe, 1_u64)
      staging[0, left_over].copy_to(output[done, left_over])
      SecretWiping.wipe(staging)
    end

    # ChaCha20 counts blocks in 32 bits, so a message starting at block
    # *initial_counter* holds at most 2^32 - *initial_counter* blocks.
    private def self.ensure_message_fits(initial_counter : UInt32, message_bytesize : Int32) : Nil
      blocks_available = (1_u64 << 32) - initial_counter
      return if message_bytesize.to_u64 <= blocks_available * BLOCK_BYTESIZE

      raise MessageTooLong.new("ChaCha20 counts #{blocks_available} blocks from block #{initial_counter}, the message needs more")
    end

    private def self.load_state(key : Bytes, nonce : Bytes, initial_counter : UInt32, state : Slice(UInt32)) : Nil
      raise KeySizeMismatch.new("a ChaCha20 key is #{ChaCha20StreamCipher::KEY_BYTESIZE} bytes, not #{key.size}") unless key.size == ChaCha20StreamCipher::KEY_BYTESIZE
      unless nonce.size == ChaCha20StreamCipher::NONCE_BYTESIZE
        raise NonceSizeMismatch.new("a ChaCha20 nonce is #{ChaCha20StreamCipher::NONCE_BYTESIZE} bytes, not #{nonce.size}")
      end

      state[0] = 0x61707865_u32
      state[1] = 0x3320646e_u32
      state[2] = 0x79622d32_u32
      state[3] = 0x6b206574_u32
      8.times { |index| state[4 + index] = IO::ByteFormat::LittleEndian.decode(UInt32, key[index * 4, 4]) }
      state[12] = initial_counter
      3.times { |index| state[13 + index] = IO::ByteFormat::LittleEndian.decode(UInt32, nonce[index * 4, 4]) }
    end

    # The assembly, kept out of line so that the program holds one copy.
    # The callers pass a group count of at least 1.
    @[NoInline]
    private def self.xor_groups(state : Slice(UInt32), input : Pointer(UInt8), output : Pointer(UInt8), group_count : UInt64) : Nil
      raise OutputSizeMismatch.new("the ChaCha20 state is #{STATE_WORD_COUNT} words") unless state.size == STATE_WORD_COUNT

      state_pointer = state.to_unsafe
      {% if flag?(:aarch64) %}
        Armv8CipherInstructions.xor_chacha20_keystream(state_pointer, input, output, group_count)
      {% elsif flag?(:x86_64) %}
        X8664CipherInstructions.xor_chacha20_keystream(state_pointer, input, output, group_count)
      {% else %}
        raise UnsupportedProcessor.new("this processor has no vector instructions Beryl can use")
      {% end %}
    end
  end
end
