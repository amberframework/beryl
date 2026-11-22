require "./libcrypto_differential_spec"

# Differential test of Beryl's ciphers against libcrypto: the same random
# key, nonce, associated data and message go to both. Every case checks
# three things: both produce the same ciphertext and tag, Beryl decrypts
# what libcrypto encrypted, and both refuse the message once one bit of it
# is flipped.
#
#     crystal-alpha spec --release --tag differential -e "cipher ChaCha20-Poly1305 equals"
#
# The names are `cipher ChaCha20-Poly1305`, `cipher XChaCha20-Poly1305`,
# `cipher AES-128-GCM`, `cipher AES-256-GCM`, `cipher AES-128-CBC` and
# `cipher AES-256-CBC`. A failing case replays alone with the environment
# variables the hash differential documents.
lib LibCrypto
  fun beryl_spec_evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : LibC::Int, arg : LibC::Int, ptr : Void*) : LibC::Int
end

module LibcryptoCipherDifferential
  EVP_CTRL_AEAD_SET_IVLEN =  0x9
  EVP_CTRL_AEAD_GET_TAG   = 0x10
  EVP_CTRL_AEAD_SET_TAG   = 0x11

  LARGEST_USUAL_MESSAGE_BYTESIZE   =  2_048
  LARGEST_MESSAGE_BYTESIZE         = 65_536
  LARGEST_ASSOCIATED_DATA_BYTESIZE =     64
  LARGEST_UNUSUAL_NONCE_BYTESIZE   =     64

  # One case in this many draws a message of up to 65,536 bytes.
  LONG_MESSAGE_ODDS = 1_000

  def self.cipher_named(libcrypto_name : String) : LibCrypto::EVP_CIPHER
    cipher = LibCrypto.evp_get_cipherbyname(libcrypto_name)
    raise "libcrypto has no cipher named #{libcrypto_name}" if cipher.null?
    cipher
  end

  # Runs one libcrypto cipher operation. Returns the output (ciphertext then
  # tag when sealing, plaintext when opening), or nil when libcrypto refuses
  # the message. *tag_bytesize* of 0 is a cipher without a tag (CBC).
  def self.libcrypto_run(cipher : LibCrypto::EVP_CIPHER, is_sealing : Bool, key : Bytes, nonce : Bytes,
                         associated_data : Bytes, input : Bytes, tag_bytesize : Int32) : Bytes?
    context = LibCrypto.evp_cipher_ctx_new
    raise "libcrypto could not create a cipher context" if context.null?
    direction = is_sealing ? 1 : 0
    body = is_sealing ? input : input[0, input.size - tag_bytesize]
    begin
      check LibCrypto.evp_cipherinit_ex(context, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null, direction)
      if tag_bytesize > 0
        check LibCrypto.beryl_spec_evp_cipher_ctx_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, nonce.size, Pointer(Void).null)
      end
      check LibCrypto.evp_cipherinit_ex(context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, key, nonce, direction)
      if tag_bytesize > 0 && !is_sealing
        tag = input[input.size - tag_bytesize, tag_bytesize]
        check LibCrypto.beryl_spec_evp_cipher_ctx_ctrl(context, EVP_CTRL_AEAD_SET_TAG, tag_bytesize, tag.to_unsafe.as(Void*))
      end

      written = 0
      unless associated_data.empty?
        check LibCrypto.evp_cipherupdate(context, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size)
      end
      output = Bytes.new(body.size + 32 + tag_bytesize)
      output_bytesize = 0
      unless body.empty?
        check LibCrypto.evp_cipherupdate(context, output, pointerof(written), body, body.size)
        output_bytesize += written
      end
      return nil unless LibCrypto.evp_cipherfinal_ex(context, output.to_unsafe + output_bytesize, pointerof(written)) == 1
      output_bytesize += written

      if tag_bytesize > 0 && is_sealing
        check LibCrypto.beryl_spec_evp_cipher_ctx_ctrl(context, EVP_CTRL_AEAD_GET_TAG, tag_bytesize, (output.to_unsafe + output_bytesize).as(Void*))
        output_bytesize += tag_bytesize
      end
      output[0, output_bytesize]
    ensure
      LibCrypto.evp_cipher_ctx_free(context)
    end
  end

  private def self.check(result : LibC::Int) : Nil
    raise "a libcrypto cipher call failed" unless result == 1
  end

  # HChaCha20 worked out from libcrypto's own ChaCha20: with the 16 nonce
  # bytes as the cipher's counter and nonce, the first keystream block is
  # the permuted state plus the starting state, so subtracting the starting
  # words leaves the words HChaCha20 returns.
  def self.libcrypto_hchacha20(chacha20 : LibCrypto::EVP_CIPHER, key : Bytes, nonce : Bytes) : Bytes
    block = libcrypto_run(chacha20, true, key, nonce, Bytes.empty, Bytes.new(64), 0) || raise "libcrypto ChaCha20 failed"
    list_of_constants = {0x61707865_u32, 0x3320646e_u32, 0x79622d32_u32, 0x6b206574_u32}
    subkey = Bytes.new(32)
    4.times do |index|
      first_row_word = IO::ByteFormat::LittleEndian.decode(UInt32, block[index * 4, 4]) &- list_of_constants[index]
      last_row_word = IO::ByteFormat::LittleEndian.decode(UInt32, block[48 + index * 4, 4]) &-
                      IO::ByteFormat::LittleEndian.decode(UInt32, nonce[index * 4, 4])
      IO::ByteFormat::LittleEndian.encode(first_row_word, subkey[index * 4, 4])
      IO::ByteFormat::LittleEndian.encode(last_row_word, subkey[16 + index * 4, 4])
    end
    subkey
  end

  def self.random_message_bytesize(generator : Random::PCG32) : Int32
    if generator.rand(LONG_MESSAGE_ODDS) == 0
      generator.rand(0..LARGEST_MESSAGE_BYTESIZE)
    else
      generator.rand(0..LARGEST_USUAL_MESSAGE_BYTESIZE)
    end
  end

  def self.random_bytes(generator : Random::PCG32, bytesize : Int32) : Bytes
    bytes = Bytes.new(bytesize)
    generator.random_bytes(bytes)
    bytes
  end

  # Returns a copy of *message* with one bit flipped.
  def self.with_one_bit_flipped(message : Bytes, generator : Random::PCG32) : Bytes
    altered = message.dup
    bit = generator.rand(altered.size * 8)
    altered[bit // 8] ^= (1_u8 << (bit % 8))
    altered
  end
end

if RequestedSpecTag.includes?("differential")
  describe "differential against libcrypto", tags: "differential" do
    {% for algorithm, algorithm_number in [{"ChaCha20-Poly1305", "chacha20-poly1305", 32, 12},
                                           {"AES-128-GCM", "aes-128-gcm", 16, 12},
                                           {"AES-192-GCM", "aes-192-gcm", 24, 12},
                                           {"AES-256-GCM", "aes-256-gcm", 32, 12},
                                           {"XChaCha20-Poly1305", "chacha20-poly1305", 32, 24}] %}
      it "cipher {{ algorithm[0].id }} equals libcrypto on random keys, nonces, associated data and messages" do
        settings = LibcryptoDifferential.settings
        LibcryptoDifferential.describe_run("cipher {{ algorithm[0].id }}", settings.case_count)
        libcrypto_cipher = LibcryptoCipherDifferential.cipher_named({{ algorithm[1] }})
        libcrypto_chacha20 = LibcryptoCipherDifferential.cipher_named("chacha20")
        bytes_encrypted = 0_u64
        unusual_nonce_count = 0
        short_tag_count = 0

        settings.case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for(200 + {{ algorithm_number }}, case_number)
          key = LibcryptoCipherDifferential.random_bytes(generator, {{ algorithm[2] }})
          nonce_bytesize = {{ algorithm[3] }}
          tag_bytesize = 16
          {% if algorithm[0].ends_with?("GCM") %}
            # One case in eight uses a nonce of another length, and one in
            # eight a shorter tag.
            if generator.rand(8) == 0
              nonce_bytesize = generator.rand(1..LibcryptoCipherDifferential::LARGEST_UNUSUAL_NONCE_BYTESIZE)
              unusual_nonce_count += 1 unless nonce_bytesize == 12
            end
            if generator.rand(8) == 0
              tag_bytesize = generator.rand(12..15)
              short_tag_count += 1
            end
          {% end %}
          nonce = LibcryptoCipherDifferential.random_bytes(generator, nonce_bytesize)
          associated_data = LibcryptoCipherDifferential.random_bytes(
            generator, generator.rand(0..LibcryptoCipherDifferential::LARGEST_ASSOCIATED_DATA_BYTESIZE)
          )
          message = LibcryptoCipherDifferential.random_bytes(generator, LibcryptoCipherDifferential.random_message_bytesize(generator))
          bytes_encrypted += message.size

          {% if algorithm[0] == "XChaCha20-Poly1305" %}
            beryl_cipher = Beryl::Crypto::V1::XChaCha20Poly1305.new(key)
            libcrypto_key = LibcryptoCipherDifferential.libcrypto_hchacha20(libcrypto_chacha20, key, nonce[0, 16])
            libcrypto_nonce = Bytes.new(12)
            nonce[16, 8].copy_to(libcrypto_nonce[4, 8])
          {% elsif algorithm[0] == "ChaCha20-Poly1305" %}
            beryl_cipher = Beryl::Crypto::V1::ChaCha20Poly1305.new(key)
            libcrypto_key = key
            libcrypto_nonce = nonce
          {% else %}
            beryl_cipher = Beryl::Crypto::V1::AESGCM.new(key, tag_bytesize: tag_bytesize)
            libcrypto_key = key
            libcrypto_nonce = nonce
          {% end %}

          beryl_sealed = beryl_cipher.encrypt(message, nonce: nonce, associated_data: associated_data)
          libcrypto_sealed = LibcryptoCipherDifferential.libcrypto_run(
            libcrypto_cipher, true, libcrypto_key, libcrypto_nonce, associated_data, message, tag_bytesize
          )
          unless beryl_sealed == libcrypto_sealed
            LibcryptoDifferential.report_mismatch(
              "cipher {{ algorithm[0].id }}", case_number,
              "encrypting #{message.size} bytes with #{associated_data.size} bytes of associated data, a #{nonce.size}-byte nonce " \
              "and a #{tag_bytesize}-byte tag, Beryl ends #{beryl_sealed[-tag_bytesize, tag_bytesize].hexstring}, " \
              "libcrypto #{libcrypto_sealed.try(&.[-tag_bytesize, tag_bytesize].hexstring) || "refused"}"
            )
          end

          unless beryl_cipher.decrypt(beryl_sealed, nonce: nonce, associated_data: associated_data) == message
            LibcryptoDifferential.report_mismatch("cipher {{ algorithm[0].id }}", case_number, "Beryl does not decrypt its own message of #{message.size} bytes")
          end

          altered = LibcryptoCipherDifferential.with_one_bit_flipped(beryl_sealed, generator)
          beryl_verdict = beryl_cipher.decrypt(altered, nonce: nonce, associated_data: associated_data)
          libcrypto_verdict = LibcryptoCipherDifferential.libcrypto_run(
            libcrypto_cipher, false, libcrypto_key, libcrypto_nonce, associated_data, altered, tag_bytesize
          )
          unless beryl_verdict.nil? && libcrypto_verdict.nil?
            LibcryptoDifferential.report_mismatch(
              "cipher {{ algorithm[0].id }}", case_number,
              "a message with one bit flipped was #{beryl_verdict ? "accepted" : "refused"} by Beryl and " \
              "#{libcrypto_verdict ? "accepted" : "refused"} by libcrypto"
            )
          end
        end
        STDOUT.puts "differential cipher {{ algorithm[0].id }}: #{settings.case_count} cases, #{bytes_encrypted} bytes, " \
                    "#{unusual_nonce_count} with a nonce that is not 12 bytes, #{short_tag_count} with a tag under 16 bytes, 0 mismatches"
      end
    {% end %}

    {% for algorithm, algorithm_number in [{"AES-128-CBC", "aes-128-cbc", 16}, {"AES-192-CBC", "aes-192-cbc", 24}, {"AES-256-CBC", "aes-256-cbc", 32}] %}
      it "cipher {{ algorithm[0].id }} equals libcrypto on random keys, initialization vectors and messages" do
        settings = LibcryptoDifferential.settings
        LibcryptoDifferential.describe_run("cipher {{ algorithm[0].id }}", settings.case_count)
        libcrypto_cipher = LibcryptoCipherDifferential.cipher_named({{ algorithm[1] }})
        bytes_encrypted = 0_u64
        refused_by_both_count = 0

        settings.case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for(300 + {{ algorithm_number }}, case_number)
          key = LibcryptoCipherDifferential.random_bytes(generator, {{ algorithm[2] }})
          initialization_vector = LibcryptoCipherDifferential.random_bytes(generator, 16)
          message = LibcryptoCipherDifferential.random_bytes(generator, LibcryptoCipherDifferential.random_message_bytesize(generator))
          bytes_encrypted += message.size

          beryl_cipher = Beryl::Crypto::Compatibility::AESCBC.new(key)
          beryl_ciphertext = beryl_cipher.encrypt(message, initialization_vector: initialization_vector)
          libcrypto_ciphertext = LibcryptoCipherDifferential.libcrypto_run(
            libcrypto_cipher, true, key, initialization_vector, Bytes.empty, message, 0
          )
          unless beryl_ciphertext == libcrypto_ciphertext
            LibcryptoDifferential.report_mismatch("cipher {{ algorithm[0].id }}", case_number, "encrypting #{message.size} bytes gives different ciphertexts")
          end
          unless beryl_cipher.decrypt(beryl_ciphertext, initialization_vector: initialization_vector) == message
            LibcryptoDifferential.report_mismatch("cipher {{ algorithm[0].id }}", case_number, "Beryl does not decrypt its own message of #{message.size} bytes")
          end

          # CBC carries no tag, so a flipped bit is refused only when it
          # breaks the padding; either way both must give the same answer.
          altered = LibcryptoCipherDifferential.with_one_bit_flipped(beryl_ciphertext, generator)
          beryl_plaintext = beryl_cipher.decrypt(altered, initialization_vector: initialization_vector)
          libcrypto_plaintext = LibcryptoCipherDifferential.libcrypto_run(
            libcrypto_cipher, false, key, initialization_vector, Bytes.empty, altered, 0
          )
          refused_by_both_count += 1 if beryl_plaintext.nil? && libcrypto_plaintext.nil?
          unless beryl_plaintext == libcrypto_plaintext
            LibcryptoDifferential.report_mismatch(
              "cipher {{ algorithm[0].id }}", case_number,
              "a ciphertext with one bit flipped was #{beryl_plaintext ? "decrypted" : "refused"} by Beryl and " \
              "#{libcrypto_plaintext ? "decrypted" : "refused"} by libcrypto"
            )
          end
        end
        STDOUT.puts "differential cipher {{ algorithm[0].id }}: #{settings.case_count} cases, #{bytes_encrypted} bytes, " \
                    "#{refused_by_both_count} altered ciphertexts refused by both for their padding, 0 mismatches"
      end
    {% end %}
  end
end
