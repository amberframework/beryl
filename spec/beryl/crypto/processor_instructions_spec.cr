require "../../spec_helper"

# Each hash below is its parent with the choice of compression function
# removed: it always runs the portable code. On a processor with the SHA
# instructions the parent runs the assembly, so comparing the two checks one
# against the other inside one program; on any other processor, and under
# `-Dberyl_portable_hashes`, both run the portable code and the comparison
# holds trivially.
private class PortableSHA1 < Beryl::Crypto::Compatibility::SHA1
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

private class PortableSHA224 < Beryl::Crypto::V1::SHA224
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

private class PortableSHA256 < Beryl::Crypto::V1::SHA256
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

private class PortableSHA384 < Beryl::Crypto::V1::SHA384
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

private class PortableSHA512 < Beryl::Crypto::V1::SHA512
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

private class PortableSHA512With256BitDigest < Beryl::Crypto::V1::SHA512_256
  private def compress(list_of_blocks : Bytes) : Nil
    compress_with_portable_code(list_of_blocks)
  end
end

# Feeds *message* to *digest* in pieces cut at random points.
private def update_in_random_pieces(digest : ::Digest, message : Bytes, generator : Random) : Nil
  offset = 0
  while offset < message.size
    piece_bytesize = generator.rand(1..(message.size - offset))
    digest.update(message[offset, piece_bytesize])
    offset += piece_bytesize
  end
end

describe "Beryl hashes on the processor's SHA instructions" do
  it "states which instructions this run uses" do
    STDOUT.puts
    has_sha1 = Beryl::Crypto::ProcessorFeatures::HAS_SHA1_INSTRUCTIONS
    has_sha256 = Beryl::Crypto::ProcessorFeatures::HAS_SHA256_INSTRUCTIONS
    has_sha512 = Beryl::Crypto::ProcessorFeatures::HAS_SHA512_INSTRUCTIONS
    STDOUT.puts "SHA instructions in use: SHA-1 #{has_sha1}, SHA-256 #{has_sha256}, SHA-512 #{has_sha512}"
    {% if flag?(:beryl_portable_hashes) %}
      has_sha1.should be_false
      has_sha256.should be_false
      has_sha512.should be_false
    {% elsif flag?(:aarch64) && flag?(:darwin) %}
      has_sha1.should be_true
      has_sha256.should be_true
      has_sha512.should be_true
    {% end %}
  end

  {% for pair in [{"SHA-1", "Beryl::Crypto::Compatibility::SHA1", "PortableSHA1"},
                  {"SHA-224", "Beryl::Crypto::V1::SHA224", "PortableSHA224"},
                  {"SHA-256", "Beryl::Crypto::V1::SHA256", "PortableSHA256"},
                  {"SHA-384", "Beryl::Crypto::V1::SHA384", "PortableSHA384"},
                  {"SHA-512", "Beryl::Crypto::V1::SHA512", "PortableSHA512"},
                  {"SHA-512/256", "Beryl::Crypto::V1::SHA512_256", "PortableSHA512With256BitDigest"}] %}
    it "gives {{ pair[0].id }} the digest of the portable code at every length from 0 to 1,100 bytes" do
      generator = Random.new(20_261_122)
      1_101.times do |message_bytesize|
        message = generator.random_bytes(message_bytesize)
        {{ pair[1].id }}.digest(message).should eq({{ pair[2].id }}.new.update(message).final)
      end
    end

    it "gives {{ pair[0].id }} the digest of the portable code on long messages fed in pieces" do
      generator = Random.new(20_261_123)
      40.times do
        message = generator.random_bytes(generator.rand(0..200_000))
        chosen_hash = {{ pair[1].id }}.new
        portable_hash = {{ pair[2].id }}.new
        update_in_random_pieces(chosen_hash, message, generator)
        update_in_random_pieces(portable_hash, message, generator)
        chosen_hash.final.should eq(portable_hash.final)
      end
    end
  {% end %}
end
