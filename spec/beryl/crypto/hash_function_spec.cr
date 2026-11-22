require "../../spec_helper"

# {standard name, digest bytes, block bytes, digest of "abc", digest of ""}
private LIST_OF_KNOWN_ANSWERS = [
  {"MD5", 16, 64, "900150983cd24fb0d6963f7d28e17f72", "d41d8cd98f00b204e9800998ecf8427e"},
  {"SHA-1", 20, 64, "a9993e364706816aba3e25717850c26c9cd0d89d", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
  {"SHA-224", 28, 64, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
   "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
  {"SHA-256", 32, 64, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
  {"SHA-384", 48, 128,
   "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
   "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
  {"SHA-512", 64, 128,
   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
   "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
  {"SHA-512/256", 32, 128, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
   "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
]

private def message_of_every_byte_value(bytesize : Int32) : Bytes
  Bytes.new(bytesize) { |index| (index % 251).to_u8 }
end

describe "Beryl hash functions" do
  LIST_OF_KNOWN_ANSWERS.each do |standard_name, digest_bytesize, block_bytesize, digest_of_abc, digest_of_nothing|
    describe standard_name do
      build_hash = HASH_FUNCTION_BY_STANDARD_NAME[standard_name]

      it "reports its digest size and block size" do
        build_hash.call.digest_size.should eq(digest_bytesize)
        build_hash.call.block_size.should eq(block_bytesize)
      end

      it "hashes the empty message and \"abc\"" do
        build_hash.call.final.hexstring.should eq(digest_of_nothing)
        build_hash.call.update("abc").final.hexstring.should eq(digest_of_abc)
        build_hash.call.update("abc").hexfinal.should eq(digest_of_abc)
      end

      it "gives the same digest however the message is split across updates" do
        message = message_of_every_byte_value(3 * block_bytesize + 17)
        expected_digest = build_hash.call.update(message).final

        (0..message.size).each do |first_split|
          second_split = first_split + (message.size - first_split) // 2
          hash = build_hash.call
          hash.update(message[0, first_split])
          hash.update(message[first_split, second_split - first_split])
          hash.update(message[second_split, message.size - second_split])
          hash.final.should eq(expected_digest)
        end
      end

      it "gives the same digest fed one byte at a time" do
        message = message_of_every_byte_value(2 * block_bytesize + 3)
        hash = build_hash.call
        message.each { |byte| hash.update(Bytes[byte]) }
        hash.final.should eq(build_hash.call.update(message).final)
      end

      it "pads correctly at every message length around a block boundary" do
        # Checked against the splitting-independent one-shot path; the CAVP
        # short-message vectors pin the absolute values at these lengths.
        (0..(2 * block_bytesize + 1)).each do |bytesize|
          message = message_of_every_byte_value(bytesize)
          streamed_hash = build_hash.call
          streamed_hash.update(message[0, bytesize // 2])
          streamed_hash.update(message[bytesize // 2, bytesize - bytesize // 2])
          streamed_hash.final.should eq(build_hash.call.update(message).final)
        end
      end

      it "starts over after reset" do
        hash = build_hash.call
        hash.update("something else entirely")
        hash.final
        hash.reset
        hash.update("abc").final.hexstring.should eq(digest_of_abc)

        hash.reset.update("discarded before final")
        hash.reset
        hash.final.hexstring.should eq(digest_of_nothing)
      end

      it "refuses more input after final" do
        hash = build_hash.call
        hash.update("abc")
        hash.final
        expect_raises(Digest::FinalizedError) { hash.update("more") }
        expect_raises(Digest::FinalizedError) { hash.final }
      end

      it "refuses an output buffer of the wrong size" do
        expect_raises(Beryl::Crypto::OutputSizeMismatch, /#{digest_bytesize} bytes/) do
          build_hash.call.final(Bytes.new(digest_bytesize - 1))
        end
        expect_raises(Beryl::Crypto::OutputSizeMismatch) do
          build_hash.call.final(Bytes.new(digest_bytesize + 1))
        end
      end

      it "continues independently from a copy" do
        original = build_hash.call
        original.update("ab")
        copy = original.dup
        original.update("c")
        copy.update("d")
        original.final.hexstring.should eq(digest_of_abc)
        copy.final.should eq(build_hash.call.update("abd").final)
      end

      it "is a ::Digest" do
        build_hash.call.should be_a(::Digest)
      end
    end
  end

  it "offers the ::Digest class methods on each class" do
    Beryl::Crypto::V1::SHA256.hexdigest("abc").should eq(LIST_OF_KNOWN_ANSWERS[3][3])
    Beryl::Crypto::V1::SHA256.digest("abc").hexstring.should eq(LIST_OF_KNOWN_ANSWERS[3][3])
    Beryl::Crypto::V1::SHA512.base64digest("abc").should eq(Base64.strict_encode(LIST_OF_KNOWN_ANSWERS[5][3].hexbytes))
    Beryl::Crypto::V1::SHA224.hexdigest(&.update("a").update("bc")).should eq(LIST_OF_KNOWN_ANSWERS[2][3])
    Beryl::Crypto::V1::SHA384.hexdigest("abc").should eq(LIST_OF_KNOWN_ANSWERS[4][3])
    Beryl::Crypto::V1::SHA512_256.hexdigest("abc").should eq(LIST_OF_KNOWN_ANSWERS[6][3])
    Beryl::Crypto::Compatibility::SHA1.hexdigest("abc").should eq(LIST_OF_KNOWN_ANSWERS[1][3])
    Beryl::Crypto::Compatibility::MD5.hexdigest("abc").should eq(LIST_OF_KNOWN_ANSWERS[0][3])
  end

  it "names each class for what it is and aliases the common name" do
    Beryl::Crypto::V1::SHA224.should eq(Beryl::Crypto::V1::SecureHashWith224BitDigest)
    Beryl::Crypto::V1::SHA256.should eq(Beryl::Crypto::V1::SecureHashWith256BitDigest)
    Beryl::Crypto::V1::SHA384.should eq(Beryl::Crypto::V1::SecureHashWith384BitDigest)
    Beryl::Crypto::V1::SHA512.should eq(Beryl::Crypto::V1::SecureHashWith512BitDigest)
    Beryl::Crypto::V1::SHA512_256.should eq(Beryl::Crypto::V1::SecureHashWith512BitStateAnd256BitDigest)
    Beryl::Crypto::Compatibility::SHA1.should eq(Beryl::Crypto::Compatibility::SecureHashAlgorithm1)
    Beryl::Crypto::Compatibility::MD5.should eq(Beryl::Crypto::Compatibility::MessageDigest5)
  end

  it "exposes the digest size and block size as constants" do
    Beryl::Crypto::V1::SHA256::DIGEST_SIZE.should eq(32)
    Beryl::Crypto::V1::SHA256::BLOCK_SIZE.should eq(64)
    Beryl::Crypto::V1::SHA224::DIGEST_SIZE.should eq(28)
    Beryl::Crypto::V1::SHA224::BLOCK_SIZE.should eq(64)
    Beryl::Crypto::V1::SHA384::DIGEST_SIZE.should eq(48)
    Beryl::Crypto::V1::SHA384::BLOCK_SIZE.should eq(128)
    Beryl::Crypto::V1::SHA512::DIGEST_SIZE.should eq(64)
    Beryl::Crypto::V1::SHA512::BLOCK_SIZE.should eq(128)
    Beryl::Crypto::V1::SHA512_256::DIGEST_SIZE.should eq(32)
    Beryl::Crypto::V1::SHA512_256::BLOCK_SIZE.should eq(128)
    Beryl::Crypto::Compatibility::SHA1::DIGEST_SIZE.should eq(20)
    Beryl::Crypto::Compatibility::SHA1::BLOCK_SIZE.should eq(64)
    Beryl::Crypto::Compatibility::MD5::DIGEST_SIZE.should eq(16)
    Beryl::Crypto::Compatibility::MD5::BLOCK_SIZE.should eq(64)
  end

  it "hashes one million repetitions of \"a\" (FIPS 180 long-message example)" do
    chunk = Bytes.new(1000, 'a'.ord.to_u8)
    {
      "SHA-1"   => "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
      "SHA-256" => "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      "SHA-512" => "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    }.each do |standard_name, expected_digest|
      hash = HASH_FUNCTION_BY_STANDARD_NAME[standard_name].call
      1000.times { hash.update(chunk) }
      hash.final.hexstring.should eq(expected_digest)
    end
  end
end
