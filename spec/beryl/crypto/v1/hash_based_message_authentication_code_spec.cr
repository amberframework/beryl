require "../../../spec_helper"

private alias HMACSHA256 = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256)

# RFC 4231 test case 2.
private KEY     = "Jefe"
private MESSAGE = "what do ya want for nothing?"
private TAG     = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".hexbytes

# SHA-256 that declines to have its last block laid out ahead of time, which
# sends HMAC down the path that hashes the inner digest step by step.
private class SHA256WithoutPreparedBlock < Beryl::Crypto::V1::SHA256
  def lay_out_final_block(prepared_block : Bytes, tail_bytesize : Int32, message_bytesize : UInt64) : Bool
    false
  end
end

describe Beryl::Crypto::V1::HashBasedMessageAuthenticationCode do
  it "is aliased as HMAC" do
    Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256)
      .should eq(Beryl::Crypto::V1::HashBasedMessageAuthenticationCode(Beryl::Crypto::V1::SecureHashWith256BitDigest))
  end

  describe ".authenticate" do
    it "returns the tag of a message in one call" do
      HMACSHA256.authenticate(MESSAGE, key: KEY).should eq(TAG)
      HMACSHA256.authenticate(MESSAGE.to_slice, key: KEY.to_slice).should eq(TAG)
    end
  end

  describe ".verify" do
    it "accepts the right tag and refuses any other" do
      HMACSHA256.verify(MESSAGE, TAG, key: KEY).should be_true
      HMACSHA256.verify(MESSAGE + "!", TAG, key: KEY).should be_false
      HMACSHA256.verify(MESSAGE, TAG, key: "Jefa").should be_false
    end
  end

  describe "#update and #final" do
    it "gives the same tag however the message is split" do
      (0..MESSAGE.bytesize).each do |split|
        authentication = HMACSHA256.new(KEY)
        authentication.update(MESSAGE.to_slice[0, split])
        authentication.update(MESSAGE.to_slice[split, MESSAGE.bytesize - split])
        authentication.final.should eq(TAG)
      end
    end

    it "refuses more input after final" do
      authentication = HMACSHA256.new(KEY)
      authentication.update(MESSAGE).final
      expect_raises(Digest::FinalizedError) { authentication.update("more") }
    end

    it "refuses an output buffer of the wrong size" do
      expect_raises(Beryl::Crypto::OutputSizeMismatch, /32 bytes/) do
        HMACSHA256.new(KEY).final(Bytes.new(16))
      end
    end
  end

  describe "#reset" do
    it "starts a new message under the same key" do
      authentication = HMACSHA256.new(KEY)
      authentication.update("another message").final
      authentication.reset
      authentication.update(MESSAGE).final.should eq(TAG)
    end
  end

  describe "#reset" do
    {% for names in LIST_OF_HASH_FUNCTION_NAMES %}
      it "starts over on {{ names[0].id }} after a message abandoned at any point of a block" do
        key = "a key for the abandoned message"
        expected = Beryl::Crypto::V1::HMAC({{ names[1].id }}).authenticate("the next message", key: key)
        authentication = Beryl::Crypto::V1::HMAC({{ names[1].id }}).new(key)
        (0..260).each do |abandoned_bytesize|
          authentication.update(Bytes.new(abandoned_bytesize, 0xff_u8))
          authentication.reset
          authentication.update("the next message").final.should eq(expected)
          authentication.reset
        end
      end

      it "gives the same {{ names[0].id }} tag for one message again and again from one keyed instance" do
        authentication = Beryl::Crypto::V1::HMAC({{ names[1].id }}).new("a key used many times")
        (0..300).each do |message_bytesize|
          message = Bytes.new(message_bytesize) { |index| (index &* 7).to_u8! }
          expected = Beryl::Crypto::V1::HMAC({{ names[1].id }}).authenticate(message, key: "a key used many times")
          authentication.reset
          authentication.update(message).final.should eq(expected)
          authentication.reset
          authentication.update(message).final.should eq(expected)
        end
      end
    {% end %}
  end

  describe "#dup" do
    it "continues independently from a copy" do
      original = HMACSHA256.new(KEY)
      original.update("what do ya want ")
      copy = original.dup
      original.update("for nothing?")
      copy.update("for something?")

      original.final.should eq(TAG)
      copy.final.should eq(HMACSHA256.authenticate("what do ya want for something?", key: KEY))
      copy.reset.update(MESSAGE).final.should eq(TAG)
    end

    it "gives a copy made after final the same tag for the next message" do
      authentication = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA512).new("key")
      first_tag = authentication.update("first").final
      copy = authentication.dup
      copy.reset
      copy.update("first").final.should eq(first_tag)
    end
  end

  describe "the outer hash" do
    it "gives the same tag whether its last block was laid out when keyed or is hashed step by step" do
      (0..150).each do |message_bytesize|
        message = Bytes.new(message_bytesize) { |index| (index &* 13).to_u8! }
        expected = Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256).authenticate(message, key: "outer key")
        authentication = Beryl::Crypto::V1::HMAC(SHA256WithoutPreparedBlock).new("outer key")
        authentication.update(message).final.should eq(expected)
        authentication.reset
        authentication.update(message).verify(expected).should be_true
      end
    end
  end

  describe "#digest_size" do
    it "is the digest size of the hash" do
      HMACSHA256.new(KEY).digest_size.should eq(32)
      Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA512).new(KEY).digest_size.should eq(64)
      Beryl::Crypto::V1::HMAC(Beryl::Crypto::Compatibility::MD5).new(KEY).digest_size.should eq(16)
    end
  end

  describe "keys" do
    {% for names in LIST_OF_HASH_FUNCTION_NAMES %}
      it "hashes a key longer than the {{ names[0].id }} block and pads a shorter one (RFC 2104 section 2)" do
        block_bytesize = {{ names[1].id }}::BLOCK_SIZE
        long_key = Bytes.new(block_bytesize + 1) { |index| index.to_u8! }
        hashed_key = {{ names[1].id }}.digest(long_key)
        padded_key = Bytes.new(block_bytesize)
        hashed_key.copy_to(padded_key)

        hmac = Beryl::Crypto::V1::HMAC({{ names[1].id }})
        hmac.authenticate(MESSAGE, key: long_key).should eq(hmac.authenticate(MESSAGE, key: hashed_key))
        hmac.authenticate(MESSAGE, key: hashed_key).should eq(hmac.authenticate(MESSAGE, key: padded_key))

        exact_key = Bytes.new(block_bytesize) { |index| index.to_u8! }
        hmac.authenticate(MESSAGE, key: exact_key).should_not eq(hmac.authenticate(MESSAGE, key: long_key))
      end

      it "accepts an empty key and an empty message on {{ names[0].id }}" do
        hmac = Beryl::Crypto::V1::HMAC({{ names[1].id }})
        tag = hmac.authenticate("", key: "")
        tag.size.should eq({{ names[1].id }}::DIGEST_SIZE)
        hmac.verify("", tag, key: Bytes.empty).should be_true
      end
    {% end %}
  end

  describe "#verify" do
    it "accepts the right tag" do
      HMACSHA256.new(KEY).update(MESSAGE).verify(TAG).should be_true
    end

    it "refuses a tag with any single bit changed" do
      (TAG.size * 8).times do |bit_index|
        altered_tag = TAG.dup
        altered_tag[bit_index // 8] ^= (1_u8 << (bit_index % 8))
        HMACSHA256.new(KEY).update(MESSAGE).verify(altered_tag).should be_false
      end
    end

    it "refuses a tag that is too short, too long or empty, even when its bytes are right" do
      HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[0, 31]).should be_false
      HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[0, 16]).should be_false
      HMACSHA256.new(KEY).update(MESSAGE).verify(Bytes.empty).should be_false
      longer_tag = Bytes.new(33)
      TAG.copy_to(longer_tag)
      HMACSHA256.new(KEY).update(MESSAGE).verify(longer_tag).should be_false
    end

    it "finishes the authentication" do
      authentication = HMACSHA256.new(KEY)
      authentication.update(MESSAGE).verify(TAG)
      expect_raises(Digest::FinalizedError) { authentication.update("more") }
      authentication.reset.update(MESSAGE).verify(TAG).should be_true
    end

    context "with a truncated tag" do
      it "accepts the leading bytes only at the stated size" do
        HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[0, 16], truncated_to_bytesize: 16).should be_true
        HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[0, 20], truncated_to_bytesize: 16).should be_false
        HMACSHA256.new(KEY).update(MESSAGE).verify(TAG, truncated_to_bytesize: 16).should be_false
        HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[16, 16], truncated_to_bytesize: 16).should be_false
      end

      it "refuses to check under half the tag or under 80 bits (RFC 2104 section 5)" do
        expect_raises(Beryl::Crypto::TruncatedTagTooShort, /16 to 32 bytes, not 15/) do
          HMACSHA256.new(KEY).update(MESSAGE).verify(TAG[0, 15], truncated_to_bytesize: 15)
        end
        expect_raises(Beryl::Crypto::TruncatedTagTooShort) do
          HMACSHA256.new(KEY).update(MESSAGE).verify(TAG, truncated_to_bytesize: 33)
        end

        md5_authentication = Beryl::Crypto::V1::HMAC(Beryl::Crypto::Compatibility::MD5).new(KEY)
        expect_raises(Beryl::Crypto::TruncatedTagTooShort, /10 to 16 bytes, not 8/) do
          md5_authentication.update(MESSAGE).verify(Bytes.new(8), truncated_to_bytesize: 8)
        end
      end
    end
  end
end

# An application's own subclass of a Beryl hash, as HMAC's type argument.
private class ApplicationHash < Beryl::Crypto::V1::SHA256
end

describe "HMAC, HKDF and PBKDF2 when a hash has been subclassed" do
  it "still build on the hash and on its subclass" do
    Beryl::Crypto::V1::HMAC(ApplicationHash).authenticate(MESSAGE, key: KEY).should eq(TAG)
    Beryl::Crypto::V1::HMAC(Beryl::Crypto::V1::SHA256).authenticate(MESSAGE, key: KEY).should eq(TAG)
    Beryl::Crypto.derive_key("secret", bytesize: 16).size.should eq(16)
    Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256)
      .derive_key("passwd", salt: "salt", iteration_count: 1, bytesize: 8).hexstring.should eq("55ac046e56e3089f")
  end
end
