require "../../spec_helper"

private alias ChaCha20 = Beryl::Crypto::V1::ChaCha20StreamCipher
private alias Poly1305 = Beryl::Crypto::V1::Poly1305OneTimeAuthenticator

private def poly1305_tag(key : Bytes, message : Bytes) : Bytes
  tag = Bytes.new(16)
  Poly1305.authenticate(key, message, tag)
  tag
end

describe "RFC 8439 vectors" do
  rfc_text = VectorFile.read("rfc/rfc8439.txt")

  it "ChaCha20 encrypts the three messages of Appendix A.2" do
    list_of_lines = RfcHexDump.section(rfc_text, /\AA\.2\.  ChaCha20 Encryption/, /\AA\.3\.  /)
    list_of_keys = RfcHexDump.values_after(list_of_lines, /\A\s+Key:/)
    list_of_nonces = RfcHexDump.values_after(list_of_lines, /\A\s+Nonce:/)
    list_of_plaintexts = RfcHexDump.values_after(list_of_lines, /\A\s+Plaintext:/)
    list_of_ciphertexts = RfcHexDump.values_after(list_of_lines, /\A\s+Ciphertext:/)
    list_of_counters = list_of_lines.compact_map { |line| line.match(/Initial Block Counter = (\d+)/).try(&.[1].to_u32) }
    list_of_keys.size.should eq(3)
    list_of_counters.should eq([0_u32, 1_u32, 42_u32])

    list_of_keys.each_with_index do |key, index|
      plaintext = list_of_plaintexts[index]
      ciphertext = Bytes.new(plaintext.size)
      ChaCha20.xor_keystream(key, list_of_nonces[index], list_of_counters[index], plaintext, ciphertext)
      ciphertext.should eq(list_of_ciphertexts[index])
      VectorCaseCount.record("ChaCha20", "RFC")
    end
  end

  it "ChaCha20 produces the five keystream blocks of Appendix A.1" do
    list_of_lines = RfcHexDump.section(rfc_text, /\AA\.1\.  The ChaCha20 Block Functions/, /\AA\.2\.  /)
    list_of_keys = RfcHexDump.values_after(list_of_lines, /\A\s+Key:/)
    list_of_nonces = RfcHexDump.values_after(list_of_lines, /\A\s+Nonce:/)
    list_of_keystreams = RfcHexDump.values_after(list_of_lines, /\A\s+Keystream:/)
    list_of_counters = list_of_lines.compact_map { |line| line.match(/\A\s+Block Counter = (\d+)/).try(&.[1].to_u32) }
    list_of_keystreams.size.should eq(5)

    list_of_keys.each_with_index do |key, index|
      keystream = Bytes.new(64)
      ChaCha20.xor_keystream(key, list_of_nonces[index], list_of_counters[index], Bytes.new(64), keystream)
      keystream.should eq(list_of_keystreams[index])
      VectorCaseCount.record("ChaCha20", "RFC")
    end
  end

  it "Poly1305 authenticates the four messages of Appendix A.3 printed as dumps" do
    list_of_lines = RfcHexDump.section(rfc_text, /\AA\.3\.  Poly1305 Message Authentication Code/, /\A\s+Test Vector #5/)
    list_of_keys = RfcHexDump.values_after(list_of_lines, /\A\s+One-time Poly1305 Key:/)
    list_of_messages = RfcHexDump.values_after(list_of_lines, /\A\s+Text to MAC:/)
    list_of_tags = RfcHexDump.values_after(list_of_lines, /\A\s+Tag:/)
    list_of_keys.size.should eq(4)

    list_of_keys.each_with_index do |key, index|
      poly1305_tag(key, list_of_messages[index]).should eq(list_of_tags[index])
      VectorCaseCount.record("Poly1305", "RFC")
    end
  end

  it "Poly1305 reduces correctly in the seven edge cases of Appendix A.3" do
    list_of_lines = RfcHexDump.section(rfc_text, /\A\s+Test Vector #5: If one uses 130-bit partial reduction/, /\AA\.4\.  /)
    list_of_r = RfcHexDump.values_after(list_of_lines, /\A\s+R:\s*\z/)
    list_of_s = RfcHexDump.values_after(list_of_lines, /\A\s+S:\s*\z/)
    list_of_messages = RfcHexDump.values_after(list_of_lines, /\A\s+data:\s*\z/)
    list_of_tags = RfcHexDump.values_after(list_of_lines, /\A\s+tag:\s*\z/)
    list_of_r.size.should eq(7)

    list_of_r.each_with_index do |r, index|
      key = Bytes.new(32)
      r.copy_to(key)
      list_of_s[index].copy_to(key[16, 16])
      poly1305_tag(key, list_of_messages[index]).should eq(list_of_tags[index])
      VectorCaseCount.record("Poly1305", "RFC")
    end
  end

  it "Poly1305 authenticates the message of section 2.5.2" do
    key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b".hexbytes
    list_of_lines = RfcHexDump.section(rfc_text, /\A2\.5\.2\.  Poly1305 Example and Test Vector/, /\A2\.6\.  /)
    section_text = list_of_lines.join('\n')
    section_text.should contain("r before clamping: 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8")
    section_text.should contain("01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b")
    message = RfcHexDump.values_after(list_of_lines, /\A\s+Message to be Authenticated:/).first
    section_text.should contain("Tag: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
    poly1305_tag(key, message).should eq("a8061dc1305136c6c22b8baf0c0127a9".hexbytes)
    VectorCaseCount.record("Poly1305", "RFC")
  end

  it "ChaCha20-Poly1305 seals the message of section 2.8.2" do
    list_of_lines = RfcHexDump.section(rfc_text, /\A2\.8\.2\.  Example and Test Vector for AEAD_CHACHA20_POLY1305/, /\A3\.  /)
    plaintext = RfcHexDump.values_after(list_of_lines, /\A\s+Plaintext:/).first
    associated_data = RfcHexDump.values_after(list_of_lines, /\A\s+AAD:/).first
    key = RfcHexDump.values_after(list_of_lines, /\A\s+Key:/).first
    ciphertext = RfcHexDump.values_after(list_of_lines, /\A\s+Ciphertext:/).first
    tag = RfcHexDump.values_after(list_of_lines, /\A\s+Tag:/).first
    # The nonce is printed as a constant and an IV: 07 00 00 00, then 40 to 47.
    nonce = "070000004041424344454647".hexbytes
    String.new(plaintext).should start_with("Ladies and Gentlemen of the class of '99")
    tag.size.should eq(16)

    cipher = Beryl::Crypto::V1::ChaCha20Poly1305.new(key)
    sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)
    sealed[0, plaintext.size].should eq(ciphertext)
    sealed[plaintext.size, 16].should eq(tag)
    cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should eq(plaintext)
    VectorCaseCount.record("ChaCha20-Poly1305", "RFC")
  end

  it "ChaCha20-Poly1305 opens the message of Appendix A.5" do
    list_of_lines = RfcHexDump.section(rfc_text, /\AA\.5\.  ChaCha20-Poly1305 AEAD Decryption/, /\AAppendix B\.  /)
    key = RfcHexDump.values_after(list_of_lines, /\A\s+The ChaCha20 Key\s*\z/).first
    ciphertext = RfcHexDump.values_after(list_of_lines, /\A\s+Ciphertext:/).first
    nonce = RfcHexDump.values_after(list_of_lines, /\A\s+The nonce:/).first
    associated_data = RfcHexDump.values_after(list_of_lines, /\A\s+The AAD:/).first
    tag = RfcHexDump.values_after(list_of_lines, /\A\s+Received Tag:/).first
    ciphertext.size.should eq(265)

    sealed = Bytes.new(ciphertext.size + tag.size)
    ciphertext.copy_to(sealed)
    tag.copy_to(sealed[ciphertext.size, tag.size])
    plaintext = Beryl::Crypto::V1::ChaCha20Poly1305.new(key).decrypt(sealed, nonce: nonce, associated_data: associated_data)
    plaintext.should_not be_nil
    String.new(plaintext.as(Bytes)).should start_with("Internet-Drafts are draft documents valid for a maximum of six months")
    VectorCaseCount.record("ChaCha20-Poly1305", "RFC")
  end
end

describe "draft-irtf-cfrg-xchacha-03 vectors" do
  draft_text = VectorFile.read("rfc/draft-irtf-cfrg-xchacha-03.txt")

  it "HChaCha20 derives the subkey of section 2.2.1" do
    draft_text.should contain("Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:")
    draft_text.should contain("Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27)")
    list_of_lines = RfcHexDump.section(draft_text, /HChaCha20 will then return only the first and last rows/, /Resultant HChaCha20 subkey/)
    # The subkey is printed as eight words, most significant digit first.
    list_of_words = list_of_lines.join(' ').scan(/\b[0-9a-f]{8}\b/).map(&.[0])
    list_of_words.size.should eq(8)

    key = Bytes.new(32) { |index| index.to_u8 }
    subkey = Bytes.new(32)
    ChaCha20.derive_subkey(key, "000000090000004a0000000031415927".hexbytes, subkey)
    subkey.hexstring.should eq(list_of_words.join)
    VectorCaseCount.record("HChaCha20", "RFC")
  end

  it "XChaCha20-Poly1305 seals the message of Appendix A.3.1" do
    list_of_lines = RfcHexDump.section(draft_text, /\AA\.3\.1\.  AEAD_XCHACHA20_POLY1305/, /\AA\.3\.2\.  /)
    plaintext = RfcHexDump.values_after(list_of_lines, /\A\s+Plaintext:/).first
    associated_data = RfcHexDump.values_after(list_of_lines, /\A\s+AAD:/).first
    key = RfcHexDump.values_after(list_of_lines, /\A\s+Key:/).first
    nonce = RfcHexDump.values_after(list_of_lines, /\A\s+IV:/).first
    ciphertext = RfcHexDump.values_after(list_of_lines, /\A\s+Ciphertext:/).first
    tag = RfcHexDump.values_after(list_of_lines, /\A\s+Tag:/).first
    nonce.size.should eq(24)
    plaintext.size.should eq(114)

    cipher = Beryl::Crypto::V1::XChaCha20Poly1305.new(key)
    sealed = cipher.encrypt(plaintext, nonce: nonce, associated_data: associated_data)
    sealed[0, plaintext.size].should eq(ciphertext)
    sealed[plaintext.size, 16].should eq(tag)
    cipher.decrypt(sealed, nonce: nonce, associated_data: associated_data).should eq(plaintext)
    VectorCaseCount.record("XChaCha20-Poly1305", "RFC")
  end
end
