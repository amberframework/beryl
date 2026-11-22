require "../../spec_helper"

# NIST CAVP: the GCM validation files (`gcmtestvectors.zip`) and the AES
# known-answer and multi-block files (`KAT_AES.zip`, `aesmmt.zip`).

private alias BitslicedAES = Beryl::Crypto::V1::BitslicedAdvancedEncryptionStandard
private alias CipherBlockChaining = Beryl::Crypto::Compatibility::CipherBlockChaining

private def expanded_key(key : Bytes) : {Slice(UInt64), Int32}
  round_keys = Slice(UInt64).new(BitslicedAES::ROUND_KEY_WORD_COUNT, 0_u64)
  BitslicedAES.expand_key(key, round_keys)
  {round_keys, BitslicedAES.round_count_for(key.size)}
end

describe "NIST CAVP cipher vectors" do
  {% for key_bit_size in [128, 192, 256] %}
    it "AES-{{ key_bit_size }}-GCM encrypts every case of gcmEncryptExtIV{{ key_bit_size }}.rsp" do
      list_of_records = CavpResponseFile.parse(VectorFile.read("nist-cavp/gcm/gcmEncryptExtIV{{ key_bit_size }}.rsp"))
      list_of_records.size.should eq(7875)

      list_of_records.each do |record|
        tag = record["Tag"].hexbytes
        cipher = Beryl::Crypto::V1::AESGCM.new(record["Key"].hexbytes, tag_bytesize: tag.size)
        sealed = cipher.encrypt(record["PT"].hexbytes, nonce: record["IV"].hexbytes, associated_data: record["AAD"].hexbytes)
        unless sealed == (record["CT"] + record["Tag"]).hexbytes
          fail "gcmEncryptExtIV{{ key_bit_size }}.rsp: IVlen #{record["IVlen"]}, PTlen #{record["PTlen"]}, AADlen #{record["AADlen"]}, " \
               "Taglen #{record["Taglen"]}, Count #{record["Count"]} gave #{sealed.hexstring}"
        end
      end
      VectorCaseCount.record("AES-GCM", "CAVP", list_of_records.size)
    end

    it "AES-{{ key_bit_size }}-GCM decrypts or refuses every case of gcmDecrypt{{ key_bit_size }}.rsp as marked" do
      list_of_records = CavpResponseFile.parse(VectorFile.read("nist-cavp/gcm/gcmDecrypt{{ key_bit_size }}.rsp"))
      list_of_records.size.should eq(7875)
      refused_count = 0

      list_of_records.each do |record|
        tag = record["Tag"].hexbytes
        cipher = Beryl::Crypto::V1::AESGCM.new(record["Key"].hexbytes, tag_bytesize: tag.size)
        plaintext = cipher.decrypt((record["CT"] + record["Tag"]).hexbytes, nonce: record["IV"].hexbytes, associated_data: record["AAD"].hexbytes)
        expected_plaintext = record.has_key?("FAIL") ? nil : record["PT"].hexbytes
        refused_count += 1 if expected_plaintext.nil?
        unless plaintext == expected_plaintext
          fail "gcmDecrypt{{ key_bit_size }}.rsp: IVlen #{record["IVlen"]}, PTlen #{record["PTlen"]}, AADlen #{record["AADlen"]}, " \
               "Taglen #{record["Taglen"]}, Count #{record["Count"]} gave #{plaintext.try(&.hexstring) || "a refusal"}"
        end
      end
      refused_count.should be > 1000
      VectorCaseCount.record("AES-GCM", "CAVP", list_of_records.size)
    end

    {% for kind in %w[GFSbox KeySbox VarKey VarTxt MMT] %}
      it "AES-{{ key_bit_size }} encrypts and decrypts every block of ECB{{ kind.id }}{{ key_bit_size }}.rsp" do
        list_of_records = CavpResponseFile.parse(VectorFile.read("nist-cavp/aes/ECB{{ kind.id }}{{ key_bit_size }}.rsp"))
        list_of_records.should_not be_empty

        list_of_records.each do |record|
          round_keys, round_count = expanded_key(record["KEY"].hexbytes)
          plaintext = record["PLAINTEXT"].hexbytes
          ciphertext = record["CIPHERTEXT"].hexbytes
          output = Bytes.new(plaintext.size)
          # The file's second half asks for decryption; both directions are
          # checked on every case.
          BitslicedAES.encrypt_blocks(round_keys, round_count, plaintext, output)
          output.should eq(ciphertext)
          BitslicedAES.decrypt_blocks(round_keys, round_count, ciphertext, output)
          output.should eq(plaintext)
        end
        VectorCaseCount.record("AES", "CAVP", list_of_records.size)
      end

      it "AES-{{ key_bit_size }}-CBC encrypts and decrypts every case of CBC{{ kind.id }}{{ key_bit_size }}.rsp" do
        list_of_records = CavpResponseFile.parse(VectorFile.read("nist-cavp/aes/CBC{{ kind.id }}{{ key_bit_size }}.rsp"))
        list_of_records.should_not be_empty

        list_of_records.each do |record|
          round_keys, round_count = expanded_key(record["KEY"].hexbytes)
          initialization_vector = record["IV"].hexbytes
          plaintext = record["PLAINTEXT"].hexbytes
          ciphertext = record["CIPHERTEXT"].hexbytes
          # These files carry whole blocks with no padding, so they go to
          # the chaining itself.
          encrypted = plaintext.dup
          CipherBlockChaining.encrypt_in_place(round_keys, round_count, initialization_vector, encrypted)
          encrypted.should eq(ciphertext)
          decrypted = Bytes.new(ciphertext.size)
          CipherBlockChaining.decrypt(round_keys, round_count, initialization_vector, ciphertext, decrypted)
          decrypted.should eq(plaintext)
        end
        VectorCaseCount.record("AES-CBC", "CAVP", list_of_records.size)
      end
    {% end %}
  {% end %}
end
