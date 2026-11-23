require "../../spec_helper"

# The published vectors for the curves: RFC 7748 (X25519), RFC 8032
# (Ed25519), RFC 6979 (deterministic ECDSA on P-256 and P-384) and NIST CAVP
# 186-4 (ECDSA SigVer, SigGen, KeyPair and PKV on P-256 and P-384).

private alias X25519 = Beryl::Crypto::V1::X25519
private alias Ed25519 = Beryl::Crypto::V1::Ed25519
private alias P256 = Beryl::Crypto::V1::P256
private alias P384 = Beryl::Crypto::V1::P384
private alias SignatureFormat = Beryl::Crypto::V1::SignatureFormat

# Hashes a message with the hash a vector file names.
private def digest_named(hash_name : String, message : Bytes) : Bytes
  case hash_name.delete('-').upcase
  when "SHA1"   then Beryl::Crypto::Compatibility::SHA1.digest(message)
  when "SHA224" then Beryl::Crypto::V1::SHA224.digest(message)
  when "SHA256" then Beryl::Crypto::V1::SHA256.digest(message)
  when "SHA384" then Beryl::Crypto::V1::SHA384.digest(message)
  when "SHA512" then Beryl::Crypto::V1::SHA512.digest(message)
  else               raise "no hash named #{hash_name}"
  end
end

# Runs the RFC 7748 iteration of §5.2: k and u start at 9, and each step
# sets k to X25519(k, u) and u to the old k.
private def x25519_iterate(iteration_count : Int32) : Bytes
  scalar = X25519::BASE_POINT_U.dup
  u_coordinate = X25519::BASE_POINT_U.dup
  iteration_count.times do
    result = X25519.scalar_multiply(scalar, u_coordinate)
    u_coordinate = scalar
    scalar = result
  end
  scalar
end

describe "RFC 7748 X25519 vectors" do
  rfc_text = VectorFile.read("rfc/rfc7748.txt")
  list_of_lines = RfcTextVectors.section(rfc_text, /\A5\.2\.\s+Test Vectors/, /\A6\.\s+Diffie-Hellman/)

  it "computes both scalar multiplications of section 5.2" do
    x25519_lines = list_of_lines[0, list_of_lines.index! { |line| line.includes?("X448:") }]
    vector_starts = x25519_lines.each_index.select { |index| x25519_lines[index].strip == "Input scalar:" }.to_a
    vector_starts.size.should eq(2)
    vector_starts.each do |start|
      block = x25519_lines[start..]
      scalar = RfcTextVectors.hex_after(block, /\A\s+Input scalar:\z/).hexbytes
      u_coordinate = RfcTextVectors.hex_after(block, /\A\s+Input u-coordinate:\z/).hexbytes
      expected = RfcTextVectors.hex_after(block, /\A\s+Output u-coordinate:\z/).hexbytes
      X25519.scalar_multiply(scalar, u_coordinate).should eq(expected)
      VectorCaseCount.record("X25519", "RFC")
    end
  end

  it "matches the iteration of section 5.2 after 1 and 1,000 steps" do
    x25519_lines = list_of_lines[list_of_lines.index! { |line| line.includes?("For X25519:") }..]
    x25519_iterate(1).should eq(RfcTextVectors.hex_after(x25519_lines, /After one iteration:/).hexbytes)
    x25519_iterate(1_000).should eq(RfcTextVectors.hex_after(x25519_lines, /After 1,000 iterations:/).hexbytes)
    VectorCaseCount.record("X25519", "RFC", 2)
  end

  it "reproduces the Diffie-Hellman example of section 6.1" do
    section = RfcTextVectors.section(rfc_text, /\A6\.1\.\s+Curve25519/, /\A6\.2\./)
    alice = X25519::PrivateKey.new(RfcTextVectors.hex_after(section, /Alice's private key, a:/).hexbytes)
    bob = X25519::PrivateKey.new(RfcTextVectors.hex_after(section, /Bob's private key, b:/).hexbytes)
    alice.public_key.to_slice.should eq(RfcTextVectors.hex_after(section, /Alice's public key, X25519\(a, 9\):/).hexbytes)
    bob.public_key.to_slice.should eq(RfcTextVectors.hex_after(section, /Bob's public key, X25519\(b, 9\):/).hexbytes)
    shared = RfcTextVectors.hex_after(section, /Their shared secret, K:/).hexbytes
    alice.shared_secret(bob.public_key).should eq(shared)
    bob.shared_secret(alice.public_key).should eq(shared)
    VectorCaseCount.record("X25519", "RFC")
  end
end

if RequestedSpecTag.includes?("slow")
  describe "RFC 7748 X25519 iteration", tags: "slow" do
    it "matches the iteration of section 5.2 after 1,000,000 steps" do
      rfc_text = VectorFile.read("rfc/rfc7748.txt")
      list_of_lines = RfcTextVectors.section(rfc_text, /\A5\.2\.\s+Test Vectors/, /\A6\.\s+Diffie-Hellman/)
      x25519_lines = list_of_lines[list_of_lines.index! { |line| line.includes?("For X25519:") }..]
      x25519_iterate(1_000_000).should eq(RfcTextVectors.hex_after(x25519_lines, /After 1,000,000 iterations:/).hexbytes)
      VectorCaseCount.record("X25519", "RFC")
    end
  end
end

describe "RFC 8032 Ed25519 vectors" do
  it "derives each public key and signature of section 7.1, and verifies the signature" do
    list_of_cases = RfcTextVectors.rfc8032_ed25519_cases(VectorFile.read("rfc/rfc8032.txt"))
    list_of_cases.size.should eq(5)
    list_of_cases.each do |test_case|
      signing_key = Ed25519::SigningKey.new(test_case.secret_key)
      signing_key.verification_key.to_slice.should eq(test_case.public_key)
      signing_key.sign(test_case.message).should eq(test_case.signature)
      Ed25519::VerificationKey.new(test_case.public_key).verify(test_case.message, test_case.signature).should be_true
      VectorCaseCount.record("Ed25519", "RFC")
    end
  end
end

describe "RFC 6979 deterministic ECDSA vectors" do
  rfc_text = VectorFile.read("rfc/rfc6979.txt")

  it "signs every P-256 case of appendix A.2.5 with the published nonce and signature" do
    vectors = RfcTextVectors.rfc6979_cases(rfc_text, /\AA\.2\.5\.\s+ECDSA, 256 Bits/, /\AA\.2\.6\./)
    vectors.list_of_cases.size.should eq(10)
    private_key = P256::PrivateKey.new(vectors.private_key.hexbytes)
    private_key.public_key.to_uncompressed.hexstring.should eq("04" + vectors.public_x + vectors.public_y)
    vectors.list_of_cases.each do |test_case|
      message = test_case.message.to_slice
      digest = digest_named(test_case.hash, message)
      signature = {% begin %}
        case test_case.hash
        {% for name in [{"SHA-1", "Beryl::Crypto::Compatibility::SHA1"}, {"SHA-224", "Beryl::Crypto::V1::SHA224"},
                        {"SHA-256", "Beryl::Crypto::V1::SHA256"}, {"SHA-384", "Beryl::Crypto::V1::SHA384"},
                        {"SHA-512", "Beryl::Crypto::V1::SHA512"}] %}
          when {{ name[0] }}
            nonce = Beryl::Crypto::V1::DeterministicSignatureNonce({{ name[1].id }}).generate(
              private_key.to_slice, P256::Arithmetic.limbs_to_big_endian(P256::Arithmetic.reduce_once_modulo_order(P256::Arithmetic.digest_to_integer(digest))),
              P256::Arithmetic::GROUP_ORDER)
            nonce.hexstring.should eq(test_case.k)
            private_key.sign_digest(digest, {{ name[1].id }}, format: SignatureFormat::FixedWidth)
        {% end %}
        else
          raise "unexpected hash #{test_case.hash}"
        end
      {% end %}
      signature.hexstring.should eq(test_case.r + test_case.s)
      private_key.public_key.verify_digest(digest, signature, format: SignatureFormat::FixedWidth).should be_true
      VectorCaseCount.record("P-256 ECDSA", "RFC")
    end
  end

  it "derives every P-384 nonce of appendix A.2.6 and verifies each signature" do
    vectors = RfcTextVectors.rfc6979_cases(rfc_text, /\AA\.2\.6\.\s+ECDSA, 384 Bits/, /\AA\.2\.7\./)
    vectors.list_of_cases.size.should eq(10)
    private_scalar = vectors.private_key.hexbytes
    P384::Arithmetic.encode_uncompressed(P384::Arithmetic.multiply_generator(private_scalar)).hexstring.should eq("04" + vectors.public_x + vectors.public_y)
    public_key = P384::PublicKey.new(("04" + vectors.public_x + vectors.public_y).hexbytes)
    vectors.list_of_cases.each do |test_case|
      digest = digest_named(test_case.hash, test_case.message.to_slice)
      reduced = P384::Arithmetic.limbs_to_big_endian(P384::Arithmetic.reduce_once_modulo_order(P384::Arithmetic.digest_to_integer(digest)))
      nonce = {% begin %}
        case test_case.hash
        {% for name in [{"SHA-1", "Beryl::Crypto::Compatibility::SHA1"}, {"SHA-224", "Beryl::Crypto::V1::SHA224"},
                        {"SHA-256", "Beryl::Crypto::V1::SHA256"}, {"SHA-384", "Beryl::Crypto::V1::SHA384"},
                        {"SHA-512", "Beryl::Crypto::V1::SHA512"}] %}
          when {{ name[0] }}
            Beryl::Crypto::V1::DeterministicSignatureNonce({{ name[1].id }}).generate(private_scalar, reduced, P384::Arithmetic::GROUP_ORDER)
        {% end %}
        else
          raise "unexpected hash #{test_case.hash}"
        end
      {% end %}
      nonce.hexstring.should eq(test_case.k)
      public_key.verify_digest(digest, (test_case.r + test_case.s).hexbytes, format: SignatureFormat::FixedWidth).should be_true
      VectorCaseCount.record("P-384 ECDSA", "RFC")
    end
  end
end

describe "NIST CAVP 186-4 ECDSA vectors" do
  {% for curve in [{"P-256", "P256", 32}, {"P-384", "P384", 48}] %}
    it "{{ curve[0].id }}: decides every SigVer.rsp case as marked" do
      cases_run = 0
      CavpEcdsaFile.parse(VectorFile.read("nist-cavp/ecdsa/SigVer.rsp")).each do |test_case|
        next unless test_case.curve == {{ curve[0] }}
        fields = test_case.fields
        public_key = {{ curve[1].id }}::PublicKey.new(("04" + fields["Qx"] + fields["Qy"]).hexbytes)
        signature = ((CavpEcdsaFile.fixed_width(fields["R"], {{ curve[2] }}) || Bytes.empty).to_a +
                     (CavpEcdsaFile.fixed_width(fields["S"], {{ curve[2] }}) || Bytes.empty).to_a)
        digest = digest_named(test_case.hash.not_nil!, fields["Msg"].hexbytes)
        is_accepted = public_key.verify_digest(digest, Bytes.new(signature.size) { |index| signature[index] }, format: SignatureFormat::FixedWidth)
        is_accepted.should eq(fields["Result"].starts_with?("P")), "SigVer #{test_case.curve},#{test_case.hash} case #{cases_run} (#{fields["Result"]})"
        cases_run += 1
      end
      cases_run.should be > 0
      VectorCaseCount.record({{ curve[0] }} + " ECDSA", "CAVP", cases_run)
    end

    it "{{ curve[0].id }}: decides every PKV.rsp public key as marked" do
      cases_run = 0
      CavpEcdsaFile.parse(VectorFile.read("nist-cavp/ecdsa/PKV.rsp")).each do |test_case|
        next unless test_case.curve == {{ curve[0] }}
        fields = test_case.fields
        x = CavpEcdsaFile.fixed_width(fields["Qx"], {{ curve[2] }})
        y = CavpEcdsaFile.fixed_width(fields["Qy"], {{ curve[2] }})
        is_accepted = if x && y
                        encoded = Bytes.new(1 + 2 * {{ curve[2] }})
                        encoded[0] = 0x04_u8
                        x.copy_to(encoded[1, {{ curve[2] }}])
                        y.copy_to(encoded[1 + {{ curve[2] }}, {{ curve[2] }}])
                        begin
                          {{ curve[1].id }}::PublicKey.new(encoded)
                          true
                        rescue Beryl::Crypto::InvalidPublicKey
                          false
                        end
                      else
                        false
                      end
        is_accepted.should eq(fields["Result"].starts_with?("P")), "PKV #{test_case.curve} case #{cases_run} (#{fields["Result"]})"
        cases_run += 1
      end
      cases_run.should be > 0
      VectorCaseCount.record({{ curve[0] }} + " ECDSA", "CAVP", cases_run)
    end

    it "{{ curve[0].id }}: derives every KeyPair.rsp public key" do
      cases_run = 0
      CavpEcdsaFile.parse(VectorFile.read("nist-cavp/ecdsa/KeyPair.rsp")).each do |test_case|
        # A section opens with a count line (N = 10), not a case.
        next unless test_case.curve == {{ curve[0] }} && test_case.fields.has_key?("d")
        fields = test_case.fields
        private_scalar = CavpEcdsaFile.fixed_width(fields["d"], {{ curve[2] }}).not_nil!
        expected = "04" + CavpEcdsaFile.fixed_width(fields["Qx"], {{ curve[2] }}).not_nil!.hexstring +
                   CavpEcdsaFile.fixed_width(fields["Qy"], {{ curve[2] }}).not_nil!.hexstring
        {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic.multiply_generator(private_scalar)).hexstring.should eq(expected)
        cases_run += 1
      end
      cases_run.should be > 0
      VectorCaseCount.record({{ curve[0] }} + " ECDSA", "CAVP", cases_run)
    end
  {% end %}

  it "P-256: reproduces every SigGen.txt signature from its key and nonce" do
    cases_run = 0
    CavpEcdsaFile.parse(VectorFile.read("nist-cavp/ecdsa/SigGen.txt")).each do |test_case|
      next unless test_case.curve == "P-256"
      fields = test_case.fields
      private_key = P256::PrivateKey.new(CavpEcdsaFile.fixed_width(fields["d"], 32).not_nil!)
      private_key.public_key.to_uncompressed.hexstring.should eq("04" + fields["Qx"] + fields["Qy"])
      digest = digest_named(test_case.hash.not_nil!, fields["Msg"].hexbytes)
      nonce = CavpEcdsaFile.fixed_width(fields["k"], 32).not_nil!
      signature = private_key.sign_with_nonce(digest, nonce, format: SignatureFormat::FixedWidth)
      signature.hexstring.should eq(fields["R"] + fields["S"])
      cases_run += 1
    end
    cases_run.should eq(60)
    VectorCaseCount.record("P-256 ECDSA", "CAVP", cases_run)
  end

  it "P-384: verifies every SigGen.txt signature" do
    cases_run = 0
    CavpEcdsaFile.parse(VectorFile.read("nist-cavp/ecdsa/SigGen.txt")).each do |test_case|
      next unless test_case.curve == "P-384"
      fields = test_case.fields
      public_key = P384::PublicKey.new(("04" + fields["Qx"] + fields["Qy"]).hexbytes)
      digest = digest_named(test_case.hash.not_nil!, fields["Msg"].hexbytes)
      public_key.verify_digest(digest, (fields["R"] + fields["S"]).hexbytes, format: SignatureFormat::FixedWidth).should be_true
      cases_run += 1
    end
    cases_run.should eq(60)
    VectorCaseCount.record("P-384 ECDSA", "CAVP", cases_run)
  end
end
