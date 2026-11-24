require "../../../spec_helper"
require "big"

private alias X25519 = Beryl::Crypto::V1::X25519
private alias Ed25519 = Beryl::Crypto::V1::Ed25519
private alias P256 = Beryl::Crypto::V1::P256
private alias P384 = Beryl::Crypto::V1::P384
private alias SignatureFormat = Beryl::Crypto::V1::SignatureFormat

describe "Beryl::Crypto public-key convenience calls" do
  it "signs and verifies with Ed25519" do
    signing_key = Beryl::Crypto.generate_signing_key
    signature = Beryl::Crypto.sign("a message", signing_key: signing_key)
    signature.size.should eq(64)
    Beryl::Crypto.verify_signature("a message", signature, verification_key: signing_key.verification_key).should be_true
    Beryl::Crypto.verify_signature("another message", signature, verification_key: signing_key.verification_key).should be_false
  end

  it "agrees on one shared secret with X25519" do
    alice = Beryl::Crypto.generate_key_agreement_key
    bob = Beryl::Crypto.generate_key_agreement_key
    shared = Beryl::Crypto.agree_on_shared_secret(alice, bob.public_key)
    shared.should_not be_nil
    shared.should eq(Beryl::Crypto.agree_on_shared_secret(bob, alice.public_key))
  end
end

describe Beryl::Crypto::V1::X25519 do
  it "refuses the all-zero shared secret of a point of small order" do
    private_key = X25519::PrivateKey.generate
    private_key.shared_secret(X25519::PublicKey.new(Bytes.new(32))).should be_nil
  end

  it "refuses keys of the wrong length" do
    expect_raises(Beryl::Crypto::KeySizeMismatch) { X25519::PrivateKey.new(Bytes.new(31)) }
    expect_raises(Beryl::Crypto::KeySizeMismatch) { X25519::PublicKey.new(Bytes.new(33)) }
  end

  it "derives the public key through edwards25519 as the ladder does" do
    100.times do
      secret = Random::Secure.random_bytes(32)
      X25519.multiply_base_point(secret).should eq(X25519.scalar_multiply(secret, X25519::BASE_POINT_U))
    end
    X25519.multiply_base_point(Bytes.new(32)).should eq(X25519.scalar_multiply(Bytes.new(32), X25519::BASE_POINT_U))
  end

  it "keeps the private key it was given" do
    secret = Bytes.new(32) { |index| index.to_u8 }
    X25519::PrivateKey.new(secret).to_slice.should eq(secret)
  end
end

describe Beryl::Crypto::V1::Ed25519 do
  it "refuses a public key that is not a point" do
    # y = 2 has no x on edwards25519.
    encoded = Bytes.new(32)
    encoded[0] = 2_u8
    expect_raises(Beryl::Crypto::InvalidPublicKey) { Ed25519::VerificationKey.new(encoded) }
  end

  it "refuses a public key whose y is not below p" do
    encoded = Bytes.new(32, 0xff_u8)
    encoded[0] = 0xee_u8
    encoded[31] = 0x7f_u8
    expect_raises(Beryl::Crypto::InvalidPublicKey) { Ed25519::VerificationKey.new(encoded) }
  end

  it "refuses a signature whose S is not below L" do
    signing_key = Ed25519::SigningKey.generate
    signature = signing_key.sign("message")
    group_order = Beryl::Crypto::V1::Edwards25519Group::GROUP_ORDER
    carry = 0
    32.times do |index|
      sum = signature[32 + index].to_i32 + group_order[index] + carry
      signature[32 + index] = (sum & 0xff).to_u8
      carry = sum >> 8
    end
    signing_key.verification_key.verify("message", signature).should be_false
  end

  it "refuses signatures of the wrong length" do
    signing_key = Ed25519::SigningKey.generate
    signing_key.verification_key.verify("message", signing_key.sign("message")[0, 63]).should be_false
  end
end

describe Beryl::Crypto::V1::P256 do
  it "signs, verifies and agrees in both encodings" do
    private_key = P256::PrivateKey.generate
    {SignatureFormat::DER, SignatureFormat::FixedWidth}.each do |format|
      signature = private_key.sign("a message", format: format)
      private_key.public_key.verify("a message", signature, format: format).should be_true
      private_key.public_key.verify("a message!", signature, format: format).should be_false
    end
    peer = P256::PrivateKey.generate
    private_key.shared_secret(peer.public_key).should eq(peer.shared_secret(private_key.public_key))
  end

  it "decodes its own compressed and uncompressed points" do
    public_key = P256::PrivateKey.generate.public_key
    P256::PublicKey.new(public_key.to_compressed).should eq(public_key)
    P256::PublicKey.new(public_key.to_uncompressed).should eq(public_key)
  end

  it "refuses a private key of zero or one not below n" do
    expect_raises(Beryl::Crypto::InvalidPrivateKey) { P256::PrivateKey.new(Bytes.new(32)) }
    expect_raises(Beryl::Crypto::InvalidPrivateKey) { P256::PrivateKey.new(P256::Arithmetic::GROUP_ORDER.dup) }
    expect_raises(Beryl::Crypto::KeySizeMismatch) { P256::PrivateKey.new(Bytes.new(31, 1_u8)) }
  end

  it "refuses points off the curve, at infinity, or with a coordinate not below p" do
    point = P256::PrivateKey.generate.public_key.to_uncompressed
    point[64] ^= 1_u8
    expect_raises(Beryl::Crypto::InvalidPublicKey) { P256::PublicKey.new(point) }
    expect_raises(Beryl::Crypto::InvalidPublicKey) { P256::PublicKey.new(Bytes[0x00]) }
    too_large = Bytes.new(65, 0xff_u8)
    too_large[0] = 0x04_u8
    expect_raises(Beryl::Crypto::InvalidPublicKey) { P256::PublicKey.new(too_large) }
  end

  it "refuses DER that is not strict" do
    private_key = P256::PrivateKey.generate
    signature = private_key.sign("message")
    public_key = private_key.public_key
    public_key.verify("message", signature).should be_true
    with_trailing_byte = Bytes.new(signature.size + 1)
    signature.copy_to(with_trailing_byte)
    public_key.verify("message", with_trailing_byte).should be_false
    long_form = Bytes.new(signature.size + 1)
    long_form[0] = 0x30_u8
    long_form[1] = 0x81_u8
    long_form[2] = signature[1]
    signature[2, signature.size - 2].copy_to(long_form[3, signature.size - 2])
    public_key.verify("message", long_form).should be_false
  end

  it "signs the same digest the same way twice (RFC 6979)" do
    private_key = P256::PrivateKey.generate
    private_key.sign("message").should eq(private_key.sign("message"))
  end
end

describe Beryl::Crypto::V1::P384 do
  it "refuses signatures over another message" do
    private_scalar = Bytes.new(48) { |index| (index + 1).to_u8 }
    point = P384::Arithmetic.encode_uncompressed(P384::Arithmetic.multiply_generator(private_scalar))
    public_key = P384::PublicKey.new(point)
    public_key.verify("message", Bytes.new(96, 1_u8), format: SignatureFormat::FixedWidth).should be_false
    public_key.verify("message", Bytes.new(96), format: SignatureFormat::FixedWidth).should be_false
  end
end

# The constant-time multiplications keep a stand-in point while the sum is
# still infinity and read a real multiple for each digit 0, so scalars with
# long runs of zero windows, at the bottom, in the middle or at the top,
# are where they could go wrong. Each is checked against the variable-time
# multiplication of signature verification.
module SparseScalarCheck
  def self.list_of_scalars(bytesize : Int32, group_order : Bytes) : Array(Bytes)
    list_of_scalars = [] of Bytes
    [1, 2, 3, 15, 16, 17, 31, 32, 33, 1023, 1024, 1025].each do |small|
      scalar = Bytes.new(bytesize)
      scalar[bytesize - 1] = (small & 0xff).to_u8
      scalar[bytesize - 2] = (small >> 8).to_u8
      list_of_scalars << scalar
    end
    (0...bytesize * 8 - 1).step(7) do |bit|
      scalar = Bytes.new(bytesize)
      scalar[bytesize - 1 - bit // 8] = (1 << (bit % 8)).to_u8
      list_of_scalars << scalar
      both_ends = scalar.dup
      both_ends[bytesize - 1] |= 1_u8
      list_of_scalars << both_ends
    end
    order_minus_one = group_order.dup
    order_minus_one[bytesize - 1] &-= 1
    list_of_scalars << order_minus_one
    order_minus_two = group_order.dup
    order_minus_two[bytesize - 1] &-= 2
    list_of_scalars << order_minus_two
    list_of_scalars
  end
end

{% for curve in [{"P-256", "P256"}, {"P-384", "P384"}] %}
  describe "{{ curve[0].id }} constant-time multiplication by sparse scalars" do
    it "matches the variable-time multiplication of the generator" do
      zero = Bytes.new({{ curve[1].id }}::Arithmetic::BYTESIZE)
      SparseScalarCheck.list_of_scalars({{ curve[1].id }}::Arithmetic::BYTESIZE, {{ curve[1].id }}::Arithmetic::GROUP_ORDER).each do |scalar|
        expected = {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic.multiply_and_add_public(scalar, {{ curve[1].id }}::Arithmetic.generator, zero))
        {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic.multiply_generator(scalar)).should eq(expected)
      end
    end

    it "matches the variable-time multiplication of another point" do
      zero = Bytes.new({{ curve[1].id }}::Arithmetic::BYTESIZE)
      point_scalar = Random::Secure.random_bytes({{ curve[1].id }}::Arithmetic::BYTESIZE)
      point_scalar[0] = 0_u8
      point = {{ curve[1].id }}::Arithmetic.multiply_and_add_public(point_scalar, {{ curve[1].id }}::Arithmetic.generator, zero)
      multiples = {{ curve[1].id }}::Arithmetic.multiples_of(point)
      SparseScalarCheck.list_of_scalars({{ curve[1].id }}::Arithmetic::BYTESIZE, {{ curve[1].id }}::Arithmetic::GROUP_ORDER).each do |scalar|
        expected = {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic.multiply_and_add_public(zero, point, scalar))
        {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic.multiply_constant_time(scalar, multiples)).should eq(expected)
      end
    end

    it "gives infinity for the scalar 0" do
      zero = Bytes.new({{ curve[1].id }}::Arithmetic::BYTESIZE)
      multiples = {{ curve[1].id }}::Arithmetic.multiples_of({{ curve[1].id }}::Arithmetic.generator)
      {{ curve[1].id }}::Arithmetic.neutral_bit({{ curve[1].id }}::Arithmetic.multiply_generator(zero)).should eq(1_u64)
      {{ curve[1].id }}::Arithmetic.neutral_bit({{ curve[1].id }}::Arithmetic.multiply_constant_time(zero, multiples)).should eq(1_u64)
    end
  end
{% end %}

{% for curve in [{"P-256", "P256"}, {"P-384", "P384"}] %}
  describe "{{ curve[0].id }} stand-in of the generator multiplication" do
    it "is [17]G, and neither equal nor opposite to any table entry" do
      stand_in = {{ curve[1].id }}::Arithmetic.generator_stand_in
      seventeen = Bytes.new({{ curve[1].id }}::Arithmetic::BYTESIZE)
      seventeen[-1] = 17_u8
      expected = {{ curve[1].id }}::Arithmetic.multiply_and_add_public(seventeen, {{ curve[1].id }}::Arithmetic.generator, Bytes.new({{ curve[1].id }}::Arithmetic::BYTESIZE))
      {{ curve[1].id }}::Arithmetic.encode_uncompressed({{ curve[1].id }}::Arithmetic::Point.from_affine(stand_in)).should eq({{ curve[1].id }}::Arithmetic.encode_uncompressed(expected))
      {{ curve[1].id }}::Arithmetic.generator_window_tables.each do |table|
        table.each { |entry| (entry.x == stand_in.x).should be_false }
      end
    end
  end
{% end %}

{% for curve in [{"P-256", "P256"}, {"P-384", "P384"}] %}
  describe "{{ curve[0].id }} stand-in of the variable-point multiplication" do
    it "is [2^e]P, never ±[d]P for a digit d from 1 to 16, at every window" do
      group_order = {{ curve[1].id }}::Arithmetic::GROUP_ORDER.hexstring.to_big_i(16)
      last_exponent = 5 + 5 * ({{ curve[1].id }}::Arithmetic::GENERATOR_WINDOW_COUNT - 1)
      residue = BigInt.new(16)
      (5..last_exponent).each do
        residue = (residue * 2) % group_order
        (1..16).each do |digit|
          (residue == digit || residue == group_order - digit).should be_false
        end
      end
    end
  end
{% end %}
