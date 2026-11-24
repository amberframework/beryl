require "../../spec_helper"

describe Beryl::TLS::HandshakeSecrets do
  describe "#wipe" do
    it "wipes held secrets and, when the handshake failed, the handed-on ones" do
      secrets = Beryl::TLS::HandshakeSecrets.new
      held = secrets.held(Bytes.new(32, 1))
      handed_on = secrets.handed_on(Bytes.new(32, 2))
      secrets.wipe
      held.all?(&.zero?).should be_true
      handed_on.all?(&.zero?).should be_true
    end

    it "keeps the handed-on secrets of a finished handshake" do
      secrets = Beryl::TLS::HandshakeSecrets.new
      held = secrets.held(Bytes.new(32, 1))
      handed_on = secrets.handed_on(Bytes.new(32, 2))
      secrets.complete
      secrets.wipe
      held.all?(&.zero?).should be_true
      handed_on.should eq(Bytes.new(32, 2))
    end
  end
end
