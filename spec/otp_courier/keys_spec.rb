# frozen_string_literal: true

RSpec.describe OtpCourier::Keys do
  describe ".rotate!" do
    it "adds a new key and switches the active kid" do
      OtpCourier.config.secret = "old"

      described_class.rotate!("v2", "new")

      expect(OtpCourier.config.active_kid).to eq("v2")
      expect(OtpCourier.config.secrets).to include("primary" => "old", "v2" => "new")
    end

    it "leaves old tokens decryptable until the old key is retired" do
      OtpCourier.config.secret = "old"
      issued = OtpCourier::OTP.issue(purpose: :test, payload: { x: 1 })

      described_class.rotate!("v2", "completely-different-secret")

      result = OtpCourier::OTP.consume(issued.token, issued.code, purpose: :test)
      expect(result).to eq("x" => 1)
    end

    it "encrypts new tokens with the new kid" do
      described_class.rotate!("v2", "new-secret-value")

      issued = OtpCourier::OTP.issue(purpose: :test)

      expect(issued.token).to start_with("oc1.v2.")
    end
  end

  describe ".retire!" do
    it "removes a key" do
      OtpCourier.config.secret = "old"
      described_class.rotate!("v2", "new")
      described_class.retire!("primary")

      expect(OtpCourier.config.secrets).not_to include("primary")
    end

    it "makes tokens encrypted under the retired key unconsumable" do
      OtpCourier.config.secret = "old"
      issued = OtpCourier::OTP.issue(purpose: :test, payload: { x: 1 })

      described_class.rotate!("v2", "completely-different-secret")
      described_class.retire!("primary")

      expect(OtpCourier::OTP.consume(issued.token, issued.code, purpose: :test)).to be_nil
    end
  end

  describe ".kids / .active_kid" do
    it "introspects the configured keys" do
      OtpCourier.config.secrets = { "v1" => "a", "v2" => "b" }
      OtpCourier.config.active_kid = "v2"

      expect(described_class.kids).to contain_exactly("v1", "v2")
      expect(described_class.active_kid).to eq("v2")
    end
  end
end
