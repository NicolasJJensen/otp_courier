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

RSpec.describe "Rails key retirement" do
  before do
    application = double("Rails application", secret_key_base: "rails-secret" * 8)
    stub_const("Rails", double("Rails", application: application))
    OtpCourier.reset!
    OtpCourier.config.bcrypt_cost = 4
  end

  it "rejects a token after retiring its implicit Rails key" do
    issued = OtpCourier::OTP.issue(purpose: :test)
    OtpCourier::Keys.rotate!("replacement", "replacement-secret")
    OtpCourier::Keys.retire!("primary")

    expect(OtpCourier.config.secret_for("primary")).to be_nil
    expect { OtpCourier::OTP.consume!(issued.token, issued.code, purpose: :test) }
      .to raise_error(OtpCourier::InvalidToken)
  end

  it "keeps the Rails key retired when it was the only key" do
    OtpCourier::Keys.retire!("primary")

    expect(OtpCourier.config.secret_for("primary")).to be_nil
    expect { OtpCourier::OTP.issue(purpose: :test) }.to raise_error(OtpCourier::ConfigurationError)
  end

  it "disables implicit fallback when an explicit keyring replaces the Rails key" do
    issued = OtpCourier::OTP.issue(purpose: :test)
    OtpCourier.config.secrets = { "replacement" => "replacement-secret" }
    OtpCourier.config.active_kid = "replacement"

    expect(OtpCourier.config.secret_for("primary")).to be_nil
    expect(OtpCourier::OTP.consume(issued.token, issued.code, purpose: :test)).to be_nil
  end

  it "allows an explicit secret to restore a retired key" do
    OtpCourier::Keys.retire!("primary")
    OtpCourier.config.secret = "replacement-secret"

    issued = OtpCourier::OTP.issue(purpose: :test)
    expect(OtpCourier::OTP.consume!(issued.token, issued.code, purpose: :test)).to eq({})
  end

  it "does not change the active key when rotation settings are invalid" do
    expect { OtpCourier::Keys.rotate!("invalid.key", "secret") }.to raise_error(ArgumentError)
    expect { OtpCourier::Keys.rotate!("next", "") }.to raise_error(ArgumentError)
    expect(OtpCourier::Keys.active_kid).to eq("primary")
    expect(OtpCourier::Keys.kids).to be_empty
  end
end
