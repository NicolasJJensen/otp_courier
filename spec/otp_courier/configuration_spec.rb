# frozen_string_literal: true

RSpec.describe OtpCourier::Configuration do
  describe "defaults" do
    it "has sensible defaults" do
      config = described_class.new

      expect(config.salt).to eq("otp_courier/v1")
      expect(config.default_length).to eq(6)
      expect(config.default_validity).to eq(600)
      expect(config.bcrypt_cost).to eq(12)
      expect(config.code_charset).to eq(:digits)
      expect(config.before_issue).to be_nil
      expect(config.active_kid).to eq("primary")
      expect(config.secrets).to eq({})
    end
  end

  describe "#secret= / #secret" do
    it "stores the value under the active kid" do
      config = described_class.new
      config.secret = "abc"

      expect(config.secrets).to eq("primary" => "abc")
      expect(config.secret).to eq("abc")
    end

    it "tracks the active kid when it changes" do
      config = described_class.new
      config.secrets = { "v1" => "first", "v2" => "second" }
      config.active_kid = "v2"

      expect(config.secret).to eq("second")
    end
  end

  describe "#secret!" do
    it "returns the active secret when set" do
      config = described_class.new
      config.secret = "abc"

      expect(config.secret!).to eq("abc")
    end

    it "raises a clear error when nothing is configured and Rails isn't present" do
      config = described_class.new

      expect { config.secret! }.to raise_error(OtpCourier::Error, /no secret/i)
    end
  end

  describe "#secret_for" do
    it "looks up a specific kid" do
      config = described_class.new
      config.secrets = { "v1" => "a", "v2" => "b" }

      expect(config.secret_for("v1")).to eq("a")
      expect(config.secret_for("v2")).to eq("b")
      expect(config.secret_for("v3")).to be_nil
    end
  end

  describe "#code_charset=" do
    it "accepts :digits and :alphanumeric" do
      config = described_class.new
      config.code_charset = :alphanumeric
      expect(config.code_charset).to eq(:alphanumeric)
    end

    it "rejects unknown charsets" do
      config = described_class.new
      expect { config.code_charset = :hex }.to raise_error(ArgumentError, /code_charset/)
    end
  end

  describe "#for / #defaults_for" do
    it "lets you set per-purpose defaults" do
      config = described_class.new
      config.for(:two_factor) do |p|
        p.default_length = 8
        p.default_validity = 30
        p.code_charset = :alphanumeric
      end

      defaults = config.defaults_for(:two_factor)
      expect(defaults.length).to eq(8)
      expect(defaults.validity).to eq(30)
      expect(defaults.charset).to eq(:alphanumeric)
    end

    it "falls back to globals for unset values" do
      config = described_class.new
      config.default_length = 5
      config.for(:two_factor) { |p| p.default_validity = 30 }

      defaults = config.defaults_for(:two_factor)
      expect(defaults.length).to eq(5)
      expect(defaults.validity).to eq(30)
      expect(defaults.charset).to eq(:digits)
    end

    it "returns a defaults object even for unconfigured purposes" do
      config = described_class.new
      defaults = config.defaults_for(:unknown)

      expect(defaults.length).to eq(config.default_length)
      expect(defaults.validity).to eq(config.default_validity)
      expect(defaults.charset).to eq(config.code_charset)
    end
  end
end

RSpec.describe OtpCourier do
  describe ".configure / .config" do
    it "yields a Configuration that persists" do
      described_class.configure { |c| c.default_length = 8 }

      expect(described_class.config.default_length).to eq(8)
    end
  end

  describe ".reset!" do
    it "drops all configured values back to defaults" do
      described_class.configure { |c| c.default_length = 8 }
      described_class.reset!

      expect(described_class.config.default_length).to eq(6)
    end
  end
end
