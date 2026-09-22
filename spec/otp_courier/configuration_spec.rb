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

  describe "#active_secret!" do
    it "returns the active secret when set" do
      config = described_class.new
      config.secret = "abc"

      expect(config.active_secret!).to eq("abc")
    end

    it "raises a clear error when nothing is configured and Rails isn't present" do
      config = described_class.new

      expect { config.active_secret! }.to raise_error(OtpCourier::Error, /no secret/i)
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
      expect { config.code_charset = :hex }.to raise_error(ArgumentError, /charset/)
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

RSpec.describe "Configuration validation" do
  {
    default_length: [0, -1, 73, 2.5, "6", false],
    default_validity: [0, -1, Float::INFINITY, Float::NAN, "600", false],
    code_charset: [:hex, "", 7, false]
  }.each do |option, values|
    values.each do |value|
      it "rejects #{option}=#{value.inspect} globally and per purpose" do
        expect { OtpCourier.config.public_send("#{option}=", value) }.to raise_error(ArgumentError)
        expect { OtpCourier.config.for(:signup).public_send("#{option}=", value) }.to raise_error(ArgumentError)
      end
    end
  end

  it "normalizes charset strings at both configuration levels" do
    OtpCourier.config.code_charset = "alphanumeric"
    OtpCourier.config.for(:signup).code_charset = "digits"
    expect(OtpCourier.config.code_charset).to eq(:alphanumeric)
    expect(OtpCourier.config.defaults_for(:signup).charset).to eq(:digits)
  end

  it "restores inherited purpose defaults when an override is cleared" do
    defaults = OtpCourier.config.for(:signup)
    defaults.default_length = 8
    defaults.default_length = nil
    expect(defaults.length).to eq(6)
  end

  it "rejects blank purposes" do
    expect { OtpCourier.config.for(" ") }.to raise_error(ArgumentError)
  end

  it "rejects invalid secrets without partially replacing the keyring" do
    original = OtpCourier.config.secrets
    expect { OtpCourier.config.secrets = { "valid" => "secret", "invalid.key" => "secret" } }
      .to raise_error(ArgumentError)
    expect { OtpCourier.config.secrets = { "valid" => "" } }.to raise_error(ArgumentError)
    expect(OtpCourier.config.secrets).to eq(original)
  end

  it "prevents keyring mutation outside configuration methods" do
    expect { OtpCourier.config.secrets.delete("primary") }.to raise_error(FrozenError)
    expect { OtpCourier.config.secret.replace("modified") }.to raise_error(FrozenError)
  end

  it "validates crypto settings and the issuance hook" do
    expect { OtpCourier.config.bcrypt_cost = 3 }.to raise_error(ArgumentError)
    expect { OtpCourier.config.bcrypt_cost = 32 }.to raise_error(ArgumentError)
    expect { OtpCourier.config.salt = "" }.to raise_error(ArgumentError)
    expect { OtpCourier.config.before_issue = :callback }.to raise_error(ArgumentError)
  end
end
