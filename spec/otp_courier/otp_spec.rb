# frozen_string_literal: true

RSpec.describe OtpCourier::OTP do
  describe ".issue + .consume" do
    it "round-trips the payload when the code matches the purpose" do
      issued = described_class.issue(
        purpose: :email_signup,
        payload: { email: "alex@example.com" }
      )

      result = described_class.consume(issued.token, issued.code, purpose: :email_signup)

      expect(result).to eq("email" => "alex@example.com")
    end

    it "wraps the token in the oc1 envelope with the active kid" do
      issued = described_class.issue(purpose: :test)

      expect(issued.token).to start_with("oc1.primary.")
    end

    it "returns a numeric code of the configured length" do
      issued = described_class.issue(purpose: :test, length: 8)

      expect(issued.code).to match(/\A\d{8}\z/)
    end

    it "uses the default length when none is given" do
      OtpCourier.config.default_length = 4
      issued = described_class.issue(purpose: :test)

      expect(issued.code).to match(/\A\d{4}\z/)
    end

    it "rejects the wrong code" do
      issued = described_class.issue(purpose: :test, payload: { x: 1 })
      wrong = (issued.code.to_i + 1).to_s.rjust(issued.code.length, "0")

      expect(described_class.consume(issued.token, wrong, purpose: :test)).to be_nil
    end

    it "rejects the wrong purpose" do
      issued = described_class.issue(purpose: :signup, payload: { x: 1 })

      expect(described_class.consume(issued.token, issued.code, purpose: :reset)).to be_nil
    end

    it "rejects a tampered token" do
      issued = described_class.issue(purpose: :test, payload: { x: 1 })
      tampered = issued.token[0..-2] + (issued.token[-1] == "a" ? "b" : "a")

      expect(described_class.consume(tampered, issued.code, purpose: :test)).to be_nil
    end

    it "rejects an expired token" do
      issued = described_class.issue(purpose: :test, payload: { x: 1 }, validity: 1)
      sleep 1.1

      expect(described_class.consume(issued.token, issued.code, purpose: :test)).to be_nil
    end

    it "rejects an unknown envelope version" do
      issued = described_class.issue(purpose: :test, payload: { x: 1 })
      # swap "oc1" for "oc2"
      mutated = issued.token.sub(/\Aoc1\./, "oc99.")

      expect(described_class.consume(mutated, issued.code, purpose: :test)).to be_nil
    end

    it "rejects a token whose kid has been retired" do
      issued = described_class.issue(purpose: :test, payload: { x: 1 })
      OtpCourier.config.secrets.delete("primary")
      OtpCourier.config.secrets["v2"] = "different-secret"
      OtpCourier.config.active_kid = "v2"

      expect(described_class.consume(issued.token, issued.code, purpose: :test)).to be_nil
    end

    it "rejects blank input" do
      expect(described_class.consume(nil, "123456", purpose: :test)).to be_nil
      expect(described_class.consume("", "123456", purpose: :test)).to be_nil
      expect(described_class.consume("token", nil, purpose: :test)).to be_nil
      expect(described_class.consume("token", "", purpose: :test)).to be_nil
    end

    it "stringifies symbol keys in the payload" do
      issued = described_class.issue(purpose: :test, payload: { user_id: 7, role: :admin })

      result = described_class.consume(issued.token, issued.code, purpose: :test)

      expect(result).to eq("user_id" => 7, "role" => "admin")
    end

    it "returns an empty hash when no payload was given" do
      issued = described_class.issue(purpose: :test)

      expect(described_class.consume(issued.token, issued.code, purpose: :test)).to eq({})
    end
  end

  describe ".issue_link + .consume_link" do
    it "round-trips the payload" do
      token = described_class.issue_link(
        purpose: :invite,
        payload: { email: "alex@example.com", organisation_id: 42 }
      )

      result = described_class.consume_link(token, purpose: :invite)

      expect(result).to eq("email" => "alex@example.com", "organisation_id" => 42)
    end

    it "rejects the wrong purpose" do
      token = described_class.issue_link(purpose: :invite, payload: { x: 1 })

      expect(described_class.consume_link(token, purpose: :reset)).to be_nil
    end

    it "rejects an expired link" do
      token = described_class.issue_link(purpose: :invite, payload: { x: 1 }, validity: 1)
      sleep 1.1

      expect(described_class.consume_link(token, purpose: :invite)).to be_nil
    end

    it "rejects blank input" do
      expect(described_class.consume_link(nil, purpose: :invite)).to be_nil
      expect(described_class.consume_link("", purpose: :invite)).to be_nil
    end
  end

  describe "kind separation" do
    it "refuses to consume a link token via .consume" do
      token = described_class.issue_link(purpose: :flow, payload: { x: 1 })

      expect(described_class.consume(token, "000000", purpose: :flow)).to be_nil
    end

    it "refuses to consume an otp token via .consume_link" do
      issued = described_class.issue(purpose: :flow, payload: { x: 1 })

      expect(described_class.consume_link(issued.token, purpose: :flow)).to be_nil
    end
  end

  describe "per-purpose defaults" do
    it "uses purpose-specific length when configured" do
      OtpCourier.config.for(:short_code) { |p| p.default_length = 4 }

      issued = described_class.issue(purpose: :short_code)

      expect(issued.code).to match(/\A\d{4}\z/)
    end

    it "uses purpose-specific validity when configured" do
      OtpCourier.config.for(:fast_expire) { |p| p.default_validity = 1 }

      issued = described_class.issue(purpose: :fast_expire, payload: { x: 1 })
      sleep 1.1

      expect(described_class.consume(issued.token, issued.code, purpose: :fast_expire)).to be_nil
    end

    it "honours per-call overrides over purpose defaults" do
      OtpCourier.config.for(:short_code) { |p| p.default_length = 4 }

      issued = described_class.issue(purpose: :short_code, length: 6)

      expect(issued.code).to match(/\A\d{6}\z/)
    end

    it "applies purpose-specific validity to .issue_link too" do
      OtpCourier.config.for(:fast_invite) { |p| p.default_validity = 1 }

      token = described_class.issue_link(purpose: :fast_invite, payload: { x: 1 })
      sleep 1.1

      expect(described_class.consume_link(token, purpose: :fast_invite)).to be_nil
    end
  end

  describe "code charset" do
    it "supports alphanumeric codes per-call" do
      issued = described_class.issue(purpose: :test, length: 12, charset: :alphanumeric)

      expect(issued.code).to match(/\A[A-HJ-NP-Z2-9]{12}\z/)
      expect(issued.code).not_to match(/[IO01]/)
    end

    it "uses the global charset setting" do
      OtpCourier.config.code_charset = :alphanumeric
      issued = described_class.issue(purpose: :test, length: 10)

      expect(issued.code).to match(/\A[A-HJ-NP-Z2-9]{10}\z/)
    end

    it "uses the per-purpose charset when set" do
      OtpCourier.config.for(:strong) { |p| p.code_charset = :alphanumeric }

      issued = described_class.issue(purpose: :strong, length: 8)

      expect(issued.code).to match(/\A[A-HJ-NP-Z2-9]{8}\z/)
    end

    it "round-trips alphanumeric codes through consume" do
      issued = described_class.issue(
        purpose: :test, length: 8, charset: :alphanumeric, payload: { x: 1 }
      )

      expect(described_class.consume(issued.token, issued.code, purpose: :test))
        .to eq("x" => 1)
    end
  end

  describe "before_issue hook" do
    it "calls the hook with purpose and payload for .issue" do
      captured = nil
      OtpCourier.config.before_issue = ->(purpose, payload) { captured = [purpose, payload] }

      described_class.issue(purpose: :rate_limited, payload: { user_id: 42 })

      expect(captured).to eq([:rate_limited, { user_id: 42 }])
    end

    it "calls the hook for .issue_link too" do
      captured = nil
      OtpCourier.config.before_issue = ->(purpose, payload) { captured = [purpose, payload] }

      described_class.issue_link(purpose: :invite, payload: { email: "a@b.com" })

      expect(captured).to eq([:invite, { email: "a@b.com" }])
    end

    it "lets the hook abort by raising" do
      OtpCourier.config.before_issue = ->(_, _) { raise "rate limited" }

      expect { described_class.issue(purpose: :rate_limited, payload: {}) }
        .to raise_error("rate limited")
    end
  end
end
