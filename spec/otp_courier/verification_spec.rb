# frozen_string_literal: true

RSpec.describe "OTP verification contracts" do
  let(:otp) { OtpCourier::OTP }
  let(:issued) { otp.issue(purpose: :signup, payload: { id: 1 }) }
  let(:link) { otp.issue_link(purpose: :signup, payload: { id: 1 }) }

  def signed_content(changes)
    data = OtpCourier::Encoder.decrypt(issued.token, purpose: :signup).merge(changes)
    OtpCourier::Encoder.encrypt(data, purpose: :signup)
  end

  it "returns the same payload from both APIs" do
    expect(otp.consume!(issued.token, issued.code, purpose: :signup)).to eq("id" => 1)
    expect(otp.consume(issued.token, issued.code, purpose: :signup)).to eq("id" => 1)
    expect(otp.consume_link!(link, purpose: :signup)).to eq("id" => 1)
    expect(otp.consume_link(link, purpose: :signup)).to eq("id" => 1)
  end

  [nil, "", " ", "wrong", "oc1", "oc1..blob", "oc1.unknown.blob", {}, 123, "\xff".b].each do |token|
    it "rejects malformed token #{token.inspect} through both APIs" do
      expect { otp.consume!(token, "123456", purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
      expect(otp.consume(token, "123456", purpose: :signup)).to be_nil
      expect { otp.consume_link!(token, purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
      expect(otp.consume_link(token, purpose: :signup)).to be_nil
    end
  end

  [nil, "", " ", "not-a-code", 123456, {}, "x" * 73, "\0", "\xff".b].each do |code|
    it "reports InvalidCode for #{code.inspect} without discarding the token" do
      expect { otp.consume!(issued.token, code, purpose: :signup) }.to raise_error(OtpCourier::InvalidCode)
      expect(otp.consume(issued.token, code, purpose: :signup)).to be_nil
      expect(otp.consume!(issued.token, issued.code, purpose: :signup)).to eq("id" => 1)
    end
  end

  it "rejects a code containing a null byte without exposing BCrypt exceptions" do
    expect { otp.consume!(issued.token, issued.code + "\0extra", purpose: :signup) }
      .to raise_error(OtpCourier::InvalidCode)
  end

  it "reports expiry at the exact boundary, including when the submitted code is blank" do
    freeze_time
    issued = otp.issue(purpose: :signup, validity: 60)
    link = otp.issue_link(purpose: :signup, validity: 60)
    travel 59
    expect(otp.consume!(issued.token, issued.code, purpose: :signup)).to eq({})
    expect(otp.consume_link!(link, purpose: :signup)).to eq({})
    travel 1
    expect { otp.consume!(issued.token, "", purpose: :signup) }.to raise_error(OtpCourier::ExpiredToken)
    expect { otp.consume_link!(link, purpose: :signup) }.to raise_error(OtpCourier::ExpiredToken)
    expect(otp.consume(issued.token, issued.code, purpose: :signup)).to be_nil
    expect(otp.consume_link(link, purpose: :signup)).to be_nil
  end

  it "rejects wrong-purpose and wrong-kind tokens before reporting expiry" do
    freeze_time
    issued = otp.issue(purpose: :signup, validity: 1)
    link = otp.issue_link(purpose: :signup, validity: 1)
    travel 2
    expect { otp.consume!(issued.token, issued.code, purpose: :reset) }.to raise_error(OtpCourier::InvalidToken)
    expect { otp.consume!(link, issued.code, purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
    expect { otp.consume_link!(issued.token, purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
  end

  [
    { "v" => 1 }, { "v" => nil }, { "kind" => nil }, { "payload" => nil },
    { "payload" => [] }, { "expires_at" => nil }, { "expires_at" => "tomorrow" },
    { "digest" => nil }, { "digest" => "broken hash" }
  ].each do |changes|
    it "rejects authenticated but invalid token contents #{changes.inspect}" do
      token = signed_content(changes)
      expect { otp.consume!(token, issued.code, purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
      expect(otp.consume(token, issued.code, purpose: :signup)).to be_nil
    end
  end

  it "rejects authenticated content that is not an object" do
    token = OtpCourier::Encoder.encrypt([], purpose: :signup)
    expect { otp.consume_link!(token, purpose: :signup) }.to raise_error(OtpCourier::InvalidToken)
  end

  it "does not swallow configuration or operational errors" do
    issued_token = issued.token
    allow(OtpCourier::Encoder).to receive(:decrypt).and_raise(OtpCourier::ConfigurationError, "Invalid configuration")
    expect { otp.consume(issued_token, "123456", purpose: :signup) }.to raise_error(OtpCourier::ConfigurationError)
    expect { otp.consume_link(issued_token, purpose: :signup) }.to raise_error(OtpCourier::ConfigurationError)
    allow(OtpCourier::Encoder).to receive(:decrypt).and_raise(IOError, "Unavailable")
    expect { otp.consume(issued_token, "123456", purpose: :signup) }.to raise_error(IOError)
  end

  it "keeps stateless tokens reusable until expiry, including after another issuance" do
    allow(SecureRandom).to receive(:random_number).with(10).and_return(1)
    first = otp.issue(purpose: :signup)
    allow(SecureRandom).to receive(:random_number).with(10).and_return(2)
    second = otp.issue(purpose: :signup)
    2.times do
      expect(otp.consume!(first.token, first.code, purpose: :signup)).to eq({})
      expect(otp.consume_link!(link, purpose: :signup)).to eq("id" => 1)
    end
    expect(otp.consume(first.token, second.code, purpose: :signup)).to be_nil
    expect(otp.consume(second.token, first.code, purpose: :signup)).to be_nil
    expect(otp.consume!(second.token, second.code, purpose: :signup)).to eq({})
  end

  it "preserves leading zeros and supports the full BCrypt code length" do
    allow(SecureRandom).to receive(:random_number).with(10).and_return(0)
    issued = otp.issue(purpose: :signup, length: 72)
    expect(issued.code).to eq("0" * 72)
    expect(otp.consume!(issued.token, issued.code, purpose: :signup)).to eq({})
  end

  it "normalizes nested JSON data without changing the caller's payload" do
    payload = { user: { role: :admin }, flags: [true, nil, 1.5] }
    issued = otp.issue(purpose: :signup, payload: payload)
    expect(otp.consume!(issued.token, issued.code, purpose: :signup))
      .to eq("user" => { "role" => "admin" }, "flags" => [true, nil, 1.5])
    expect(payload[:user][:role]).to eq(:admin)
  end

  [
    { payload: nil }, { payload: [] }, { payload: { value: "\xff" } },
    { payload: { "\xff" => "value" } }, { payload: { value: Object.new } },
    { payload: { value: Float::INFINITY } }, { payload: { 1 => "value" } },
    { payload: { id: 1, "id" => 2 } }, { purpose: " " }, { purpose: nil },
    { length: 0 }, { length: 73 }, { validity: "60" }, { validity: Complex(1, 1) },
    { validity: Float::INFINITY }, { validity: 1e-300 }, { charset: :hex }
  ].each do |options|
    it "validates #{options.inspect} before calling the issuance hook" do
      hook = double("issuance hook")
      expect(hook).not_to receive(:call)
      OtpCourier.config.before_issue = hook
      expect { otp.issue(**{ purpose: :signup }.merge(options)) }.to raise_error(ArgumentError)
    end
  end

  it "accepts duration validity and string charset values" do
    issued = otp.issue(purpose: :signup, validity: 1.minute, charset: "alphanumeric")
    expect(issued.code).to match(/\A[A-HJ-NP-Z2-9]{6}\z/)
    expect(otp.consume!(issued.token, issued.code, purpose: :signup)).to eq({})
  end

  it "rejects cyclic and excessive payload nesting without a stack overflow" do
    cycle = {}
    cycle["self"] = cycle
    expect { otp.issue(purpose: :signup, payload: cycle) }.to raise_error(ArgumentError)
    nested = 100.times.reduce({}) { |value, _| { child: value } }
    expect { otp.issue_link(purpose: :signup, payload: nested) }.to raise_error(ArgumentError)
  end
end
