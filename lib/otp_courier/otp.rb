# frozen_string_literal: true

require "bcrypt"
require "securerandom"

module OtpCourier
  module OTP
    Issued = Struct.new(:token, :code, keyword_init: true)
    PAYLOAD_VERSION = 2
    KIND_OTP = "otp"
    KIND_LINK = "link"
    ALPHANUMERIC_CHARS = (("A".."Z").to_a + ("0".."9").to_a - %w[I O 0 1]).freeze
    DIGIT_CHARS = ("0".."9").to_a.freeze
    CHARSETS = { digits: DIGIT_CHARS, alphanumeric: ALPHANUMERIC_CHARS }.freeze
    module_function

    def issue(purpose:, payload: {}, length: nil, validity: nil, charset: nil)
      original_purpose = purpose
      original_payload = payload
      purpose = Validation.purpose!(purpose)
      payload = Validation.payload!(payload)
      config = OtpCourier.config
      defaults = config.defaults_for(purpose)
      length = Validation.length!(length.nil? ? defaults.length : length)
      validity = Validation.validity!(validity.nil? ? defaults.validity : validity)
      charset = Validation.charset!(charset.nil? ? defaults.charset : charset)
      expires_at = expiry_for(validity)
      invoke_before_issue(original_purpose, original_payload)
      code = generate_code(length, charset)
      digest = BCrypt::Password.create(code, cost: config.bcrypt_cost).to_s
      token = Encoder.encrypt(
        {
          "v" => PAYLOAD_VERSION,
          "kind" => KIND_OTP,
          "payload" => payload,
          "digest" => digest,
          "nonce" => SecureRandom.hex(16),
          "expires_at" => expires_at
        },
        purpose: purpose
      )
      Issued.new(token: token, code: code)
    end

    def issue_link(purpose:, payload: {}, validity: nil)
      original_purpose = purpose
      original_payload = payload
      purpose = Validation.purpose!(purpose)
      payload = Validation.payload!(payload)
      defaults = OtpCourier.config.defaults_for(purpose)
      validity = Validation.validity!(validity.nil? ? defaults.validity : validity)
      expires_at = expiry_for(validity)
      invoke_before_issue(original_purpose, original_payload)
      Encoder.encrypt(
        {
          "v" => PAYLOAD_VERSION,
          "kind" => KIND_LINK,
          "payload" => payload,
          "nonce" => SecureRandom.hex(16),
          "expires_at" => expires_at
        },
        purpose: purpose
      )
    end

    def consume(token, code, purpose:)
      consume!(token, code, purpose: purpose)
    rescue OtpCourier::VerificationError
      nil
    end

    def consume!(token, code, purpose:)
      purpose = Validation.purpose!(purpose)
      raise InvalidToken, "Token is invalid" if blank?(token)
      data = decrypt_and_check(token, purpose: purpose, kind: KIND_OTP)
      raise ExpiredToken, "Token has expired" if expired?(data)
      digest = data["digest"]
      raise InvalidToken, "Token is invalid" unless digest.is_a?(String) && !digest.empty?
      validate_code!(code)
      begin
        raise InvalidCode, "Code is invalid" unless BCrypt::Password.new(digest) == code
      rescue BCrypt::Errors::InvalidHash
        raise InvalidToken, "Token is invalid"
      end
      data["payload"]
    end

    def consume_link(token, purpose:)
      consume_link!(token, purpose: purpose)
    rescue OtpCourier::VerificationError
      nil
    end

    def consume_link!(token, purpose:)
      purpose = Validation.purpose!(purpose)
      raise InvalidToken, "Token is invalid" if blank?(token)
      data = decrypt_and_check(token, purpose: purpose, kind: KIND_LINK)
      raise ExpiredToken, "Token has expired" if expired?(data)
      data["payload"]
    end

    def decrypt_and_check(token, purpose:, kind:)
      data = Encoder.decrypt(token, purpose: purpose)
      raise InvalidToken, "Token is invalid" unless data.is_a?(Hash)
      raise InvalidToken, "Token is invalid" unless data["kind"] == kind && data["v"] == PAYLOAD_VERSION
      raise InvalidToken, "Token is invalid" unless data["payload"].is_a?(Hash)
      expires_at = data["expires_at"]
      raise InvalidToken, "Token is invalid" unless expires_at.is_a?(Numeric) && expires_at.finite?
      data
    end

    def generate_code(length, charset)
      chars = CHARSETS.fetch(charset)
      Array.new(length) { chars[SecureRandom.random_number(chars.length)] }.join
    end

    def expiry_for(validity)
      now = Time.now.to_f
      expires_at = now + validity
      unless expires_at.finite? && expires_at > now
        raise ArgumentError, "validity must produce a finite future expiry"
      end
      expires_at
    end

    def expired?(data)
      Time.now.to_f >= data["expires_at"]
    end

    def blank?(value)
      value.nil? || (value.respond_to?(:empty?) && value.empty?)
    end

    def validate_code!(code)
      unless code.is_a?(String) && code.bytesize <= Validation::MAX_LENGTH &&
             code.ascii_only? && code.match?(/\A[0-9A-Z]+\z/)
        raise InvalidCode, "Code is invalid"
      end
    end

    def invoke_before_issue(purpose, payload)
      hook = OtpCourier.config.before_issue
      hook.call(purpose, payload) if hook
    end

    private_class_method :decrypt_and_check, :generate_code, :expired?, :blank?,
                         :validate_code!, :invoke_before_issue, :expiry_for
  end
end
