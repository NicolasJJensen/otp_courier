# frozen_string_literal: true

require "bcrypt"
require "securerandom"

module OtpCourier
  # Stateless one-time-password and one-time-link service.
  #
  # The "state" of a pending verification lives entirely inside the encrypted
  # token returned by `issue` / `issue_link`. Nothing is stored server-side, so
  # there's no DB churn and no squatting on unverified contacts.
  #
  # Tokens are namespaced by `purpose:` to prevent cross-flow replay (e.g. a
  # 2FA challenge token can't be redeemed against a signup confirmation), and
  # tagged with `kind` ("otp" vs "link") so a link token can never satisfy an
  # OTP consume call even with the right purpose.
  module OTP
    Issued = Struct.new(:token, :code, keyword_init: true)

    PAYLOAD_VERSION = 1

    KIND_OTP = "otp"
    KIND_LINK = "link"

    # Crockford-style alphanumeric, minus visually ambiguous characters
    # (I/1, O/0). 32 chars total → ~5 bits per character.
    ALPHANUMERIC_CHARS = (("A".."Z").to_a + ("0".."9").to_a - %w[I O 0 1]).freeze
    DIGIT_CHARS = ("0".."9").to_a.freeze

    CHARSETS = {
      digits: DIGIT_CHARS,
      alphanumeric: ALPHANUMERIC_CHARS
    }.freeze

    module_function

    # Issue a one-time code. Returns an Issued struct with `token` (give to the
    # client / store in session) and `code` (deliver out-of-band: email, SMS).
    def issue(purpose:, payload: {}, length: nil, validity: nil, charset: nil)
      config = OtpCourier.config
      defaults = config.defaults_for(purpose)
      length ||= defaults.length
      validity ||= defaults.validity
      charset ||= defaults.charset

      invoke_before_issue(purpose, payload)

      code = generate_code(length, charset)
      digest = BCrypt::Password.create(code, cost: config.bcrypt_cost).to_s

      token = Encoder.encrypt(
        {
          "v" => PAYLOAD_VERSION,
          "kind" => KIND_OTP,
          "payload" => stringify(payload),
          "digest" => digest,
          "nonce" => SecureRandom.hex(16)
        },
        purpose: purpose,
        expires_in: validity
      )

      Issued.new(token: token, code: code)
    end

    # Issue a one-time link token (no code; the secret is the URL itself).
    def issue_link(purpose:, payload: {}, validity: nil)
      validity ||= OtpCourier.config.defaults_for(purpose).validity

      invoke_before_issue(purpose, payload)

      Encoder.encrypt(
        {
          "v" => PAYLOAD_VERSION,
          "kind" => KIND_LINK,
          "payload" => stringify(payload),
          "nonce" => SecureRandom.hex(16)
        },
        purpose: purpose,
        expires_in: validity
      )
    end

    # Verify a token + code pair. Returns the stored payload (Hash, string
    # keys) on success, or nil on any failure (expired, wrong purpose,
    # tampered, wrong code, wrong kind, wrong payload version, blank input).
    def consume(token, code, purpose:)
      return nil if blank?(token) || blank?(code)

      data = decrypt_and_check(token, purpose: purpose, kind: KIND_OTP)
      return nil unless data

      digest = data["digest"]
      return nil unless digest.is_a?(String) && !digest.empty?

      begin
        return nil unless BCrypt::Password.new(digest) == code.to_s
      rescue BCrypt::Errors::InvalidHash
        return nil
      end

      data["payload"] || {}
    end

    # Verify a link token. Returns the stored payload on success, nil
    # otherwise.
    def consume_link(token, purpose:)
      return nil if blank?(token)

      data = decrypt_and_check(token, purpose: purpose, kind: KIND_LINK)
      return nil unless data

      data["payload"] || {}
    end

    # --- internal --------------------------------------------------------

    def decrypt_and_check(token, purpose:, kind:)
      data = Encoder.decrypt(token, purpose: purpose)
      return nil unless data.is_a?(Hash)
      return nil unless data["kind"] == kind
      return nil unless data["v"] == PAYLOAD_VERSION
      data
    end

    def generate_code(length, charset)
      chars = CHARSETS[charset] || DIGIT_CHARS
      Array.new(length) { chars[SecureRandom.random_number(chars.length)] }.join
    end

    def stringify(hash)
      return {} if hash.nil?
      hash.each_with_object({}) { |(k, v), out| out[k.to_s] = v }
    end

    def blank?(value)
      value.nil? || (value.respond_to?(:empty?) && value.empty?)
    end

    def invoke_before_issue(purpose, payload)
      hook = OtpCourier.config.before_issue
      return unless hook
      hook.call(purpose, payload)
    end
  end
end
