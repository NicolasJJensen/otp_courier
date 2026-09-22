# frozen_string_literal: true

module OtpCourier
  module DefaultOptions
    attr_reader :default_length, :default_validity, :code_charset

    def default_length=(value)
      @default_length = value.nil? && is_a?(PurposeDefaults) ? nil : Validation.length!(value)
    end

    def default_validity=(value)
      @default_validity = value.nil? && is_a?(PurposeDefaults) ? nil : Validation.validity!(value)
    end

    def code_charset=(value)
      @code_charset = value.nil? && is_a?(PurposeDefaults) ? nil : Validation.charset!(value)
    end
  end

  class PurposeDefaults
    include DefaultOptions

    def initialize(parent)
      @parent = parent
    end

    def length
      @default_length || @parent.default_length
    end

    def validity
      @default_validity || @parent.default_validity
    end

    def charset
      @code_charset || @parent.code_charset
    end
  end

  class Configuration
    include DefaultOptions

    DEFAULT_SALT = "otp_courier/v1"
    DEFAULT_ACTIVE_KID = "primary"

    attr_reader :salt, :bcrypt_cost, :before_issue, :secrets, :active_kid

    def initialize
      @secrets = {}.freeze
      @retired_kids = []
      @rails_fallback_enabled = true
      @active_kid = DEFAULT_ACTIVE_KID
      @salt = DEFAULT_SALT
      @default_length = 6
      @default_validity = 600
      @bcrypt_cost = 12
      @code_charset = :digits
      @before_issue = nil
      @purpose_defaults = {}
    end

    def secret=(value)
      value.nil? ? retire_secret(@active_kid) : add_secret(@active_kid, value)
    end

    def secret
      @secrets[@active_kid]
    end

    def secrets=(map)
      raise ArgumentError, "secrets must be a Hash" unless map.is_a?(Hash)

      normalized = map.each_with_object({}) do |(kid, secret), result|
        kid = validate_kid!(kid)
        raise ArgumentError, "secrets contains duplicate key IDs" if result.key?(kid)
        result[kid] = validate_secret!(secret)
      end
      @secrets = normalized.freeze
      @rails_fallback_enabled = false
      @retired_kids -= normalized.keys
    end

    def active_kid=(kid)
      @active_kid = validate_kid!(kid)
    end

    def add_secret(kid, secret)
      kid = validate_kid!(kid)
      secret = validate_secret!(secret)
      @secrets = @secrets.merge(kid => secret).freeze
      @retired_kids.delete(kid)
    end

    def retire_secret(kid)
      kid = validate_kid!(kid)
      @secrets = @secrets.reject { |key, _| key == kid }.freeze
      @retired_kids |= [kid]
    end

    def secret_for(kid)
      kid = kid.to_s
      return nil if @retired_kids.include?(kid)

      @secrets[kid] || rails_fallback(kid)
    end

    def active_secret!
      secret_for(@active_kid) ||
        raise(ConfigurationError, "No secret configured for active key '#{@active_kid}'")
    end

    def salt=(value)
      raise ArgumentError, "salt must be a nonempty String" unless value.is_a?(String) && !value.strip.empty?

      @salt = value.dup.freeze
    end

    def bcrypt_cost=(value)
      unless value.is_a?(Integer) && (4..31).cover?(value)
        raise ArgumentError, "bcrypt_cost must be an Integer between 4 and 31"
      end

      @bcrypt_cost = value
    end

    def before_issue=(value)
      unless value.nil? || value.respond_to?(:call)
        raise ArgumentError, "before_issue must respond to call"
      end

      @before_issue = value
    end

    def for(purpose)
      purpose = Validation.purpose!(purpose)
      defaults = (@purpose_defaults[purpose] ||= PurposeDefaults.new(self))
      yield defaults if block_given?
      defaults
    end

    def defaults_for(purpose)
      @purpose_defaults[Validation.purpose!(purpose)] || PurposeDefaults.new(self)
    end

    private

    def validate_kid!(kid)
      unless (kid.is_a?(String) || kid.is_a?(Symbol)) && kid.to_s.match?(/\A[a-zA-Z0-9_-]+\z/)
        raise ArgumentError, "key ID must contain only letters, digits, underscores, or hyphens"
      end

      kid.to_s.dup.freeze
    end

    def validate_secret!(secret)
      unless secret.is_a?(String) && !secret.strip.empty?
        raise ArgumentError, "secret must be a nonempty String"
      end

      secret.dup.freeze
    end

    def rails_fallback(kid)
      return nil unless @rails_fallback_enabled && kid == DEFAULT_ACTIVE_KID
      return nil unless defined?(Rails) && Rails.respond_to?(:application) && Rails.application

      secret = Rails.application.secret_key_base
      return nil if secret.nil?

      validate_secret!(secret)
    end
  end
end
