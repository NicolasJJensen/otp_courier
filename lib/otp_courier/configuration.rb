# frozen_string_literal: true

module OtpCourier
  # Per-purpose override container. Reads fall through to the parent
  # Configuration when the override isn't set, so you only specify the
  # values you actually want different.
  class PurposeDefaults
    attr_accessor :default_length, :default_validity, :code_charset

    def initialize(parent)
      @parent = parent
      @default_length = nil
      @default_validity = nil
      @code_charset = nil
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

  # Holds all tunable settings for the gem.
  #
  # Single-secret apps can still use `config.secret = "..."` — it transparently
  # stores under the active kid. Multi-key apps configure `config.secrets =
  # { "v1" => "...", "v2" => "..." }` and pick which is active.
  class Configuration
    DEFAULT_SALT = "otp_courier/v1"
    DEFAULT_ACTIVE_KID = "primary"
    CHARSETS = %i[digits alphanumeric].freeze

    attr_accessor :salt, :default_length, :default_validity, :bcrypt_cost,
                  :code_charset, :before_issue
    attr_reader :secrets, :active_kid, :purpose_defaults

    def initialize
      @secrets = {}
      @active_kid = DEFAULT_ACTIVE_KID
      @salt = DEFAULT_SALT
      @default_length = 6
      @default_validity = 600 # 10 minutes
      @bcrypt_cost = 12
      @code_charset = :digits
      @before_issue = nil
      @purpose_defaults = {}
    end

    # Single-secret convenience: stores under the currently-active kid.
    def secret=(value)
      if value.nil?
        @secrets.delete(@active_kid)
      else
        @secrets[@active_kid] = value
      end
    end

    def secret
      @secrets[@active_kid]
    end

    def secrets=(map)
      raise ArgumentError, "secrets must be a Hash" unless map.is_a?(Hash)
      @secrets = map.transform_keys(&:to_s)
    end

    def active_kid=(kid)
      @active_kid = kid.to_s
    end

    # Look up the secret for a specific kid, falling back to Rails'
    # `secret_key_base` if the active kid is the default and nothing is set.
    def secret_for(kid)
      kid = kid.to_s
      @secrets[kid] || rails_fallback(kid)
    end

    def active_secret!
      secret_for(@active_kid) ||
        raise(OtpCourier::Error,
              "OtpCourier.config has no secret for active kid '#{@active_kid}'. " \
              "Configure it via OtpCourier.configure { |c| c.secret = ... }.")
    end

    # Backwards-compatible alias.
    alias_method :secret!, :active_secret!

    def code_charset=(value)
      value = value.to_sym
      unless CHARSETS.include?(value)
        raise ArgumentError, "code_charset must be one of #{CHARSETS.inspect}"
      end
      @code_charset = value
    end

    # Configure per-purpose defaults:
    #
    #   config.for(:two_factor) do |p|
    #     p.default_length = 6
    #     p.default_validity = 30
    #   end
    def for(purpose)
      defaults = (@purpose_defaults[purpose.to_s] ||= PurposeDefaults.new(self))
      yield defaults if block_given?
      defaults
    end

    # Always returns a PurposeDefaults (never nil), so issuance code can call
    # `.length` / `.validity` / `.charset` without checking.
    def defaults_for(purpose)
      @purpose_defaults[purpose.to_s] || PurposeDefaults.new(self)
    end

    private

    def rails_fallback(kid)
      return nil unless kid == DEFAULT_ACTIVE_KID
      return nil unless defined?(Rails) && Rails.respond_to?(:application) && Rails.application
      Rails.application.secret_key_base
    end
  end
end
