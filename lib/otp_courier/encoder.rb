# frozen_string_literal: true

require "logger"
require "active_support"
require "active_support/core_ext/integer/time"
require "active_support/core_ext/numeric/time"
require "active_support/message_encryptor"
require "active_support/key_generator"
require "json"

module OtpCourier
  module Encoder
    ENVELOPE_VERSION = "oc1"
    SEPARATOR = "."

    module_function

    def encrypt(payload, purpose:)
      kid = OtpCourier.config.active_kid
      blob = encryptor_for(kid).encrypt_and_sign(
        payload, purpose: purpose.to_s
      )
      [ENVELOPE_VERSION, kid, blob].join(SEPARATOR)
    end

    def decrypt(envelope, purpose:)
      return nil unless envelope.is_a?(String)

      version, kid, blob = envelope.split(SEPARATOR, 3)
      return nil unless version == ENVELOPE_VERSION
      return nil if kid.nil? || kid.empty? || blob.nil? || blob.empty?
      return nil unless OtpCourier.config.secret_for(kid)

      encryptor_for(kid).decrypt_and_verify(blob, purpose: purpose.to_s)
    rescue ActiveSupport::MessageEncryptor::InvalidMessage,
           ActiveSupport::MessageVerifier::InvalidSignature
      nil
    end

    def encryptor_for(kid)
      config = OtpCourier.config
      secret = config.secret_for(kid) ||
               raise(OtpCourier::ConfigurationError, "No secret configured for kid '#{kid}'")

      key = ActiveSupport::KeyGenerator.new(secret, iterations: 1000)
                                       .generate_key(config.salt, 32)
      ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm", serializer: JSON)
    end

    private_class_method :encryptor_for
  end
end
