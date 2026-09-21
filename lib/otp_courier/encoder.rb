# frozen_string_literal: true

require "active_support"
require "active_support/core_ext/integer/time"
require "active_support/core_ext/numeric/time"
require "active_support/message_encryptor"
require "active_support/key_generator"
require "json"

module OtpCourier
  # Wraps ActiveSupport::MessageEncryptor with a derived 32-byte AES-256-GCM
  # key and a JSON serializer.
  #
  # Tokens are wrapped in an envelope: `oc1.<kid>.<encrypted-blob>`. The
  # `oc1` prefix lets future format changes be detected and rejected. The
  # `kid` lets the gem decrypt with the right key in multi-key rotations
  # without trying every key blindly.
  module Encoder
    ENVELOPE_VERSION = "oc1"
    SEPARATOR = "."

    module_function

    def encrypt(payload, purpose:, expires_in: nil)
      kid = OtpCourier.config.active_kid
      blob = encryptor_for(kid).encrypt_and_sign(
        payload, purpose: purpose.to_s, expires_in: expires_in
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
               raise(OtpCourier::Error, "No secret configured for kid '#{kid}'")

      key = ActiveSupport::KeyGenerator.new(secret, iterations: 1000)
                                       .generate_key(config.salt, 32)
      ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm", serializer: JSON)
    end
  end
end
