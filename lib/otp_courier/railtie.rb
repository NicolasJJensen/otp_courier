# frozen_string_literal: true

require "rails/railtie"

module OtpCourier
  # Wires Rails' `secret_key_base` into the gem so host apps don't have to
  # write a boilerplate initializer just to set the secret. Apps can still
  # override via `config.secret = ...` in an initializer — that takes
  # precedence because it runs after this hook.
  class Railtie < ::Rails::Railtie
    initializer "otp_courier.set_default_secret", before: :load_config_initializers do |app|
      if OtpCourier.config.secret.nil?
        secret = app.respond_to?(:secret_key_base) ? app.secret_key_base : nil
        OtpCourier.config.secret = secret if secret
      end
    end
  end
end
