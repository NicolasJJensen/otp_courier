# frozen_string_literal: true

require "rails/railtie"

module OtpCourier
  class Railtie < ::Rails::Railtie
    initializer "otp_courier.set_default_secret", before: :load_config_initializers do |app|
      config = OtpCourier.config
      if config.active_kid == Configuration::DEFAULT_ACTIVE_KID && config.secret_for(config.active_kid)
        config.secret ||= app.secret_key_base
      end
    end
  end
end
