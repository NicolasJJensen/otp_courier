# frozen_string_literal: true

module OtpCourier
  module Keys
    module_function

    def rotate!(new_kid, new_secret)
      config = OtpCourier.config
      config.add_secret(new_kid, new_secret)
      config.active_kid = new_kid
    end

    def retire!(kid)
      OtpCourier.config.retire_secret(kid)
    end

    def active_kid
      OtpCourier.config.active_kid
    end

    def kids
      OtpCourier.config.secrets.keys
    end
  end
end
