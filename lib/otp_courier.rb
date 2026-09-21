# frozen_string_literal: true

module OtpCourier
  class Error < StandardError; end

  class << self
    def configure
      yield config
    end

    def config
      @config ||= Configuration.new
    end

    def reset!
      @config = Configuration.new
    end
  end
end

require "otp_courier/version"
require "otp_courier/configuration"
require "otp_courier/encoder"
require "otp_courier/otp"
require "otp_courier/keys"
begin
  require "rails/railtie"
rescue LoadError
  # Rails is optional. Without it the gem needs no boot integration.
else
  require "otp_courier/railtie"
end
