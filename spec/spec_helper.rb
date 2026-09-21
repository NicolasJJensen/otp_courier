# frozen_string_literal: true

require "otp_courier"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand(config.seed)

  config.before do
    OtpCourier.reset!
    OtpCourier.configure do |c|
      c.secret = "x" * 32
      c.bcrypt_cost = 4
    end
  end
end
