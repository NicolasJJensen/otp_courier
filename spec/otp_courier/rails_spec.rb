# frozen_string_literal: true

require "open3"
require "tmpdir"
require "fileutils"

RSpec.describe "Rails integration" do
  def boot_app(initializer: "", setup: "")
    Dir.mktmpdir("otp-courier-rails") do |root|
      FileUtils.mkdir_p(File.join(root, "config/initializers"))
      File.write(File.join(root, "config/initializers/otp.rb"), initializer)
      script = <<~RUBY_SCRIPT
        require "logger"
        require "rails"
        require "rails/application"
        require "otp_courier"
        #{setup}
        class TestApplication < Rails::Application
          config.root = #{root.inspect}
          config.eager_load = false
          config.secret_key_base = "rails-secret" * 8
          config.logger = Logger.new(File::NULL)
        end
        TestApplication.initialize!
        OtpCourier.config.bcrypt_cost = 4
        result = {
          secret: OtpCourier.config.secret_for(OtpCourier.config.active_kid),
          primary: OtpCourier.config.secret_for("primary")
        }
        if result[:secret]
          issued = OtpCourier::OTP.issue(purpose: :boot)
          result[:payload] = OtpCourier::OTP.consume!(issued.token, issued.code, purpose: :boot)
        end
        puts JSON.generate(result)
      RUBY_SCRIPT
      out, err, status = Open3.capture3(
        { "RAILS_ENV" => "test" }, RbConfig.ruby, "-rbundler/setup", "-Ilib", "-e", script
      )
      expect(status.success?).to be(true), "Rails boot failed:\n#{out}\n#{err}"
      JSON.parse(out.lines.last)
    end
  end

  it "uses the Rails secret after a real application boot" do
    expect(boot_app).to include("secret" => "rails-secret" * 8, "payload" => {})
  end

  it "lets an application initializer override the Rails secret" do
    result = boot_app(initializer: 'OtpCourier.config.secret = "application-secret"')
    expect(result).to include("secret" => "application-secret", "payload" => {})
  end

  it "preserves a configured active key during boot" do
    result = boot_app(setup: 'OtpCourier::Keys.rotate!("custom", "custom-secret")')
    expect(result).to include("secret" => "custom-secret", "payload" => {})
  end

  it "does not restore an explicitly retired Rails key during boot" do
    result = boot_app(setup: 'OtpCourier::Keys.retire!("primary")')
    expect(result).to include("secret" => nil, "primary" => nil)
  end
end
