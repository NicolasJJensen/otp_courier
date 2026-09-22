# frozen_string_literal: true

require "bundler"
require "tmpdir"
require "open3"
require "rubygems/package"
require "rubygems/installer"

root = File.expand_path("..", __dir__)
spec = Gem::Specification.load(File.join(root, "otp_courier.gemspec"))
active_support_version = Gem.loaded_specs.fetch("activesupport").version

Dir.mktmpdir("otp-courier-package") do |directory|
  package = File.join(directory, "otp_courier.gem")
  Dir.chdir(root) { Gem::Package.build(spec, false, false, package) }
  gem_home = File.join(directory, "gems")
  Gem::Installer.at(package, install_dir: gem_home, ignore_dependencies: true, document: []).install
  gemfile = File.join(directory, "Gemfile")
  File.write(gemfile, <<~GEMFILE)
    source "https://rubygems.org"
    gem "otp_courier", "=#{spec.version}"
    gem "activesupport", "=#{active_support_version}"
    gem "json", "< 3"
  GEMFILE

  smoke = <<~'SMOKE'
    require "otp_courier"
    installed = Gem.loaded_specs.fetch("otp_courier").full_gem_path
    abort "Loaded checkout instead of package" unless installed.start_with?(ENV.fetch("GEM_HOME"))
    abort "Rails must not be a runtime dependency" if defined?(Rails)
    OtpCourier.configure { |config| config.secret = "s" * 64; config.bcrypt_cost = 4 }
    issued = OtpCourier::OTP.issue(purpose: :package, payload: { id: 7 })
    abort "OTP verification failed" unless OtpCourier::OTP.consume!(issued.token, issued.code, purpose: :package) == { "id" => 7 }
    token = OtpCourier::OTP.issue_link(purpose: :package)
    abort "Link verification failed" unless OtpCourier::OTP.consume_link!(token, purpose: :package) == {}
    abort "Wrong code was accepted" unless OtpCourier::OTP.consume(issued.token, "incorrect", purpose: :package).nil?
    abort "Documentation was not packaged" unless File.file?(File.join(installed, "docs/rails.md"))
    abort "Example was not packaged" unless File.file?(File.join(installed, "examples/active_record_challenge.rb"))
    puts "Packaged gem passes standalone verification"
  SMOKE

  Bundler.with_unbundled_env do
    environment = {
      "GEM_HOME" => gem_home,
      "GEM_PATH" => ([gem_home] + Gem.path).join(File::PATH_SEPARATOR),
      "BUNDLE_GEMFILE" => gemfile
    }
    [
      ["bundle", "lock", "--local"],
      ["bundle", "exec", RbConfig.ruby, "-e", smoke]
    ].each do |command|
      output, status = Open3.capture2e(environment, *command, chdir: directory)
      abort output unless status.success?
      puts output
    end
  end
end
