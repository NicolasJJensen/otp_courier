# frozen_string_literal: true

require_relative "lib/otp_courier/version"

Gem::Specification.new do |spec|
  spec.name = "otp_courier"
  spec.version = OtpCourier::VERSION
  spec.authors = ["Nicolas J Jensen"]
  spec.email = ["nicolasjensen9@gmail.com"]

  spec.summary = "Encrypted verification codes and links for Ruby."
  spec.description = "Issue and verify expiring codes and encrypted links. " \
                     "Applications control delivery, storage, single use, and revocation. " \
                     "Codes are BCrypt-hashed and tokens are encrypted with AES-256-GCM. " \
                     "Purpose namespacing and key rotation are built in."
  spec.homepage = "https://github.com/NicolasJJensen/otp_courier"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues"
  }

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*", "docs/**/*.md", "examples/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE.txt"]
      .select { |f| File.file?(f) }
  end

  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 7.0", "< 9.0"
  spec.add_dependency "bcrypt", "~> 3.1"
end
