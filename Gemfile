# frozen_string_literal: true

source "https://rubygems.org"

gemspec

gem "rake", "~> 13.0"
gem "rspec", "~> 3.13"

# activesupport 8.1.3 still calls JSON.parse with a second positional argument,
# which json 3.0 removed. Pin json until Rails ships the fix.
gem "json", "< 3"
