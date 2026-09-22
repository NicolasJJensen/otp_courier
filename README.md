# OtpCourier

Generate and verify expiring codes and encrypted links in Ruby. Your application
controls delivery and storage. No database is required by the gem.

Verification does not invalidate a token. Applications can add state for single
use, resend replacement, and revocation.

## Installation

Add the gem to your Gemfile:

```ruby
gem "otp_courier"
```

Rails uses `Rails.application.secret_key_base` automatically. Other Ruby
applications must configure a secret:

```ruby
require "otp_courier"

OtpCourier.configure do |config|
  config.secret = ENV.fetch("OTP_COURIER_SECRET")
end
```

Use a securely generated secret, such as `SecureRandom.hex(32)`, stored in your
secret manager. Ruby 3.1 or newer and ActiveSupport 7 or 8 are required.

## Verification codes

Issue a code in response to a POST request. Keep the token and deliver the code
through your application's mailer or messaging provider:

```ruby
issued = OtpCourier::OTP.issue(
  purpose: :email_signup,
  payload: { email: "alex@example.com" }
)

session[:signup_otp] = issued.token
# Deliver issued.code to the email address.
```

When the user submits the code:

```ruby
begin
  payload = OtpCourier::OTP.consume!(
    session[:signup_otp], params[:code], purpose: :email_signup
  )

  # Persist the verified email with an idempotent application operation.
  session.delete(:signup_otp)
rescue OtpCourier::InvalidCode
  # Keep the token and allow a retry within your verification limit.
rescue OtpCourier::ExpiredToken, OtpCourier::InvalidToken
  session.delete(:signup_otp)
  # Ask the user to restart verification.
end
```

Session cleanup does not prevent concurrent submissions or replay of an old
cookie. Use a [database challenge](docs/rails.md#database-challenges) when you
need atomic single use or resend replacement. Throttle both issuance and verification.

## Links

```ruby
token = OtpCourier::OTP.issue_link(
  purpose: :invitation,
  payload: { invitation_id: 42 },
  validity: 7.days
)
# Deliver a URL containing token, using your URL helper to encode it.

payload = OtpCourier::OTP.consume_link!(token, purpose: :invitation)
# Authorize and complete the invitation in a POST action.
```

Anyone holding the link can present it. For single use or revocation, check and
update the invitation record in the same transaction as acceptance.

## API

| Method | Successful result | Verification failure |
| --- | --- | --- |
| `OTP.issue(purpose:, payload: {}, length: nil, validity: nil, charset: nil)` | Object with `token` and `code` | Raises on invalid arguments or configuration |
| `OTP.issue_link(purpose:, payload: {}, validity: nil)` | Token string | Raises on invalid arguments or configuration |
| `OTP.consume(token, code, purpose:)` | Payload Hash | `nil` |
| `OTP.consume!(token, code, purpose:)` | Payload Hash | Raises a verification error |
| `OTP.consume_link(token, purpose:)` | Payload Hash | `nil` |
| `OTP.consume_link!(token, purpose:)` | Payload Hash | Raises a verification error |

All methods belong to `OtpCourier::OTP`. Use a distinct `purpose` for each flow.
Payloads contain JSON-compatible values. Symbol keys and values become strings.
Supply codes as strings to preserve leading zeros.

`InvalidToken`, `ExpiredToken`, and `InvalidCode` inherit from
`OtpCourier::VerificationError`. Non-bang methods only rescue verification
errors. Caller mistakes raise `ArgumentError`. Missing issuance secrets raise
`OtpCourier::ConfigurationError`. See [failure handling](docs/lifecycle.md).

## Configuration

The defaults are six digits, ten minutes, and BCrypt cost 12. Set global or
per-purpose defaults in an initializer:

```ruby
OtpCourier.configure do |config|
  config.default_length = 6
  config.default_validity = 600
  config.code_charset = :digits # or :alphanumeric
  config.bcrypt_cost = 12

  config.for(:device_pairing) do |purpose|
    purpose.default_length = 8
    purpose.code_charset = :alphanumeric
  end
end
```

Per-call options override purpose defaults, which override global defaults.
Lengths must be integers from 1 to 72. Validity must be positive, finite seconds
or an ActiveSupport duration. Alphanumeric codes use uppercase letters and
digits, excluding `I`, `O`, `0`, and `1`.

`config.before_issue` accepts a callable receiving `(purpose, payload)`. Raise
from it to stop issuance. This hook does not limit verification requests.

See [key rotation](docs/rails.md#key-rotation) for multiple keys and deployment guidance.

## Scope

OtpCourier uses authenticated encryption, expiry checks, purpose separation,
and BCrypt code comparison. Your application supplies authorization, delivery,
rate limits, storage, and any single-use or revocation policy.

Authenticator-app TOTP is not supported. Those codes require a shared secret
and time-based verification through a TOTP library. OtpCourier generates random
codes for delivery, such as email verification or an SMS challenge.

## Development

```sh
bundle install
bundle exec rake
```

The suite includes Rails boot tests. To include PostgreSQL lifecycle tests,
set `OTP_COURIER_DATABASE_URL` to a dedicated PostgreSQL test database. CI runs these tests
across Rails 7.0 through 8.1. Set BCrypt cost to `4` in host-application tests.
Run `bundle exec ruby script/check_package.rb` to check the built gem without Rails.

## Contributing

Bug reports and pull requests are welcome on
[GitHub](https://github.com/NicolasJJensen/otp_courier).

## License

The gem is available under the [MIT License](LICENSE.txt).
