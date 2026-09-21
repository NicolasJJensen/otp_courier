# OtpCourier

Stateless one-time-password and one-time-link issuance for Ruby.

Requires Ruby >= 3.1 and ActiveSupport 7.0 through 8.x. The suite runs green on
ActiveSupport 7.0, 7.1, 7.2, 8.0, and 8.1.

State lives entirely inside the encrypted token. No database tables, no
columns that get used once and discarded, no rows squatting on contact
records in an unverified limbo.

```ruby
issued = OtpCourier::OTP.issue(
  purpose: :email_signup,
  payload: { email: "alex@example.com" }
)

session[:signup_otp] = issued.token
EmailMailer.signup_code(issued.code, to: "alex@example.com").deliver_later

# ...user enters code...

payload = OtpCourier::OTP.consume(session[:signup_otp], params[:code], purpose: :email_signup)
Email.create!(address: payload["email"], verified_at: Time.current) if payload
```

That's the whole API for codes. There's a matching `issue_link` / `consume_link`
pair for link-based flows (password reset, invitations, magic links).

---

## Table of contents

- [Why stateless?](#why-stateless)
- [How it compares](#how-it-compares)
- [Install](#install)
- [Three complete flows](#three-complete-flows)
  - [1. Email signup with OTP](#1-email-signup-with-otp)
  - [2. Two-factor challenge](#2-two-factor-challenge)
  - [3. User invitation with link](#3-user-invitation-with-link)
- [Public API](#public-api)
- [Configuration](#configuration)
- [Per-purpose defaults](#per-purpose-defaults)
- [Key rotation](#key-rotation)
- [Rate limiting](#rate-limiting)
- [Code charset](#code-charset)
- [Threat model](#threat-model)
- [Token format](#token-format)
- [Testing](#testing)
- [Operational FAQ](#operational-faq)
- [License](#license)

---

## Why stateless?

Traditional OTP flows persist a hashed code, an expiry, a sent-at, a
failed-attempts counter, and a lock-until timestamp on the contact record.
That works, but it has three costs:

1. **Unverified records squat on identifiers.** Someone starts a signup with
   `alex@example.com`, never finishes — the row stays, and the real Alex
   either can't sign up or hits weird "this email is taken" errors.
2. **Schema churn.** Six columns per verifiable table, used for ~10 minutes
   per row in their entire lifetime.
3. **Invitations need a parallel mechanism.** They're conceptually identical
   (a deliverable token that proves "you control this contact"), but they
   don't fit the per-row model, so you build a second token table.

OtpCourier collapses all of this. The pending verification is the encrypted
token. The contact row only exists once verified. Invitations are the same
primitive with a longer validity and no code.

## How it compares

| Concern                  | DB-stored OTP                                | OtpCourier                          |
|--------------------------|----------------------------------------------|-------------------------------------|
| Storage of pending state | 6 columns on the contact row                 | Encrypted token in session/cookie   |
| Unverified squatting     | Yes — row exists                             | No — row only on success            |
| Invitations              | Separate mechanism (token table)             | Same primitive (`issue_link`)       |
| Code brute force defence | failed_attempts column + lockout column      | BCrypt cost + token expiry          |
| Cross-flow replay        | Type/scope column on the token table         | `purpose:` baked into the signature |
| Code rotation across keys| Schema migration                             | `Keys.rotate!`                      |
| Cross-device flows       | Trivial (server holds state)                 | Needs care — see [FAQ](#operational-faq) |

OtpCourier is the right tool when the pending state genuinely is transient.
If you need cross-device flows (issue on desktop, consume on mobile) or
want server-side visibility into outstanding verifications, a DB column
approach still fits better.

## Install

```ruby
gem "otp_courier"
```

On Rails, no configuration is strictly required — the Railtie pulls
`Rails.application.secret_key_base` automatically. To override defaults:

```ruby
# config/initializers/otp_courier.rb
OtpCourier.configure do |c|
  c.secret = Rails.application.secret_key_base # optional on Rails

  c.default_length = 6      # digits in the OTP code
  c.default_validity = 600  # seconds (10 minutes)
  c.bcrypt_cost = 12        # raise for production, lower for tests
  c.code_charset = :digits  # or :alphanumeric

  # Per-purpose overrides — see "Per-purpose defaults" below.
  c.for(:two_factor) do |p|
    p.default_validity = 30
  end
end
```

---

## Three complete flows

These are the patterns that motivate the gem. Each is end-to-end runnable.

### 1. Email signup with OTP

User enters their email; you deliver a code; they enter the code; you create
the Email record only at the end.

**Routes**:

```ruby
# config/routes.rb
resources :signup_codes, only: %i[new create] do
  collection { get :verify }
  collection { post :verify, to: "signup_codes#confirm" }
end
```

**Controller**:

```ruby
class SignupCodesController < ApplicationController
  def new; end

  # POST /signup_codes — user submitted their email.
  def create
    email = params.require(:email)

    issued = OtpCourier::OTP.issue(
      purpose: :email_signup,
      payload: { email: email }
    )

    session[:signup_otp] = issued.token
    SignupMailer.code(to: email, code: issued.code).deliver_later
    redirect_to verify_signup_codes_path
  end

  # GET /signup_codes/verify — form to enter the code.
  def verify; end

  # POST /signup_codes/verify — user submitted the code.
  def confirm
    payload = OtpCourier::OTP.consume(
      session[:signup_otp],
      params[:code],
      purpose: :email_signup
    )

    if payload.nil?
      flash.now[:alert] = "That code is invalid or expired."
      render :verify, status: :unprocessable_entity
      return
    end

    email = Email.create!(address: payload["email"], verified_at: Time.current)
    session.delete(:signup_otp)
    redirect_to new_account_path(email_id: email.id), notice: "Email confirmed."
  end
end
```

Notes:

- The `Email` row never exists until the code is consumed. If the user
  abandons the flow, nothing is left behind.
- `session.delete(:signup_otp)` enforces single-use within validity — even
  if the user double-submits, the second attempt finds no token.
- Resending a code just calls `issue` again and overwrites the session
  entry. The old token is invalidated implicitly (replaced).

### 2. Two-factor challenge

Account is already known (password is verified). Now deliver a code to
their TOTP / SMS / email and verify.

**Controller**:

```ruby
class TwoFactorChallengesController < ApplicationController
  before_action :require_password_verified!

  # GET /two_factor_challenges/new — challenge form.
  def new
    issued = OtpCourier::OTP.issue(
      purpose: :two_factor_challenge,
      payload: { account_id: pending_account.id },
      length: 6,
      validity: 5.minutes
    )

    session[:two_factor_otp] = issued.token
    SmsDelivery.send(to: pending_account.phone, code: issued.code)
  end

  # POST /two_factor_challenges — user submits the code.
  def create
    payload = OtpCourier::OTP.consume(
      session[:two_factor_otp],
      params[:code],
      purpose: :two_factor_challenge
    )

    if payload.nil? || payload["account_id"] != pending_account.id
      flash.now[:alert] = "Invalid code."
      render :new, status: :unprocessable_entity
      return
    end

    session.delete(:two_factor_otp)
    sign_in_fully!(pending_account)
    redirect_to root_path
  end
end
```

Notes:

- **The `account_id` is in the payload.** That binds the code to a
  specific user — even if an attacker steals someone else's code, it
  won't redeem against their own session.
- **Purpose is distinct from signup.** A signup code can't be replayed
  as a 2FA code.
- For per-purpose defaults, configure once and drop the per-call args:

  ```ruby
  OtpCourier.config.for(:two_factor_challenge) do |p|
    p.default_validity = 300  # 5 minutes
  end
  ```

### 3. User invitation with link

The inviter knows the invitee's email and what role they should have.
That information is signed into the link itself; no DB row required until
the invitee accepts.

**Inviter side**:

```ruby
class InvitationsController < ApplicationController
  def create
    token = OtpCourier::OTP.issue_link(
      purpose: :user_invitation,
      payload: {
        email: params[:email],
        organisation_id: current_account.organisation_id,
        role: params[:role]
      },
      validity: 7.days
    )

    InvitationMailer.invite(
      to: params[:email],
      url: accept_invitation_url(token: token)
    ).deliver_later

    redirect_to invitations_path, notice: "Invitation sent."
  end
end
```

**Invitee side**:

```ruby
class InvitationAcceptancesController < ApplicationController
  def show
    payload = OtpCourier::OTP.consume_link(
      params[:token],
      purpose: :user_invitation
    )

    if payload.nil?
      render :expired, status: :gone
      return
    end

    @email = payload["email"]
    @organisation_id = payload["organisation_id"]
    @role = payload["role"]
    # render the "set a password" form, pre-filled with @email
  end

  def create
    payload = OtpCourier::OTP.consume_link(
      params[:token],
      purpose: :user_invitation
    )
    return render :expired, status: :gone if payload.nil?

    ActiveRecord::Base.transaction do
      account = Account.create!(
        email_address: payload["email"],
        password: params[:password],
        organisation_id: payload["organisation_id"]
      )
      account.memberships.create!(role: payload["role"])
      # The email proved deliverable via the original send. Mark verified.
      account.emails.create!(address: payload["email"], verified_at: Time.current)

      sign_in(account)
    end

    redirect_to root_path, notice: "Welcome aboard."
  end
end
```

Notes:

- **No invitation table.** The invitation is the link. Server has no
  record of pending invitations — if you need that for an admin UI, build
  it alongside (`Invitation.create!(...)` with status), but the
  cryptographic state lives in the link.
- **The email is pre-verified.** Delivering the link to that address and
  having it clicked is itself proof of control. No second OTP step.
- **Re-issuing is idempotent.** "Resend invitation" = issue a new link.
  Old links remain valid until expiry.

---

## Public API

```ruby
OtpCourier::OTP.issue(purpose:, payload: {}, length: nil, validity: nil, charset: nil)
  # => OtpCourier::OTP::Issued.new(token: "oc1.primary.<blob>", code: "123456")

OtpCourier::OTP.issue_link(purpose:, payload: {}, validity: nil)
  # => "oc1.primary.<blob>"

OtpCourier::OTP.consume(token, code, purpose:)
  # => Hash payload (string keys) | nil

OtpCourier::OTP.consume_link(token, purpose:)
  # => Hash payload (string keys) | nil
```

### `purpose:` (required)

A symbol or string identifying the flow. Baked into the signature.
A token issued under `:email_signup` will not decrypt under
`:two_factor_challenge`, regardless of code correctness.

Use distinct purposes for distinct flows. Don't reuse `:auth` across
signup, 2FA, and password reset.

### `payload:` (optional)

Any JSON-serializable Hash. Stored encrypted inside the token. On
`consume`, returned with stringified keys.

Put whatever the consume side needs in here: account ID, email address,
role, organisation ID, "next URL". The payload is encrypted, but treat it
as readable by anyone holding the token — the encryption protects against
tampering, not against legitimate redemption.

### `length:`, `validity:`, `charset:` (optional)

Per-call overrides for code length, expiry seconds, and digit/alphanumeric.
Falls back to per-purpose defaults, then global config.

### Return value

`consume` and `consume_link` return either:

- **A Hash with string keys** — verification succeeded. Use this to act
  on whatever the payload contained.
- **`nil`** — verification failed for any reason. By design, there is no
  separate "expired" vs "wrong code" signal. Surfacing that detail would
  leak information to an attacker probing tokens.

---

## Configuration

| Option              | Default              | Description                                                |
|---------------------|----------------------|------------------------------------------------------------|
| `secret`            | (Rails fallback)     | Source secret. Shorthand for `secrets[active_kid] = ...`.  |
| `secrets`           | `{}`                 | `kid => secret` map for multi-key setups.                  |
| `active_kid`        | `"primary"`          | Which kid encrypts new tokens.                             |
| `salt`              | `"otp_courier/v1"`   | KeyGenerator salt.                                         |
| `default_length`    | `6`                  | Digits in `issue`-generated codes.                         |
| `default_validity`  | `600` (10 minutes)   | Seconds before tokens expire.                              |
| `bcrypt_cost`       | `12`                 | BCrypt work factor. Lower in tests (e.g. `4`).             |
| `code_charset`      | `:digits`            | `:digits` or `:alphanumeric`.                              |
| `before_issue`      | `nil`                | `->(purpose, payload) { ... }` callback for rate limiting. |

Per-purpose overrides (via `config.for(purpose) { |p| ... }`):
`default_length`, `default_validity`, `code_charset`.

## Per-purpose defaults

Different flows want different defaults. A 2FA challenge expires in 30
seconds; an invitation link is good for a week. Set them once:

```ruby
OtpCourier.configure do |c|
  c.for(:two_factor) do |p|
    p.default_length = 6
    p.default_validity = 30
  end

  c.for(:invite_link) do |p|
    p.default_validity = 7.days.to_i
  end

  c.for(:hardware_token) do |p|
    p.default_length = 8
    p.code_charset = :alphanumeric
  end
end

# Now:
OtpCourier::OTP.issue(purpose: :two_factor, payload: { account_id: 7 })
# uses length: 6, validity: 30s, digits.
```

Per-call arguments (`length:`, `validity:`, `charset:`) still win over
purpose defaults.

## Key rotation

Rotate the encryption secret without invalidating in-flight tokens.

```ruby
# 1. Deploy with both keys present. New tokens use "2026-q2"; old tokens
#    still decrypt because "2026-q1" stays in the keyring.
OtpCourier::Keys.rotate!("2026-q2", ENV.fetch("OTP_COURIER_SECRET_Q2"))

# 2. After the longest token validity has elapsed, retire the old key.
OtpCourier::Keys.retire!("2026-q1")
```

Declarative form (e.g. in an initializer):

```ruby
OtpCourier.configure do |c|
  c.secrets = {
    "2026-q1" => ENV.fetch("OTP_COURIER_SECRET_Q1"),
    "2026-q2" => ENV.fetch("OTP_COURIER_SECRET_Q2")
  }
  c.active_kid = "2026-q2"
end
```

**Rotation cadence**: at minimum, rotate when a secret leaks. Routine
quarterly rotation is good hygiene. The retire-after window must exceed
your longest `validity:` value (otherwise valid in-flight tokens break).

**`Keys` introspection**:

```ruby
OtpCourier::Keys.active_kid   # => "2026-q2"
OtpCourier::Keys.kids         # => ["2026-q1", "2026-q2"]
```

## Rate limiting

OtpCourier doesn't rate-limit on its own — the responsibility for "how
often can this user request a code?" belongs to your throttler. Plug it in
once:

```ruby
OtpCourier.config.before_issue = ->(purpose, payload) {
  RateLimiter.check!(
    bucket: "otp_courier:#{purpose}:#{payload[:account_id] || payload[:email]}",
    limit: 5,
    period: 1.hour
  )
}
```

The hook fires before every `issue` and `issue_link`. Raise from inside it
to abort issuance — the caller sees the same exception bubble up.

For Rails 8 apps, `ActionController::RateLimiting` at the controller layer
is usually a better fit than this hook (it returns a proper HTTP 429 with
no side effects). Use `before_issue` when you need rate limiting across
multiple call sites or out-of-controller issuance (background jobs).

## Code charset

The default is digits. Reasonable for delivery via SMS or email (easy to
read aloud, no case ambiguity, predictable width). Switch to alphanumeric
when you want shorter codes with the same entropy:

```ruby
OtpCourier.config.code_charset = :alphanumeric                          # global
OtpCourier.config.for(:hardware_token) { |p| p.code_charset = :alphanumeric }  # per-purpose
OtpCourier::OTP.issue(purpose: :x, length: 8, charset: :alphanumeric)   # per-call
```

The alphanumeric set is Crockford-style: A–Z and 0–9 minus I, O, 0, 1.
That's 32 characters, ~5 bits per character. A 6-character alphanumeric
code has ~30 bits of entropy vs ~20 bits for 6 digits.

| Length | Digit entropy | Alphanumeric entropy |
|--------|---------------|----------------------|
| 4      | ~13 bits      | ~20 bits             |
| 6      | ~20 bits      | ~30 bits             |
| 8      | ~27 bits      | ~40 bits             |

For 2FA challenges, 6 digits is the industry default and is fine. For
device pairing codes that need to be short and high-entropy, alphanumeric
is the better choice.

## Threat model

OtpCourier protects against:

| Attack                          | Defence                                                |
|---------------------------------|--------------------------------------------------------|
| Tampering with token            | AES-256-GCM authenticated encryption                   |
| Replay across flows             | `purpose:` baked into signature                        |
| Replay across token shapes      | `"kind"` marker (OTP vs link) checked at consume       |
| Brute force on code             | BCrypt-hashed code, cost configurable (default 12)     |
| Expired tokens reused           | `expires_in` enforced at decrypt time                  |
| Format drift across gem versions| Envelope version (`oc1`) + payload version (`"v": 1`)  |
| Compromised key                 | Multi-key support — rotate without breaking in-flight  |

OtpCourier explicitly does **not**:

- **Rate-limit issuance.** Wire `before_issue` to your throttler, or
  enforce at the controller layer.
- **Prevent reuse within validity.** A valid token + code can be redeemed
  multiple times unless you delete the session entry on first success.
  See the [signup flow above](#1-email-signup-with-otp) for the pattern.
- **Persist anything.** Lost the token? Issue a new one.
- **Defend against XSS reading the session.** If your session storage is
  compromised, the attacker has the token. This is the same trust model
  as any session-backed flow.

## Token format

```
oc1.<kid>.<encrypted-blob>
```

- `oc1` — envelope version. Format changes bump this. Tokens from
  pre-`oc1` (none, this is v1) or post-`oc1` versions are rejected.
- `<kid>` — key id. Identifies which entry in `config.secrets` to use.
- `<encrypted-blob>` — `MessageEncryptor` output: AES-256-GCM, JSON
  serializer. Plaintext payload:

```json
{
  "v": 1,
  "kind": "otp",
  "payload": { "email": "alex@example.com" },
  "digest": "$2a$12$...",
  "nonce": "a3f7..."
}
```

- `v` — payload format version, distinct from envelope version. Lets
  future inner-shape changes be detected.
- `kind` — `"otp"` or `"link"`. Prevents link tokens being redeemed as
  OTPs and vice versa.
- `payload` — your data, JSON-encoded. Keys come out stringified.
- `digest` — BCrypt hash of the issued code (only for OTPs).
- `nonce` — random per-token; defeats any attempt to identify
  identical-payload tokens by ciphertext comparison.

Typical token length is ~250–400 bytes depending on payload size. Comfortably
fits in a session cookie.

## Testing

Drop the BCrypt cost so spec runs aren't slow:

```ruby
# spec/spec_helper.rb (or rails_helper.rb)
RSpec.configure do |config|
  config.before do
    OtpCourier.reset!
    OtpCourier.configure do |c|
      c.secret = "test-secret-at-least-32-characters-long"
      c.bcrypt_cost = 4  # ~50x faster than the default
    end
  end
end
```

`reset!` wipes all config — useful when individual specs poke at
per-purpose defaults or before_issue hooks and you don't want bleed-through.

For request specs that need to skip past a code-entry step, prefer issuing
a real token (it's cheap at cost 4) over stubbing the gem:

```ruby
issued = OtpCourier::OTP.issue(purpose: :email_signup, payload: { email: "a@b.com" })
post verify_signup_codes_path, params: { code: issued.code },
     env: { "rack.session" => { signup_otp: issued.token } }
```

## Operational FAQ

**The session cookie is too big now.**
JSON-serialized payloads under ~1KB fit comfortably in the default Rails
cookie store (4KB limit). If you're packing serialized objects, switch to
ActiveRecord session store or pass the token via a URL parameter for
single-page flows.

**A user wants to retry on a different device (e.g. requested on desktop,
wants to enter on mobile).**
Cross-device flows are awkward with stateless tokens because the token
lives in the issuing device's session. Either:

1. Email the token alongside the code (the token is the URL parameter,
   the code is what the user types). Now the user can click the link on
   any device and enter the code there.
2. Use `issue_link` instead — no code, just a clickable URL.
3. If you genuinely need device-agnostic flows, store a short pointer in
   Redis keyed off something like `account_id` and resolve on consume.
   That's a DB-storage flow, and OtpCourier is the wrong tool for it.

**What if the user requests two codes in a row?**
The second `issue` call overwrites the session entry with a fresh token
and code. The first token is "still valid" in the sense that it would
decrypt if presented — but the user no longer has it (you overwrote the
session). If the first delivery is delayed and arrives after the second,
the user enters the first code, it matches the bcrypt digest of the
second token's code... no, it won't. Each token has its own digest.
The user has to enter the code matching whichever token is in session.

**How do I let codes expire faster than the session?**
Set `validity:` shorter than the session's max age. Token expiry is
enforced at decrypt time independent of session lifetime — even if the
session is alive, a 30-second code expires in 30 seconds.

**Can I store the token in a cookie directly instead of session?**
Yes. The token is already encrypted; you don't gain anything from Rails'
cookie signing on top. But you do need to set `httponly: true` so XSS
can't read it.

**Why BCrypt for the code and not SHA?**
BCrypt is slow on purpose. Even with a token in hand, an attacker can't
grind through 6-digit codes — each guess costs ~250ms at cost 12. SHA
would let them try millions of codes per second.

**Why not use Rails' `signed_cookies` / `MessageVerifier`?**
Same primitive, plus three things on top: BCrypt-hashed code, purpose
namespacing (you can do this with MessageVerifier too, but it's not
mandatory), and kind separation. The point is the convention, not the
crypto.

**How do I revoke an issued token before it expires?**
You can't, by design — the gem doesn't track issued tokens. Workarounds:

- Delete the session entry. If the token only lived in that session,
  it's effectively dead.
- Rotate the key (`Keys.rotate!` + immediate `Keys.retire!` of the old).
  This invalidates every in-flight token, not just one.
- For finer-grained revocation, embed a session ID in the payload and
  check against a server-side revocation set on consume. At that point
  you've reintroduced state and should reconsider the design.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/NicolasJJensen/otp_courier.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
