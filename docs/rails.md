# Rails integration

These examples leave application-specific delivery and account changes to the
host. Issue credentials through POST actions. A GET action can show a form or
validate a link for display, but must not complete a challenge.

## Session tokens

Use one collection block when both verification actions share a route:

```ruby
resources :signup_codes, only: %i[new create] do
  collection do
    get :verify
    post :verify, action: :confirm
  end
end
```

```ruby
class SignupCodesController < ApplicationController
  def create
    # Validate the address and enforce issuance limits.
    issued = OtpCourier::OTP.issue(
      purpose: :email_signup,
      payload: { email: params.require(:email) }
    )
    session[:signup_otp] = issued.token
    # Deliver issued.code to the address in the payload.
    redirect_to verify_signup_codes_path
  end

  def confirm
    # Enforce verification limits before checking the code.
    payload = OtpCourier::OTP.consume!(
      session[:signup_otp], params[:code], purpose: :email_signup
    )
    # Persist the verified address with an idempotent application operation.
    session.delete(:signup_otp)
    redirect_to new_account_path
  rescue OtpCourier::InvalidCode
    # Count the failure. Clear the token if the retry limit is reached.
    render :verify, status: :unprocessable_entity
  rescue OtpCourier::ExpiredToken, OtpCourier::InvalidToken
    session.delete(:signup_otp)
    redirect_to new_signup_code_path, alert: "Request a new verification code."
  end
end
```

This manages session cleanup. It does not guarantee single use under concurrent
requests or old-cookie replay. See [lifecycle details](lifecycle.md).

## Database challenges

The tested [ActiveRecord example](../examples/active_record_challenge.rb) is an
application service you can adapt. It is not loaded by the gem. It requires a
database with row locks, such as PostgreSQL.

A challenge record needs these fields:

| Field | Type and constraint |
| --- | --- |
| `purpose` | Non-null string |
| `token` | Nullable text |
| `attempts` | Non-null integer, default `0` |
| `consumed_at` | Nullable datetime |
| Application scope | Account and pending authentication session, with a unique database constraint |

Create the scoped row when starting the flow. Resolve it through that same
scope on every request. Do not accept a challenge ID without authorization.

```ruby
challenge = pending_account.otp_challenges.find_by!(
  authentication_session_id: pending_session.id,
  purpose: "two_factor"
)
flow = OtpChallengeFlow.new(challenge, max_attempts: 5)

issued = flow.issue!(
  payload: { account_id: pending_account.id },
  validity: 5.minutes
)
# Deliver issued.code after issue! returns and its transaction commits.
```

Call `issue!` again on the same scoped row to resend. It replaces the token
under a lock and preserves the failure count. Completed or exhausted challenges
cannot be reopened. Starting a new flow remains subject to account-level limits.

On the verification POST:

```ruby
flow.complete!(params[:code]) do |payload|
  # Complete the scoped account operation using database writes here.
end
# Establish the authenticated session or enqueue work after commit.
```

The service performs verification, application writes, and completion under the
same row lock. A failed application write rolls back completion. Only one
concurrent request can complete the challenge.

Incorrect codes increment the failure count. Expired or invalid tokens are
cleared. The service raises saved verification errors after the transaction
commits, so cleanup and counters persist. Rescue those errors in the controller.

Invoke the service outside an existing transaction. The example enforces this
boundary to prevent an outer rollback from undoing recorded failures. Keep
external effects outside the yielded block. Use an outbox when delivery must
survive a crash after commit.

Resend and verification use the same lock. If completion wins the race, resend
fails. If resend wins, verification checks the replacement token. An old token
cannot bypass this policy because the application always uses the stored token.

Throttle both issuance and verification by account, session, and destination.
The row's failure count supplements those limits. It is not a request throttle.

## Invitation links

A link is a bearer credential. Authorize the invitation's organisation and role
before issuance. The following example assumes that authorization is complete.

For resend revocation, store a generation on the invitation row:

```ruby
invitation.with_lock do
  # Reject accepted or revoked invitations.
  invitation.increment!(:generation)
  token = OtpCourier::OTP.issue_link(
    purpose: :invitation,
    payload: { invitation_id: invitation.id, generation: invitation.generation },
    validity: 7.days
  )
  # Arrange delivery after commit, or write an outbox entry here.
end
```

Accept the invitation through a POST action:

```ruby
payload = OtpCourier::OTP.consume_link!(params[:token], purpose: :invitation)
invitation = Invitation.find(payload.fetch("invitation_id"))

invitation.with_lock do
  raise InvalidInvitation unless invitation.pending?
  raise InvalidInvitation unless invitation.generation == payload.fetch("generation")

  OtpCourier::OTP.consume_link!(params[:token], purpose: :invitation)
  # Recheck current authorizations.
  # Create membership and mark the invitation accepted in this transaction.
end
```

Define `InvalidInvitation` in the application. Resolve privileges from the
invitation record. A valid encrypted payload does not authorize an arbitrary role.
GET requests, mail scanners, and link previews must not mark invitations accepted.

## Authenticator applications

OtpCourier generates random codes for delivery. It does not implement TOTP
shared-secret enrollment, time-step verification, or recovery codes. Use a
TOTP library for authenticator apps. Email address verification should not be
presented as equivalent to authenticator-app MFA.

## Key rotation

Use distinct key IDs containing letters, digits, underscores, or hyphens.
Configure keys consistently across all processes:

```ruby
OtpCourier.configure do |config|
  config.secrets = {
    "previous" => ENV.fetch("OTP_COURIER_PREVIOUS_SECRET"),
    "current" => ENV.fetch("OTP_COURIER_CURRENT_SECRET")
  }
  config.active_kid = "current"
end
```

First deploy both keys with the old key active everywhere. Then switch the
active key everywhere. Keep the old key for the longest token lifetime after
the last process stops issuing with it. Finally remove it from every process.

`OtpCourier::Keys.rotate!(id, secret)` adds a key and makes it active.
`OtpCourier::Keys.retire!(id)` removes a key and disables its Rails fallback.
These calls affect only the current process. Persist the desired configuration
for deployments and restarts. Retiring a compromised key immediately invalidates
all tokens under that key.

An explicit `config.secrets` map disables the implicit Rails fallback.
Key maps are read-only. Use `config.secrets = {...}`, `config.secret = value`,
or the key management methods to change them.
