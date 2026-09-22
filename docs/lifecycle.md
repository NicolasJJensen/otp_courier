# Lifecycle and failure handling

OtpCourier verifies credentials. It does not record redemption or modify your
session. A matching token and code remain valid until expiry, even after another
token is issued.

## Failure handling

The bang methods raise these subclasses of `OtpCourier::VerificationError`:

| Error | Meaning | Typical application action |
| --- | --- | --- |
| `OtpCourier::InvalidCode` | Code is missing, malformed, or incorrect | Count the failure and permit a bounded retry |
| `OtpCourier::ExpiredToken` | An authenticated token reached its expiry | Remove the pending token and request a new one |
| `OtpCourier::InvalidToken` | Token is missing, malformed, tampered, retired, wrong-purpose, wrong-kind, or unsupported | Remove the pending token and restart the flow |

Token authentication and expiry checks precede code validation. Submitting a
blank code with an expired token therefore raises `ExpiredToken`.

The non-bang methods return `nil` for these errors. Argument, configuration,
and operational errors propagate through both APIs. Do not convert a database
failure into an incorrect-code response.

The application can use typed exceptions internally while showing a generic
public message. Throttle verification requests before performing expensive
code checks. BCrypt does not replace an attempt limit.

## Session lifecycle

- On success, persist the application result, then remove the session token.
- On an incorrect code, retain the token until the retry limit is reached.
- On expiry, invalidity, cancellation, or changed account binding, remove the token.
- On a database failure, retain a retry path and use idempotent application writes.

An expired token can remain stored until the next request. It cannot pass the
gem's expiry check. Scheduled database cleanup is an application concern.

Deleting a session value is not an atomic replay guard. Concurrent requests can
read the same token. A captured cookie can also contain an older session value.
Use server-side state when either case must be rejected.

## Single use and resend replacement

For strict single use, lock a challenge row while verifying the code and
committing the application change. Record completion in that same transaction.
The [Rails example](rails.md#database-challenges) demonstrates this pattern.

Replace the current token under the same row lock on resend. All verification
requests must resolve that row and use its current token. An older token still
passes standalone cryptographic verification until expiry, but the application
no longer accepts it for that challenge.

Random codes can occasionally repeat. Token replacement invalidates an older
token, not every possible matching code value.

Selective revocation requires changing something the verifier checks, such as
a stored token, generation, or completion status. It cannot be achieved using
only the unchanged token, key, purpose, and time.

A Redis atomic claim can prevent repeated redemption. It does not share a
transaction with application database changes. Account for failure between
claiming the token and completing the application action.
