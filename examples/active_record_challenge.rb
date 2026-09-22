# frozen_string_literal: true

require "otp_courier"

class OtpChallengeFlow
  def initialize(challenge, max_attempts: 5)
    unless max_attempts.is_a?(Integer) && max_attempts.positive?
      raise ArgumentError, "max_attempts must be a positive Integer"
    end

    @challenge = challenge
    @max_attempts = max_attempts
  end

  def issue!(payload: {}, validity: 600)
    require_transaction_boundary!
    @challenge.with_lock do
      reject_closed_challenge!
      issued = OtpCourier::OTP.issue(purpose: @challenge.purpose, payload: payload, validity: validity)
      @challenge.update!(token: issued.token)
      issued
    end
  end

  def complete!(code)
    require_transaction_boundary!
    failure = nil
    payload = nil

    completed = @challenge.with_lock do
      begin
        reject_closed_challenge!
        payload = OtpCourier::OTP.consume!(@challenge.token, code, purpose: @challenge.purpose)
      rescue OtpCourier::InvalidCode => error
        @challenge.attempts += 1
        @challenge.token = nil if @challenge.attempts >= @max_attempts
        @challenge.save!
        failure = error
        next
      rescue OtpCourier::ExpiredToken, OtpCourier::InvalidToken => error
        @challenge.update!(token: nil)
        failure = error
        next
      end

      yield payload if block_given?
      @challenge.update!(token: nil, consumed_at: Time.current)
    end

    # Raising inside the transaction would roll back failed-attempt counters and cleanup.
    raise failure if failure
    raise ActiveRecord::Rollback, "Challenge completion was rolled back" unless completed

    payload
  end

  private

  def reject_closed_challenge!
    if @challenge.consumed_at || @challenge.attempts >= @max_attempts
      raise OtpCourier::InvalidToken, "Challenge is closed"
    end
  end

  def require_transaction_boundary!
    raise ArgumentError, "challenge must be persisted" unless @challenge.persisted?
    if @challenge.class.connection.transaction_open?
      raise ArgumentError, "Call the challenge flow outside an existing transaction"
    end
  end
end
