# frozen_string_literal: true

module OtpCourier
  # Operational helpers for rotating the encryption secret.
  #
  # Recommended rotation sequence:
  #
  #   # 1. Deploy with the new key alongside the old one.
  #   OtpCourier::Keys.rotate!("2026-q2", new_secret)
  #
  #   # 2. After all in-flight tokens have expired (e.g. 1 hour for OTPs,
  #   #    7 days for invitations), retire the old key.
  #   OtpCourier::Keys.retire!("2026-q1")
  #
  # During step 1, new tokens are encrypted with the new key, but tokens
  # already in users' inboxes still decrypt with the old key.
  module Keys
    module_function

    # Add (or replace) a key and make it the active one.
    def rotate!(new_kid, new_secret)
      config = OtpCourier.config
      config.secrets[new_kid.to_s] = new_secret
      config.active_kid = new_kid.to_s
    end

    # Remove a key entirely. Any tokens still encrypted under this kid
    # become permanently undecryptable.
    def retire!(kid)
      OtpCourier.config.secrets.delete(kid.to_s)
    end

    def active_kid
      OtpCourier.config.active_kid
    end

    def kids
      OtpCourier.config.secrets.keys
    end
  end
end
