# frozen_string_literal: true

if ENV["OTP_COURIER_DATABASE_URL"].nil?
  RSpec.describe "OtpChallengeFlow" do
    it "requires OTP_COURIER_DATABASE_URL for the PostgreSQL integration suite" do
      skip "set OTP_COURIER_DATABASE_URL to run stateful PostgreSQL integration specs"
    end
  end
else
  require "active_record"
  require "timeout"
  require_relative "../../examples/active_record_challenge"

  ActiveRecord::Base.establish_connection(ENV.fetch("OTP_COURIER_DATABASE_URL"))

  class StatefulChallengeRecord < ActiveRecord::Base
    self.table_name = "otp_courier_stateful_challenges"
    self.primary_key = "subject_key"
  end

  RSpec.describe OtpChallengeFlow do
    before(:context) do
      StatefulChallengeRecord.connection.create_table(
        StatefulChallengeRecord.table_name,
        id: false,
        force: true
      ) do |t|
        t.string :subject_key, null: false, primary_key: true
        t.string :purpose, null: false
        t.text :token
        t.datetime :consumed_at
        t.integer :attempts, null: false, default: 0
        t.integer :application_value, null: false, default: 0
        t.timestamps null: false
      end
    end

    after(:context) do
      StatefulChallengeRecord.connection.drop_table(
        StatefulChallengeRecord.table_name,
        if_exists: true
      )
      ActiveRecord::Base.connection_pool.disconnect!
    end

    before do
      StatefulChallengeRecord.delete_all
    end

    def join_threads(threads)
      Timeout.timeout(5) { threads.each(&:value) }
    ensure
      threads.each { |thread| thread.kill if thread.alive? }
      threads.each(&:join)
    end

    def build_record(subject: 7, purpose: "stateful_challenge")
      StatefulChallengeRecord.create!(subject_key: subject.to_s, purpose: purpose)
    end

    def build_flow(record, max_attempts: 3)
      described_class.new(record, max_attempts: max_attempts)
    end

    it "issues against a pre-existing scoped record and preserves attempts" do
      record = build_record
      record.update!(attempts: 1)
      issued = build_flow(record).issue!(payload: { subject: 7 }, validity: 60)

      expect(issued.code).to be_a(String)
      expect(record.reload.token).to eq(issued.token)
      expect(record.attempts).to eq(1)
    end

    it "replaces the current token while retaining failed-attempt history" do
      record = build_record
      flow = build_flow(record)
      allow(SecureRandom).to receive(:random_number).with(10).and_return(1)
      first = flow.issue!(payload: { subject: 7 }, validity: 60)

      expect { flow.complete!("not-the-issued-code") }
        .to raise_error(OtpCourier::InvalidCode)
      expect(record.reload.attempts).to eq(1)

      allow(SecureRandom).to receive(:random_number).with(10).and_return(2)
      second = flow.issue!(payload: { subject: 7 }, validity: 60)

      expect(record.reload.attempts).to eq(1)
      expect { flow.complete!(first.code) }.to raise_error(OtpCourier::InvalidCode)
      expect(flow.complete!(second.code)).to eq("subject" => 7)
    end

    it "clears the token after the configured failed-attempt limit" do
      record = build_record
      flow = build_flow(record, max_attempts: 3)
      issued = flow.issue!(payload: { subject: 7 }, validity: 60)

      3.times do
        expect { flow.complete!("not-the-issued-code") }
          .to raise_error(OtpCourier::InvalidCode)
      end

      expect(record.reload.attempts).to eq(3)
      expect(record.token).to be_nil
    end

    it "rejects resends and correct codes after the failure limit" do
      record = build_record
      flow = build_flow(record, max_attempts: 1)
      issued = flow.issue!(validity: 60)
      expect { flow.complete!("incorrect") }.to raise_error(OtpCourier::InvalidCode)
      expect { flow.issue!(validity: 60) }.to raise_error(OtpCourier::InvalidToken)
      expect { flow.complete!(issued.code) }.to raise_error(OtpCourier::InvalidToken)
      expect(record.reload.token).to be_nil
    end

    it "requires its own transaction to persist failure cleanup" do
      record = build_record
      flow = build_flow(record)
      issued = flow.issue!(validity: 60)
      record.class.transaction do
        expect { flow.complete!(issued.code) }.to raise_error(ArgumentError, /existing transaction/)
        expect { flow.issue! }.to raise_error(ArgumentError, /existing transaction/)
      end
      expect(record.reload.token).to eq(issued.token)
      expect { build_flow(StatefulChallengeRecord.new).issue! }
        .to raise_error(ArgumentError, /persisted/)
    end

    it "clears terminal expired and malformed challenges" do
      record = build_record
      flow = build_flow(record)
      issued = flow.issue!(payload: { subject: 7 }, validity: 60)
      travel 61

      expect { flow.complete!(issued.code) }.to raise_error(OtpCourier::ExpiredToken)
      expect(record.reload.token).to be_nil

      travel_back
      issued = flow.issue!(payload: { subject: 7 }, validity: 60)
      record.update!(token: "malformed")

      expect { flow.complete!(issued.code) }.to raise_error(OtpCourier::InvalidToken)
      expect(record.reload.token).to be_nil
    end

    it "rolls back application changes and retains the challenge on failure" do
      record = build_record
      flow = build_flow(record)
      issued = flow.issue!(payload: { subject: 7 }, validity: 60)

      expect do
        flow.complete!(issued.code) do |payload|
          expect(payload).to eq("subject" => 7)
          record.update!(application_value: 99)
          raise "application failure"
        end
      end.to raise_error("application failure")

      expect(record.reload.application_value).to eq(0)
      expect(record.token).to eq(issued.token)
      expect(flow.complete!(issued.code)).to eq("subject" => 7)
    end

    it "reports an explicit application rollback instead of returning a verified payload" do
      record = build_record
      flow = build_flow(record)
      issued = flow.issue!(validity: 60)
      expect { flow.complete!(issued.code) { raise ActiveRecord::Rollback } }
        .to raise_error(ActiveRecord::Rollback)
      expect(record.reload.token).to eq(issued.token)
      expect(record.consumed_at).to be_nil
    end

    it "allows one concurrent completion and rejects the other" do
      record = build_record
      issued = build_flow(record).issue!(payload: { subject: 7 }, validity: 60)
      entered = Queue.new
      release = Queue.new
      results = Queue.new

      threads = 2.times.map do
        Thread.new do
          ActiveRecord::Base.connection_pool.with_connection do
            begin
              flow = build_flow(StatefulChallengeRecord.find("7"))
              flow.complete!(issued.code) do
                entered << true
                release.pop
              end
              results << :committed
            rescue OtpCourier::VerificationError
              results << :rejected
            end
          end
        end
      end

      begin
        Timeout.timeout(2) { entered.pop }
        release << true
      ensure
        release << true
        join_threads(threads)
      end

      expect([results.pop, results.pop]).to contain_exactly(:committed, :rejected)
      expect(record.reload.consumed_at).to be_present
      expect(record.token).to be_nil
    end

    it "rejects a resend racing with a completed flow" do
      record = build_record
      issued = build_flow(record).issue!(payload: { subject: 7 }, validity: 60)
      entered = Queue.new
      release = Queue.new
      resend_started = Queue.new
      resend_result = Queue.new

      consumer = Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          build_flow(StatefulChallengeRecord.find("7")).complete!(issued.code) do
            entered << true
            release.pop
          end
        end
      end

      begin
        Timeout.timeout(2) { entered.pop }
        resender = Thread.new do
          ActiveRecord::Base.connection_pool.with_connection do
            resend_started << true
            begin
              resend_result << build_flow(StatefulChallengeRecord.find("7"))
                .issue!(payload: { subject: 7 }, validity: 60)
            rescue StandardError => error
              resend_result << error
            end
          end
        end
        Timeout.timeout(2) { resend_started.pop }
        release << true
      ensure
        release << true
        join_threads([consumer, resender].compact)
      end

      expect(resend_result.pop).to be_a(OtpCourier::InvalidToken)
      expect(record.reload.token).to be_nil
    end
  end
end
