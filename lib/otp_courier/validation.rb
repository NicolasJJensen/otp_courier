# frozen_string_literal: true

module OtpCourier
  module Validation
    # BCrypt ignores bytes beyond this limit. Generated codes use ASCII characters.
    MAX_LENGTH = 72
    MAX_DEPTH = 64
    CHARSETS = %i[digits alphanumeric].freeze
    module_function

    def purpose!(value)
      unless value.is_a?(String) || value.is_a?(Symbol)
        raise ArgumentError, "purpose must be a nonblank String or Symbol"
      end
      value = value.to_s
      raise ArgumentError, "purpose must not be blank" if value.strip.empty?
      value
    end

    def length!(value)
      unless value.is_a?(Integer) && value.positive? && value <= MAX_LENGTH
        raise ArgumentError, "length must be an Integer between 1 and #{MAX_LENGTH}"
      end
      value
    end

    def validity!(value)
      unless value.is_a?(Numeric) && !value.is_a?(Complex) && value.finite? && value.positive?
        raise ArgumentError, "validity must be a positive finite number"
      end
      seconds = value.to_f
      raise ArgumentError, "validity must be a positive finite number" unless seconds.finite? && seconds.positive?
      seconds
    end

    def charset!(value)
      value = value.to_sym if value.is_a?(String) || value.is_a?(Symbol)
      return value if CHARSETS.include?(value)
      raise ArgumentError, "charset must be digits or alphanumeric"
    end

    def payload!(payload)
      raise ArgumentError, "payload must be a Hash" unless payload.is_a?(Hash)
      json_value(payload, {})
    rescue EncodingError
      raise ArgumentError, "payload strings must use valid UTF-8"
    end

    def json_value(value, seen)
      case value
      when Hash
        recursive!(value, seen)
        result = value.each_with_object({}) do |(key, item), output|
          unless key.is_a?(String) || key.is_a?(Symbol)
            raise ArgumentError, "payload keys must be Strings or Symbols"
          end
          key = json_string(key)
          raise ArgumentError, "payload contains duplicate keys" if output.key?(key)
          output[key] = json_value(item, seen)
        end
        seen.delete(value.object_id)
        result
      when Array
        recursive!(value, seen)
        result = value.map { |item| json_value(item, seen) }
        seen.delete(value.object_id)
        result
      when String, Symbol
        json_string(value)
      when TrueClass, FalseClass, NilClass, Integer then value
      when Float
        raise ArgumentError, "payload cannot contain non-finite numbers" unless value.finite?
        value
      else
        raise ArgumentError, "payload contains a non-JSON value"
      end
    end

    def json_string(value)
      string = value.to_s
      raise ArgumentError, "payload strings must use valid UTF-8" unless string.valid_encoding?
      string.encode(Encoding::UTF_8)
    end

    def recursive!(value, seen)
      raise ArgumentError, "payload cannot contain cycles" if seen[value.object_id]
      raise ArgumentError, "payload nesting exceeds #{MAX_DEPTH} levels" if seen.length >= MAX_DEPTH
      seen[value.object_id] = true
    end

    private_class_method :json_value, :recursive!, :json_string
  end
end
