require 'openid_connect'

module OmniAuth
  module OpenIDConnect
    class LogoutToken < ::OpenIDConnect::ConnectObject
      class InvalidToken < Error; end
      class ExpiredToken < InvalidToken; end
      class InvalidIssuer < InvalidToken; end
      class InvalidAudience < InvalidToken; end
      class InvalidIssuedAt < InvalidToken; end
      class InvalidEvent < InvalidToken; end
      class InvalidBackchanelLogoutEvent < InvalidToken; end
      class InvalidIdentifiers < InvalidToken; end
      class TokenRecentlyUsed < InvalidToken; end
      class NonceClaimPresent < InvalidToken; end

      BACKCHANNEL_LOGOUT_SCHEMA = "http://schemas.openid.net/event/backchannel-logout".freeze

      attr_required :iss, :aud, :iat, :jti, :events
      attr_optional :sub, :sid, :auth_time
      attr_accessor :access_token, :code, :state
      alias_method :subject, :sub
      alias_method :subject=, :sub=

      def initialize(attributes = {})
        super(attributes)

        self.iat = Time.zone.at(iat.to_i) unless iat.nil?
        self.auth_time = auth_time.to_i unless auth_time.nil?
      end

      def verify!(expected = {})
        validates_issuer(expected)
        validates_audience(expected)
        validates_issued_at_time
        validates_session_and_or_user_id_presence
        validates_events(expected)
        validate_nonce_claim(raw_attributes)

        true
      end

      private

      def all_attributes
        self.class.required_attributes + self.class.optional_attributes
      end

      def validate_nonce_claim(attributes)
        raise NonceClaimPresent if attributes.key?(:nonce)
      end

      def validates_issuer(expected = {})
        raise InvalidIssuer, "Invalid Logout token: Issuer does not match" unless iss == expected[:issuer]
      end

      def validates_audience(expected = {})
        unless Array(aud).include?(expected[:client_id]) || aud == expected[:client_id]
          raise InvalidAudience, "Invalid Logout token: Audience does not match"
        end
      end

      def validates_issued_at_time
        raise InvalidIssuedAt, "Invalid Logout token: Issued at does not match" unless iat.past?
      end

      def validates_session_and_or_user_id_presence
        unless sub || sid
          raise InvalidIdentifiers, "Invalid Logout token: Must contain either SID, SUB or both"
        end
      end

      def validates_events(_expected = {})
        raise InvalidBackchanelLogoutEvent, "Invalid Logout token: Events is not a hash" unless events.is_a? Hash
        unless events.keys.include?(BACKCHANNEL_LOGOUT_SCHEMA)
          raise InvalidBackchanelLogoutEvent, "Invalid Logout token: Events hash does not have the back channel logout event"
        end

        unless events[BACKCHANNEL_LOGOUT_SCHEMA] == {}
          raise InvalidBackchanelLogoutEvent, "Invalid Logout token: Event should be the empty JSON object {}"
        end
      end

      class << self
        def decode(jwt_string, key)
          new JSON::JWT.decode jwt_string, key
        rescue JSON::JWT::InvalidFormat => e
          raise InvalidToken.new(e.message)
        end
      end
    end
  end
end
