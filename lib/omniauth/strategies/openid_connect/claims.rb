module OmniAuth
  module Strategies
    class OpenIDConnect
      module Claims
        def self.prepended(base)
          base.class_exec do
            # Additional, specific claims to be requested on top of those requested via scopes.
            # For instance:
            #
            # {
            #   userinfo: {
            #     "given_name": {"essential": true},
            #     "nickname": null,
            #     "email": {"essential": true},
            #     "email_verified": {"essential": true},
            #     "picture": null,
            #     "http://example.info/claims/groups": null
            #   },
            #   id_token: {
            #     "auth_time": {"essential": true},
            #     "acr": {"values": ["phr", "phrh"] }
            #   }
            # }
            option :claims, {}
          end
        end

        def validate_access_token!(access_token)
          super

          verify_id_token_claims! access_token
        end

        def authorize_options
          super.merge(
            claims: claims_auth_param
          )
        end

        def claims_auth_param
          return nil unless claims?

          ERB::Util.url_encode Hash(options.claims).to_json
        end

        def claims
          @claims ||= begin
            input = options.claims.is_a?(String) ? JSON.parse(options.claims) : options.claims

            Hash(input).with_indifferent_access
          end
        end

        def claims?
          claims.present? && claims.values.any?(&:present?)
        end

        ##
        # Indicates whether claims have to be verified in either id_token or userinfo the response.
        # `acr_values` claims are by definition voluntary and therefore don't need to be verified.
        def verify_claims?
          claims? && claims.keys.any? { |context| essential_claims(context).present? }
        end

        def essential_claims(context)
          Hash(claims[context])
            .select { |claim, request| Hash(request)["essential"].to_s == "true" }
        end

        ##
        # Verifies claims returned in the ID token. Claims from the userinfo endpoint are not verified for now.
        #
        def verify_id_token_claims!(access_token)
          return unless claims?

          id_token = decode_id_token access_token.id_token

          essential_claims(:id_token).each do |claim, request|
            require_essential_claim! claim, Hash(request), id_token.send(claim) if id_token.respond_to? claim
          end
        end

        def require_essential_claim!(claim, request, response)
          expected_values = [request["value"]].select(&:present?).presence || claim_values(request["values"].presence)

          return unless expected_values.present?

          actual_values = claim_values response

          return if expected_values.any? { |value| actual_values.include? value }

          expected = expected_values.map { |v| "'#{v}'" }.join(", ")
          actual = actual_values.map { |v| "'#{v}'" }.join(", ")

          raise(
            ::OpenIDConnect::ResponseObject::IdToken::InvalidToken,
            "Expected one of #{claim.to_s.upcase} values [#{expected}] in [#{actual}]"
          )
        end

        ##
        # Makes sure the given ACR values are parsed correctly as an array.
        # They are supposed to be given as an array but in other places such as the `acr_values`
        # request parameter they are just a string of space-separated values.
        #
        # @param input [String, Array<String>] ACR values either directly as an array or as a space-separated string.
        #
        # @return [Array<String>] An array of ACR values.
        def claim_values(input)
          Array(input).flat_map { |value| String(value).split(" ") }
        end
      end
    end
  end
end
