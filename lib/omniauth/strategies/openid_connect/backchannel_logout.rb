module OmniAuth
  module Strategies
    class OpenIDConnect
      module BackchannelLogout
        def self.prepended(base)
          base.class_exec do
            # Callback for the backchannel logout
            option :backchannel_logout_callback, nil
          end
        end

        def other_phase
          if on_backchannel_flow?
            return handle_backchannel_flow
          end

          super
        end

        def on_backchannel_flow?
          return false unless options.backchannel_logout_callback

          backchannel_logout_path_pattern.match?(current_path)
        end

        def handle_backchannel_flow
          discover!
          perform_backchannel_logout!(params['logout_token'])
          backchannel_response
        rescue StandardError => e
          Rack::Response.new(
            [e.message],
            400,
            { 'Cache-Control' => 'no-store' }
          ).finish
        end

        def perform_backchannel_logout!(plain_token)
          return fail!(:missing_logout_token) unless plain_token.present?
          logout_token = decode_logout_token(plain_token)

          logout_token.verify!(
            issuer: options.issuer,
            client_id: client_options.identifier
          )

          options.backchannel_logout_callback.call(logout_token)
        end

        def decode_logout_token(token, verify: options.verify_id_token)
          key = verify ? public_key : :skip_verification

          ::OmniAuth::OpenIDConnect::LogoutToken.decode(token, key)
        end

        def backchannel_response
          Rack::Response.new(
            [''],
            200,
            { 'Cache-Control' => 'no-store' }
          ).finish
        end

        def backchannel_logout_path_pattern
          @backchannel_logout_path_pattern ||= %r{\A#{Regexp.quote(request_path)}(/backchannel-logout)}
        end
      end
    end
  end
end
