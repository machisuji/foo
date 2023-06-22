require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'forwardable'

require 'omniauth/strategies/openid_connect/user_info'
require 'omniauth/strategies/openid_connect/claims'
require 'omniauth/strategies/openid_connect/backchannel_logout'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy
      extend Forwardable

      def_delegator :request, :params

      prepend UserInfo
      prepend Claims
      prepend BackchannelLogout

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: 'https',
        host: nil,
        port: 443,
        authorization_endpoint: '/authorize',
        token_endpoint: '/token',
        userinfo_endpoint: '/userinfo',
        jwks_uri: '/jwk',
        end_session_endpoint: nil
      }
      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, "code"
      option :response_mode
      option :state
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :claims_locales
      option :verify_id_token, nil
      option :login_hint
      option :acr_values # requesting voluntary claims, e.g. 'phr phrh' for phishing-resistant authentication
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri

      credentials do
        {
          id_token: access_token.id_token,
          sid: id_token&.sid,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        discover!
        redirect authorize_uri
      end

      def callback_phase
        error = params['error_reason'] || params['error']
        if error
          raise CallbackError.new(params['error'], params['error_description'] || params['error_reason'], params['error_uri'])
        elsif params['state'].to_s.empty? || params['state'] != stored_state
          return Rack::Response.new(['401 Unauthorized'], 401).finish
        elsif !params['code']
          return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(params['error']))
        else
          discover!
          client.redirect_uri = redirect_uri
          client.authorization_code = authorization_code

          validate_access_token! access_token
          store_session_id!

          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def other_phase
        if logout_path_pattern.match?(current_path)
          discover!

          return redirect(end_session_uri) if end_session_uri
        end

        call_app!
      end

      def authorization_code
        params['code']
      end

      def end_session_uri
        return unless end_session_endpoint_is_valid?

        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_end_session_query
        end_session_uri.to_s
      end

      def authorize_uri
        client.redirect_uri = redirect_uri
        opts = authorize_options

        client.authorization_uri opts.reject { |k, v| v.nil? }
      end

      def authorize_options
        {
          response_type: options.response_type,
          response_mode: options.response_mode,
          scope: options.scope,
          state: new_state,
          login_hint: params['login_hint'].presence || options.login_hint.presence,
          ui_locales: params['ui_locales'].presence || options.ui_locales.presence,
          claims_locales: params['claims_locales'].presence || options.claims_locales.presence,
          prompt: params['prompt'].presence || options.prompt.presence,
          nonce: (new_nonce if options.send_nonce),
          hd: options.hd,
          acr_values: options.acr_values
        }
      end

      def public_key
        return config.jwks if options.discovery
        key_or_secret
      end

      private

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery

        options.issuer = issuer if options.issuer.blank?
        options.verify_id_token = true if options.verify_id_token.nil?

        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri
        client_options.end_session_endpoint = config.end_session_endpoint if config.respond_to?(:end_session_endpoint)
      end

      def access_token
        @access_token ||= client.access_token!(
          scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method
        )
      end

      def id_token
        defined?(@id_token) || begin
          encoded = access_token.id_token
          @id_token = encoded ? decode_id_token(encoded) : nil
        end

        @id_token
      end

      def validate_access_token!(_access_token)
        verify_id_token! if options.verify_id_token
      end

      def verify_id_token!
        id_token.verify!(
          issuer: options.issuer,
          client_id: client_options.identifier,
          nonce: stored_nonce
        )
      end

      def store_session_id!
        sid = id_token&.sid
        return unless sid

        session['omniauth.oidc_sid'] = sid
      end

      def decode_id_token(id_token, verify: options.verify_id_token)
        key = verify ? public_key : :skip_verification

        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key)
      end

      def client_options
        options.client_options
      end

      def new_state
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def session
        return {} if @env.nil?
        super
      end

      def key_or_secret
        case options.client_signing_alg
        when :HS256, :HS384, :HS512
          return client_options.secret
        when :RS256, :RS384, :RS512
          if options.client_jwk_signing_key
            return parse_jwk_key(options.client_jwk_signing_key)
          elsif options.client_x509_signing_key
            return parse_x509_key(options.client_x509_signing_key)
          end
        else
        end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = JSON.parse(key)
        if json.has_key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end

      def redirect_uri
        return client_options.redirect_uri unless params['redirect_uri']
        "#{ client_options.redirect_uri }?redirect_uri=#{ CGI.escape(params['redirect_uri']) }"
      end

      def encoded_end_session_query
        return unless options.post_logout_redirect_uri

        URI.encode_www_form(
          id_token_hint: access_token.id_token,
          post_logout_redirect_uri: options.post_logout_redirect_uri
        )
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint &&
          client_options.end_session_endpoint =~ URI::DEFAULT_PARSER.make_regexp
      end

      def logout_path_pattern
        @logout_path_pattern ||= %r{\A#{Regexp.quote(request_path)}(/logout)}
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
