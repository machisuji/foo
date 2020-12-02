# OmniAuth::OpenIDConnect

OpenID Connect strategy for OmniAuth

[![Build Status](https://travis-ci.org/opf/omniauth-openid-connect.png?branch=master)](https://travis-ci.org/opf/omniauth-openid-connect)

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-openid-connect', git: "https://github.com/opf/omniauth-openid-connect.git"

And then execute:

    $ bundle

## Usage

Example configuration
```ruby
config.omniauth :openid_connect, {
  name: :my_provider,
  scope: [:openid, :email, :profile, :address],
  response_type: :code,
  client_options: {
    port: 443,
    scheme: "https",
    host: "myprovider.com",
    identifier: ENV["OP_CLIENT_ID"],
    secret: ENV["OP_SECRET_KEY"],
    redirect_uri: "http://myapp.com/auth/my_provider/callback",
  },
}
```

Example configuration for Google authentication:
```ruby
config.omniauth :openid_connect, {
  name: :google,
  scope: [:openid, :email, :profile],
  client_auth_method: :not_basic, # Google does not support basic auth
  send_nonce: false,              # requests with a nonce a rejected by Google
  client_options: {
    identifier: ENV["OP_CLIENT_ID"],
    secret: ENV["OP_SECRET_KEY"],
    redirect_uri: "http://myapp.com/auth/google/callback",

    host: "accounts.google.com",
    authorization_endpoint: "/o/oauth2/auth",
    token_endpoint: "/o/oauth2/token",
    userinfo_endpoint: "https://www.googleapis.com/plus/v1/people/me/openIdConnect"
  },
}
```


Configuration details:
  * `name` is arbitrary, I recommend using the name of your provider. The name
  configuration exists because you could be using multiple OpenID Connect
  providers in a single app.
  * Although `response_type` is an available option, currently, only `:code`
  is valid. There are plans to bring in implicit flow and hybrid flow at some
  point, but it hasn't come up yet for me. Those flows aren't best practive for
  server side web apps anyway and are designed more for native/mobile apps.

For the full low down on OpenID Connect, please check out
[the spec](http://openid.net/specs/openid-connect-core-1_0.html).

## Contributing

1. Fork it ( http://github.com/opf/omniauth-openid-connect/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
