module OmniAuth
  module Strategies
    class OpenIDConnect
      module UserInfo
        def self.prepended(base)
          base.class_exec do
            option :attribute_map, {}

            uid { user_info.sub }

            info do
              mapped_attributes.merge(fixed_attributes)
            end

            extra do
              { raw_info: user_info.raw_attributes }
            end
          end
        end

        def fixed_attributes
          {
            urls: { website: user_info.website }
          }
        end

        def mapped_attributes
          mapping = default_attribute_map.merge(options.attribute_map)
          values = user_info.raw_attributes.symbolize_keys
          mapping.to_h do |k, v|
            mapped_value = values[v.to_sym]
            [k.to_sym, mapped_value]
          end
        end

        def default_attribute_map
          {
            name: :name,
            email: :email,
            nickname: :preferred_username,
            login: :preferred_username,
            first_name: :given_name,
            last_name: :family_name,
            gender: :gender,
            image: :picture,
            phone: :phone_number,
          }.with_indifferent_access
        end

        def user_info
          @user_info ||= access_token.userinfo!.tap do |user_info|
            # Google sends the string "true" as the value for the field 'email_verified' while a boolean is expected.
            if user_info.email_verified.is_a? String
              user_info.email_verified = (user_info.email_verified == "true")
            end
            user_info.gender = nil # in case someone picks something else than male or female, we don't need it anyway

            # Azure doesn't provide an email by default, but unique_name is the email used to login
            if user_info.email.blank? && user_info.raw_attributes.has_key?("unique_name")
              user_info.email = user_info.raw_attributes["unique_name"]
            end
          end
        end
      end
    end
  end
end
