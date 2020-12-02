module OmniAuth
  module Strategies
    class OpenIDConnect
      module UserInfoAmendments
        def user_info
          return @user_info if @user_info

          @user_info = super.tap do |user_info|
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
