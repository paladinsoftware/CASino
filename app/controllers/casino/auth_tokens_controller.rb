class CASino::AuthTokensController < CASino::ApplicationController
  include CASino::SessionsHelper
  include ERB::Util
  include TwoFactorAuthenticatorsHelper

  helper_method :otp_qr_code_data_url

  def login
    validation_result = validation_service.validation_result
    return redirect_to_login unless validation_result

    set_sign_in_callback_url(session.delete(:service).presence || ENV['DASHBOARD_BASE_URL'])
    sign_in(validation_result, long_term: true)
  end

  private

  def set_sign_in_callback_url(url)
    params[:service] = url
  end

  def validation_service
    @validation_service ||= CASino::AuthTokenValidationService.new(auth_token, auth_token_signature)
  end

  def redirect_to_login
    redirect_to login_path(service: params[:service])
  end

  def auth_token_signature
    @auth_token_signature ||= base64_decode(params[:ats])
  end

  def auth_token
    @auth_token ||= base64_decode(params[:at])
  end

  def base64_decode(data)
    begin
      Base64.strict_decode64(data)
    rescue
      ''
    end
  end
end
