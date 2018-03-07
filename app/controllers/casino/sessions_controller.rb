class CASino::SessionsController < CASino::ApplicationController
  include CASino::SessionsHelper
  include CASino::AuthenticationProcessor
  include CASino::TwoFactorAuthenticatorProcessor

  include AccountsHelper
  include ERB::Util
  include TwoFactorAuthenticatorsHelper

  helper_method :otp_qr_code_data_url

  before_action :validate_login_ticket, only: [:create]
  before_action :ensure_service_allowed, only: [:new, :create]
  before_action :load_ticket_granting_ticket_from_parameter, only: [:validate_otp]
  before_action :ensure_signed_in, only: [:index, :destroy]


  def index
    redirect_to ENV['DASHBOARD_BASE_URL']
  end

  def new
    store_return_to_url(params[:service])

    tgt = current_ticket_granting_ticket

    update_user_extra_attributes(tgt) if tgt

    return handle_signed_in(tgt) unless params[:renew] || tgt.nil? || !tgt.persisted?
    redirect_to(params[:service]) if params[:gateway] && params[:service].present?
  end

  def create
    validation_result = validate_login_credentials(params[:username], params[:password], params[:service])

    if !validation_result
      show_login_error I18n.t("invalid_login_credentials", scope: "login_credential_acceptor")
    elsif @error_code = validation_result[:user_data][:error_code]
      show_login_error I18n.t(@error_code, scope: "login_credential_acceptor",
                              sign_up_url: sign_up_url(params.slice(:service)),
                              forgot_password_url: forgot_password_url(params.slice(:service)),
                              confirm_account_url: confirm_account_url(params.slice(:service)))
    else
      set_sign_in_callback_url(session.delete(:service).presence || ENV['DASHBOARD_BASE_URL'])
      sign_in(validation_result, long_term: true, credentials_supplied: true)
    end
  end

  def logout
    sign_out
    redirect_to login_path(service: params[:service], notice: I18n.t("logout.logged_out_without_url"))
  end

  def validate_otp
    @ticket_granting_ticket.user.two_factor_authenticators.each do |two_factor_authenticator|
      validation_result = validate_one_time_password(params[:otp], two_factor_authenticator)

      if validation_result.success?
        @ticket_granting_ticket.update_attribute(:awaiting_two_factor_authentication, false)
        set_tgt_cookie(@ticket_granting_ticket)
        return handle_signed_in(@ticket_granting_ticket)
      else
        results = {}

        [1.minute, 5.minutes, 30.minutes, 1.hour].each do |period|
          totp = ROTP::TOTP.new(two_factor_authenticator.secret)

          results[period] = totp.verify_with_drift(params[:otp], period.to_i)
        end

        Rails.logger.debug("[TOTP DEBUG] " + {
          otp: params[:otp],
          secret: two_factor_authenticator.secret,
          utime: Time.now.to_i,
          email: @ticket_granting_ticket.user.username,
          drifts_results: results
        }.to_json)
      end
    end

    flash.now[:error] = I18n.t('validate_otp.invalid_otp')
  end

  def destroy
    tickets = current_user.ticket_granting_tickets.where(id: params[:id])
    tickets.first.destroy if tickets.any?
    redirect_to sessions_path
  end

  def destroy_others
    current_user
      .ticket_granting_tickets
      .where('id != ?', current_ticket_granting_ticket.id)
      .destroy_all if signed_in?
    redirect_to params[:service] || sessions_path
  end

  private

  def show_login_error(message)
    if @error_code == 'locked'
      render :locked
    else
      flash.now[:error] = message
      render :new, status: :forbidden
    end
  end

  def set_sign_in_callback_url(url)
    params[:service] = url
  end

  def store_return_to_url(url)
    session[:service] = url.presence
  end

  def update_user_extra_attributes(ticket_granting_ticket)
    ticket_granting_ticket.user.update!(
      extra_attributes: Paladin::Accounts::ApiClient.new.find_user(email: ticket_granting_ticket.user.username)
    )
  rescue ActiveRecord::RecordNotFound => _e
    ticket_granting_ticket.destroy!
  end

  def validate_login_ticket
    unless CASino::LoginTicket.consume(params[:lt])
      show_login_error I18n.t('login_credential_acceptor.invalid_login_ticket')
    end
  end

  def ensure_service_allowed
    if params[:service].present? && !service_allowed?(params[:service])
      render 'service_not_allowed', status: :forbidden
    end
  end

  def load_ticket_granting_ticket_from_parameter
    @ticket_granting_ticket = find_valid_ticket_granting_ticket(params[:tgt], request.user_agent, ignore_two_factor: true)
    redirect_to login_path if @ticket_granting_ticket.nil?
  end
end
