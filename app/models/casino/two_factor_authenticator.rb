
class CASino::TwoFactorAuthenticator < CASino::ApplicationRecord
  belongs_to :user

  scope :active, -> { where(active: true) }

  def self.cleanup
    where(['(created_at < ?) AND active = ?', lifetime.ago, false]).delete_all
  end

  def self.lifetime
    CASino.config.two_factor_authenticator[:lifetime_inactive].seconds
  end

  def expired?
    !active? && (Time.now - (created_at || Time.now)) > self.class.lifetime
  end
end
