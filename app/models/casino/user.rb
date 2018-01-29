
class CASino::User < CASino::ApplicationRecord
  serialize :extra_attributes, Hash

  has_many :ticket_granting_tickets, dependent: :destroy
  has_many :two_factor_authenticators, dependent: :destroy
  has_many :login_attempts, dependent: :destroy

  def active_two_factor_authenticator
    self.two_factor_authenticators.where(active: true).first
  end
end
