class CASino::LoginTicket < CASino::ApplicationRecord
  include CASino::ModelConcern::Ticket
  include CASino::ModelConcern::ConsumableTicket

  self.ticket_prefix = 'LT'.freeze

  def self.cleanup
    where(['created_at < ?', CASino.config.login_ticket[:lifetime].seconds.ago]).delete_all
  end

  def expired?
    (Time.now - (created_at || Time.now)) > CASino.config.login_ticket[:lifetime].seconds
  end
end
