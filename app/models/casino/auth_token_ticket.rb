class CASino::AuthTokenTicket < CASino::ApplicationRecord
  include CASino::ModelConcern::Ticket
  include CASino::ModelConcern::ConsumableTicket

  self.ticket_prefix = 'ATT'.freeze

  def self.cleanup
    where(['created_at < ?', CASino.config.auth_token_ticket[:lifetime].seconds.ago]).delete_all
  end

  def expired?
    (Time.now - (created_at || Time.now)) > CASino.config.auth_token_ticket[:lifetime].seconds
  end
end
