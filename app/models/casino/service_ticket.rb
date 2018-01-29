require 'addressable/uri'

class CASino::ServiceTicket < CASino::ApplicationRecord
  include CASino::ModelConcern::Ticket

  self.ticket_prefix = 'ST'.freeze

  belongs_to :ticket_granting_ticket
  before_destroy :send_single_sign_out_notification, if: :consumed?
  has_many :proxy_granting_tickets, as: :granter, dependent: :destroy

  def self.cleanup_unconsumed
    where(['created_at < ? AND consumed = ?', CASino.config.service_ticket[:lifetime_unconsumed].seconds.ago, false]).delete_all
  end

  def self.cleanup_consumed
    where(['(ticket_granting_ticket_id IS NULL OR created_at < ?) AND consumed = ?', CASino.config.service_ticket[:lifetime_consumed].seconds.ago, true]).destroy_all
  end

  def self.cleanup_consumed_hard
    where(['created_at < ? AND consumed = ?', (CASino.config.service_ticket[:lifetime_consumed] * 2).seconds.ago, true]).delete_all
  end

  def service=(service)
    normalized_encoded_service = Addressable::URI.parse(service).normalize.to_str
    super(normalized_encoded_service)
  end

  def service_with_ticket_url
    service_uri = Addressable::URI.parse(service)
    service_uri.query_values = (service_uri.query_values(Array) || []) << ['ticket', ticket]
    service_uri.to_s
  end

  def expired?
    lifetime = if consumed?
                 CASino.config.service_ticket[:lifetime_consumed]
               else
                 CASino.config.service_ticket[:lifetime_unconsumed]
               end
    (Time.now - (created_at || Time.now)) > lifetime
  end

  private

  def send_single_sign_out_notification
    notifier = SingleSignOutNotifier.new(self)
    notifier.notify
    true
  end
end
