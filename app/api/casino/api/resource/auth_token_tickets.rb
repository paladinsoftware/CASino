require 'grape'

class CASino::Api::Resource::AuthTokenTickets < Grape::API
  resource :auth_token_tickets do
    desc 'Create an auth token ticket'
    post do
      @ticket = CASino::AuthTokenTicket.create
      Rails.logger.debug "Created auth token ticket '#{@ticket.ticket}'"
      present @ticket, with: CASino::Api::Entity::AuthTokenTicket
    end
  end
end
