require 'grape'

class CASino::Api < Grape::API
  format :json

  mount CASino::Api::Resource::AuthTokenTickets
end
