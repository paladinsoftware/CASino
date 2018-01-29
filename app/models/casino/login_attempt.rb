class CASino::LoginAttempt < CASino::ApplicationRecord
  include CASino::ModelConcern::BrowserInfo

  belongs_to :user
end
