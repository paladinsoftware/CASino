require 'factory_girl'

FactoryBot.define do
  factory :user, class: CASino::User do
    authenticator 'test'
    sequence(:username) do |n|
      "test#{n}"
    end
    extra_attributes(fullname: 'Test User', age: 15, roles: [:user])
  end
end
