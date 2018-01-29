require 'factory_girl'

FactoryBot.define do
  factory :service_rule, class: CASino::ServiceRule do
    sequence :order do |n|
      n
    end
    sequence :name do |n|
      "Rule #{n}"
    end

    trait :regex do
      regex true
    end
  end
end
