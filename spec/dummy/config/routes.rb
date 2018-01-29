Rails.application.routes.draw do
  mount CASino::Engine => '/', :as => 'casino'
end
