class FixLengthOfTextFields < ActiveRecord::Migration[4.1]
  def change
    change_column :casino_proxy_tickets, :service, :text, :limit => nil
    change_column :casino_service_tickets, :service, :text, :limit => nil
    change_column :casino_ticket_granting_tickets, :user_agent, :text, :limit => nil
  end
end
