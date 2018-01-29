require 'rails/generators/active_record'

module CASino
  class MigrationGenerator < ::Rails::Generators::Base
    include Rails::Generators::Migration
    source_root File.expand_path('../../../../db/migrate', __FILE__)

    namespace 'casino:migration'

    desc 'Installs CASino migration files.'
    
    def install
      source_paths.each do |source_path|
        Dir["#{source_path}/*.rb"].each do |filename|
          migration_template File.basename(filename), "db/migrate/#{File.basename(filename).sub(/^\d+_/, '')}"
        end
      end
    end

    def self.next_migration_number(dirname)
      ActiveRecord::Generators::Base.next_migration_number(dirname)
    end
  end
end