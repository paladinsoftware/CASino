module CASino
  class InstallGenerator < Rails::Generators::Base
    source_root File.expand_path('../templates', __FILE__)

    # Explicit namespace needed for proper inflection.
    # Thor::Group does not use ActiveSupport's Inflector when programmatically
    # generating the namespace, so this would be to "c_a_sino" otherwise.
    namespace 'casino:install'

    class_option :migration,
        desc: 'Skip generating migrations',
        type: :boolean,
        default: true

    class_option :config_files,
        desc: 'Install default config files',
        type: :boolean,
        default: true

    def install_migrations
      return unless options['migration']

      generate 'casino:migration'
    end

    def copy_config_files
      return unless options['config_files']

      copy_file 'cas.yml', 'config/cas.yml'
      copy_file 'casino_and_overrides.scss', "app/assets/stylesheets/#{namespace_name}/casino_and_overrides.scss".squeeze('/')
    end

    def insert_assets_loader
      insert_into_file "app/assets/javascripts/#{namespace_name}/application.js".squeeze('/'), :after => %r{//= require +['"]?jquery_ujs['"]?} do
        "\n//= require casino"
      end
    end

    def insert_engine_routes
      route "mount CASino::Engine => '/', :as => 'casino'"
    end

    def show_readme
      readme 'README'
    end

    private
      def namespace_name
        Rails::Generators.namespace.to_s.underscore
      end

  end
end
