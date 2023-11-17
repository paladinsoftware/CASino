
$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'casino/version'

Gem::Specification.new do |s|
  s.name        = 'casino'
  s.version     = CASino::VERSION
  s.authors     = ['Nils Caspar', 'Raffael Schmid', 'Samuel Sieg']
  s.email       = ['ncaspar@me.com', 'raffael@yux.ch', 'samuel.sieg@me.com']
  s.homepage    = 'http://rbcas.org/'
  s.license     = 'MIT'
  s.summary     = 'A simple CAS server written in Ruby using the Rails framework.'
  s.description = 'CASino is a simple CAS (Central Authentication Service) server.'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  sign_file = File.expand_path '~/.gem/casino-private_key.pem'
  if File.exist?(sign_file)
    s.signing_key = sign_file
    s.cert_chain  = ['casino-public_cert.pem']
  end

  s.add_runtime_dependency 'addressable', '>= 2.3'
  s.add_runtime_dependency 'faraday', '>= 0.15.4'
  s.add_runtime_dependency 'grape', '>= 0.8'
  s.add_runtime_dependency 'grape-entity', '>= 0.4'
  s.add_runtime_dependency 'kaminari', '>= 1.2.1'
  s.add_runtime_dependency 'rails', '>= 4.2'
  s.add_runtime_dependency 'rotp', '>= 2.0'
  s.add_runtime_dependency 'rqrcode', '~> 0.10.1'
  s.add_runtime_dependency 'rqrcode_png', '>= 0.1'
  s.add_runtime_dependency 'sass-rails', '>= 4.0.0'
  s.add_runtime_dependency 'terminal-table', '>= 1.4'
  s.add_runtime_dependency 'useragent', '>= 0.4'
end
