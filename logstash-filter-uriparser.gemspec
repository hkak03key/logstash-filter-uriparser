Gem::Specification.new do |s|
  s.name          = 'logstash-filter-uriparser'
  s.version       = '0.2.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Parses URI'
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors       = ['Hikaru']
  s.email         = 'hkak03key@gmail.com'
  s.homepage        = ""
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency "addressable"
  s.add_runtime_dependency "public_suffix"

  s.add_development_dependency 'logstash-devutils'
end

