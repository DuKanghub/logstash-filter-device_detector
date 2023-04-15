Gem::Specification.new do |s|
  s.name          = 'logstash-filter-device_detector'
  s.version       = '0.1.2'
  s.licenses      = ['Apache-2.0']
  s.summary       = '使用device_detector解析useragent的logstash-filter插件.'
  s.description   = 'Detects a vast amount of different devices automaticly based on regex rules.'
  s.homepage      = 'https://github.com/Dukanghub/logstash-filter-device_detector'
  s.authors       = ['Dukang']
  s.email         = 'dukanghub@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "device_detector", "~> 1.0"
  s.add_development_dependency "logstash-devutils", "~> 0"
end
