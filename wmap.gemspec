#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Sam (Yang) Li <yang.li@owasp.org>
#++

# -*- encoding: utf-8 -*-
VERSION = File.dirname(__FILE__) + "/version.txt"

# Simple parser for the project version file
info=Hash.new
f=File.open(VERSION,'r')
f.each do |line|
	line.chomp!
	case line
	when /^(\s)*#/
		next
	when /\=/
		entry=line.split("=").map! {|x| x.strip}
		info[entry[0]]=entry[1]
	end
end
f.close
#

Gem::Specification.new do |s|
  s.name = info["package"]
  s.version = info["version"]
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = info["author"]
  s.homepage = info["github"]
  s.licenses = ["MIT"]
  s.date = info["date"]
  s.description = "wmap is written to perform Internet web application / service discovery. The discovery results are designed to be automatically tracked by the software."
  s.email = info["email"]
  s.executables = ["wmap","wscan","wadd","wadds","wdel","wcheck","wdump","spiderBot","googleBot","updateAll","prime","deprime","refresh","trust","distrust","run_tests"]
  s.files = ["CHANGELOG.md", "TODO", "settings/discovery_ports","data/","LICENSE.txt",
							"version.txt","README.rdoc", "wmap.gemspec"]
  s.files += Dir['lib/*.rb'] + Dir['lib/wmap/*.rb'] + Dir['lib/wmap/**/*'] + Dir['bin/*'] + Dir['settings/*'] + Dir['demos/*'] + Dir['test/*'] + Dir['ruby_whois_patches/*'] + Dir['dicts/*']
  #s.homepage = "none"
  s.post_install_message = "*"*80 + "\n\nThank you for installing the wmap gem - a pure Ruby library for Internet web application discovery and tracking. Please refer to the README.rdoc for more information of using this gem.  \n\n" + "*"*80 + "\n"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1")

	s.add_dependency 'dnsruby', '>= 1.52'
	s.add_dependency 'geoip', '>= 1.0'
	s.add_dependency 'minitest', '>= 5.0'
	s.add_dependency 'net-ping', '>= 2.0'
	s.add_dependency 'nokogiri', '>= 1.6'
	s.add_dependency 'css_parser', '>= 1.6'
	s.add_dependency 'openssl', '>= 2.0'
	s.add_dependency 'parallel', '>= 1.0'
	s.add_dependency 'whois', '>= 2.7'
	s.add_dependency 'httpclient', '~> 2.0'
	s.add_dependency 'open_uri_redirections', '>= 0.2'
	s.add_dependency 'netaddr', '~> 1.5'
	s.add_dependency 'watir', '~> 6.16.5' # Handle JS generated DOM
	s.add_dependency 'selenium-webdriver', '~> 3.141.0' #Ruby bindings for WebDriver; http://watir.com/guides/drivers/
	#Note by default you would need headless chrome binary, from http://chromedriver.storage.googleapis.com/index.html, then put it under the PATH for webdriver

  s.rubyforge_project = "wmap"
  s.rubygems_version = "1.8.24"
  s.summary = "A pure Ruby web application and service discovery API."

end
