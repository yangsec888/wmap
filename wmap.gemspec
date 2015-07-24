#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
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
  s.homepage = info["linkedin"]
  s.licenses = ["MIT"]
  s.date = info["date"]
  s.description = "wmap is written to perform Internet web application / service discovery. The discovery results are designed to be automatically tracked by the software."
  s.email = info["email"]
  s.executables = ["wmap","wscan","wadd","wadds","wdel","wcheck","wdump","spiderBot","googleBot","updateAll","prime","deprime","refresh","trust","distrust","run_tests"]
  s.files = ["CHANGELOG.md", "TODO", "settings/discovery_ports","settings/google_keywords.txt","settings/google_locator.txt","data/cidrs","data/domains","data/sub_domains","data/hosts","data/sites","data/deactivated_sites","data/prime_hosts","lib/wmap/cidr_tracker.rb","lib/wmap/dns_bruter.rb","lib/wmap/domain_tracker.rb","lib/wmap/domain_tracker/sub_domain.rb","lib/wmap/host_tracker.rb","lib/wmap/host_tracker/primary_host.rb","lib/wmap/network_profiler.rb","lib/wmap/port_scanner.rb","lib/wmap/site_tracker.rb","lib/wmap/site_tracker/deactivated_site.rb","lib/wmap/url_checker.rb","lib/wmap/url_crawler.rb","lib/wmap/geoip_tracker.rb","lib/wmap/google_search_scraper.rb","lib/wmap/utils/logger.rb","lib/wmap/utils/domain_root.rb","lib/wmap/utils/url_magic.rb","lib/wmap/utils/utils.rb","lib/wmap/whois.rb","lib/wmap.rb","LICENSE.txt","version.txt","README.rdoc",  "wmap.gemspec"]
  s.files += Dir['bin/*'] + Dir['demos/*'] + Dir['test/*'] + Dir['ruby_whois_patches/*'] + Dir['dicts/*'] + Dir['logs/wmap.log']
  #s.homepage = "none"
  s.post_install_message = "*"*80 + "\n\nThank you for installing the wmap gem - a pure Ruby library for Internet web application discovery and tracking. Please refer to the README.rdoc for more information of using this gem.  \n\n" + "*"*80 + "\n"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.2")
  s.rubyforge_project = "wmap"
  s.rubygems_version = "1.8.24"
  s.summary = "A pure Ruby web application and service discovery API."

end
