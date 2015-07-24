# filter to detect unknown internet domain
# Input is a list of URLs
# Output is an internet domain list that not currently tracked by the domain tracker

require "wmap"

k=Wmap::DomainTracker.instance
#k.verbose=true
f=File.open(ARGV[0],'r')
f.each do |line|
	url=line.chomp.strip.downcase
	host=k.url_2_host(url)
	root=k.get_domain_root(host)
	unless k.domain_known?(root)
		puts root
	end	
end
f.close
