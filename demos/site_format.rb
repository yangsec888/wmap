# filter to detect unknown internet domain
# Input is a list of URLs
# Output is an internet domain list that not currently tracked by the domain tracker

require "wmap"

k=Wmap::SiteTracker.instance
f=File.open(ARGV[0],'r')
f.each do |line|
	url=line.chomp.strip.downcase
	if k.is_url?(url)
		puts k.url_2_site(url)
	else
		puts url
	end	
end
f.close
