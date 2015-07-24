# print out the timestamp for the sites
# Usage: ruby filter_timestamp.rb [file_sites] 
require	"wmap"

tracker = Wmap::SiteTracker.instance

puts "Site | Timestamp"
f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	url=line.chomp  
	if tracker.is_url?(url)  
		site=tracker.url_2_site(url)
		if tracker.site_known?(site)
			ts=tracker.known_sites[site]['timestamp']
			puts "#{site}|#{ts}"
		else
			puts site
		end
	else
		puts url
	end
end
f_urls.close
