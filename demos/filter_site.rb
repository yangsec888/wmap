# filter to select findings for the list of sites
# Usage: ruby filter_site.rb [file targets] [file finding keys]
# Input A is a list of target sites, input B is a list of site index keys for the finding summary
# Output is a list of key for the matching purpose

require "wmap"
@map=Hash.new

def build_map (file)
	k=Wmap::SiteTracker.instance
	f=File.open(file,'r')
	f.each do |line|
		url=line.chomp.strip.downcase
		if k.is_url?(url)
			@map[k.url_2_site(url)]=true
		else
			#puts url
		end
	end
	f.close
	k=nil
end


build_map(ARGV[0])
s=Wmap::SiteTracker.instance
f=File.open(ARGV[1],'r')
f.each do |line|
	url=line.chomp.strip.downcase
	if s.is_url?(url)
		site=s.url_2_site(url)
		if @map.key?(site)
			puts "yes"
		else
			puts "no"
		end
	else
		puts "Invalid Internet URL"
	end
end
