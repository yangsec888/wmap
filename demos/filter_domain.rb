# Input file is a list of hosts or domains, output is a list of unknown hosts / domains
# Usage: ruby filter_domain_x.rb [file_host]
require	"wmap"

puts Wmap.banner
puts "Host,Domain,IP,Trusted CIDR,Trusted CIDR Netname"
myD = Wmap::DomainTracker.new
f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	url=line.chomp
	host=myD.url_2_host(url)
	next if host.nil?
	domain=myD.domain_root(host)
	next if domain.nil?
	if myD.domain_known?(domain)
		#puts url
		next
	else
		#next
		tracker=Wmap.track(host)
		puts "#{host}, #{domain}, #{tracker['ip']}, #{tracker['cidr']}, #{tracker['netname']}"
	end
end

f_urls.close
