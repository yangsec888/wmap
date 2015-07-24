# Exact netname and description from the whois query on an IP
# Usage: ruby filter_netinfo.rb [file_ip] 
require	"wmap"


puts Wmap.banner
whois = Wmap::Whois.new(:verbose=>false)
#tracker = Wmap::CidrTracker.new

#puts "IP ;  Netname ; Net Reference"
f_ips = File.open(ARGV[0], 'r:iso-8859-1')
f_ips.each do |line|
	ip=line.chomp.split(',')[1]  
	if whois.is_ip?(ip) or whois.is_cidr?(ip) 
		netname=whois.get_netname(ip)
		desc=whois.get_net_desc(ip)
		#tr=tracker.track(ip)
		puts "#{line.chomp};#{netname};#{desc}"
	else
		puts "#{line.chomp};;"
	end
end
f_ips.close
