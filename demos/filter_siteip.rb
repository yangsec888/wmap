# Sample Site IP Tracker - Given a IP, flag it if not found in the site data repository  
# Usage: ruby filter_siteip.rb [file_web_hosts] 
require	"wmap"

def known?(ip)
	ip=ip.chomp.strip
	myDis = Wmap::SiteTracker.instance
	known=false
	if myDis.is_ip?(ip)
		if myDis.siteip_known?(ip)
			myDis=nil
			return true
		end
	end
	myDis=nil
	return known
end

puts "Site IP, Status"


f_ips = File.open(ARGV[0], 'r')
f_ips.each do |line|
	ip=line.chomp.strip
	if known?(ip)
		# do nothing
	else
		puts "#{ip}, unknown"
	end
end
f_ips.close

