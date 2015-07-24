# Sample CIDR Tracker - Given a trusted IP, print out all tracked CIDR information  
# Usage: ruby filter_cidr.rb [file_web_hosts] 
require	"wmap"

puts "IP, CIDR, CIDR Netname, CIDR Reference"
myDis = Wmap::CidrTracker.new(:verbose=>false)

f_ips = File.open(ARGV[0], 'r:iso-8859-1')
f_ips.each do |line|
	ip=line.chomp.split(',')[1]
	if myDis.is_ip?(ip) 
		tracker=myDis.track(ip)
		puts "#{line.chomp},#{tracker['cidr']},#{tracker['netname']},#{tracker['ref']}"
	else
		puts "#{line.chomp},,,"
	end
end
f_ips.close
