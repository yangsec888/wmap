# Perform GEOIP info lookup, based on Maxmind GeoIP database
# Usage: ruby filter_geoip.rb [file_wdump_csv] 
require	"wmap"

verbose=false
tracker = Wmap::GeoIPTracker.new(:verbose=>false)

#puts "IP, GeoIP Location"
f_ips = File.open(ARGV[0], 'r')
f_ips.each do |line|
	ip=line.chomp.split(',')[1]
	info=String.new
	if tracker.is_ip?(ip)
		puts "IP: #{ip}" if verbose
		ctr=tracker.country(ip)
		info = info + " " + ctr.country_code3 unless ctr.country_code3.nil?
		citi=tracker.city(ip)
		info=info+" "+citi.region_name unless citi.nil? or citi.region_name.nil?
		info=info+" "+citi.city_name unless citi.nil? or citi.city_name.nil?
		info=info+" "+citi.postal_code unless citi.nil? or citi.postal_code.nil?
		puts "#{line.chomp}, #{info}"
	else
		puts "#{line.chomp},"
	end
end
f_ips.close
