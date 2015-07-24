###################
#  Simple lookup function to check if a DMP vuln finding is new found
#
#  Usage: ruby new_fnd.rb [old cweid:url pairs] [new cweid.url pair]
#  				sample input row: "297,https://157.83.142.100/"
#  Example: ruby new_fnd.rb oldkeys.csv newkeys.csv > new.csv

require "wmap"

@verbose=false

def load_keys (file)
	puts "Load the key map from file: #{file}" if @verbose
	my_keys=Hash.new
	#begin
		f_old=File.open(file)
		f_old.each_line do |line|
			entry=line.chomp.split(',')
			
			abort "Error loading entry: #{entry}" if entry.size < 2
			url=entry[1]
			cveid=entry[0].to_s
			host=Wmap::HostTracker.instance.url_2_host(url)
			ip=String.new
			if Wmap::HostTracker.instance.is_fqdn?(host)
				ip=Wmap::HostTracker.instance.local_host_2_ip(host) 
			else
				ip=host
			end
			unless Wmap::HostTracker.instance.is_ip?(ip)
				ip=Wmap::HostTracker.instance.host_2_ip(ip) 
			end
			url.sub!(host,ip) unless ip.nil?
			entry=cveid+","+url
			my_keys[entry]=true unless my_keys.key?(entry)	
			puts "Finishing loading key: #{entry}" if @verbose
		end
		f_old.close
		return my_keys
	#rescue => ee
	#	abort "Error on method #{__method__}: #{ee}" if @verbose
	#end
end

old_keys=load_keys(ARGV[0])

f_new=File.open(ARGV[1],'r')
f_new.each_line do |line|
	ent=line.chomp.split(',')
	cve=ent[0]
	url=ent[1]
	host=Wmap::HostTracker.instance.url_2_host(url)
	ip=Wmap::HostTracker.instance.local_host_2_ip(host)
	url.sub!(host,ip) unless ip.nil?
	entry=cve+","+url
	if old_keys.key?(entry)
		puts "#{entry},No"
	else
		puts "#{entry},Yes"
	end
end
f_new.close
#puts new_keys.keys.count
