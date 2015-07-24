# Replace the embedded hostname within the url, based on the prime host table
# Usage: ruby filter_prime.rb [file_host] 
require	"wmap"

puts "URL | Prime URL"
f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	url=line.chomp  
	if Wmap::HostTracker::PrimaryHost.instance.is_url?(url)  
		host=Wmap::HostTracker::PrimaryHost.instance.url_2_host(url)
		ip=Wmap::HostTracker::PrimaryHost.instance.host_2_ip(host)
		if Wmap::HostTracker::PrimaryHost.instance.ip_known?(ip)
			p_host=Wmap::HostTracker::PrimaryHost.instance.local_ip_2_host(ip)
			url_new=url.sub(host,p_host)
		else
			url_new=url
		end
		puts "#{url} | #{url_new}"
	else
		puts "#{url} | #{url}"
	end
end
f_urls.close
