# Replace the embedded hostname within the url, based on the prime host table
# Usage: ruby filter_prime.rb [file_host]
require	"wmap"

puts "URL | Prime URL"
my_tracker=Wmap::HostTracker::PrimaryHost.instance
f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	url=line.chomp
	if my_tracker.is_url?(url)
		host=my_tracker.url_2_host(url)
		ip=my_tracker.host_2_ip(host)
		if my_tracker.ip_known?(ip)
			p_host=my_tracker.local_ip_2_host(ip)
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
my_tracker=nil 
