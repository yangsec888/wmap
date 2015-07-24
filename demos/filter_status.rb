# Print the URL of a site if it response to the HTTP request
# Usage: ruby filter_status.rb [file_url_links] 
require	"wmap"

puts "List of URLs with the Valid Response Code:"
puts "URL, Reponse Code, URL Finger Print, IP, Barclays CIDR, CIDR Netname"
myDis = Wmap::UrlChecker.new(:verbose=>false, :http_timeout=>5000)

f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	next if url.nil?
	checker=myDis.check(url) 
	host=line.chomp
	tracker=Wmap.track(host)
	puts "#{url}, #{checker['code']}, #{checker['md5']}, #{tracker['ip']}, #{tracker['cidr']}, #{tracker['netname']}"
end
f_urls.close
