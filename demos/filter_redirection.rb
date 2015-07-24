# Internet domain fingerprint technique - print the redirection location if any
# Usage: ruby filter_redirection.rb [file_urls] 
require	"wmap"

puts "List of URLs with Redirection:"
puts "URL, Reponse Code, Redirection Location"
myDis = Wmap::UrlChecker.new
myDis.http_timeout=5000
f_urls = File.open(ARGV[0], 'r')
f_urls.each do |line|
	url=line.chomp
	host=myDis.url_2_host(url)
	code=myDis.response_code(url)
	if code >= 300 && code < 400
		location=myDis.redirect_location(url)
	end
	puts "#{url}, #{code}, #{location}"
end
f_urls.close
