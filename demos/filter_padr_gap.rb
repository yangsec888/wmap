# Sample Site IP Tracker - Given PADR url, flag it if ip found in the site data repository  
# Usage: ruby filter_padr_gap.rb [file_pa_urls] 
require	"wmap"

def known?(ip)
	begin
		ip=ip.chomp.strip
		return @ips.key?(ip)
	rescue => ee
		return false
	end
end

scan_list="q4"
@ips=Wmap::HostTracker.instance.file_2_hash(scan_list)
f_ips = File.open(ARGV[0], 'r')
f_ips.each do |url|
	url.chomp!
	urls=Array.new
	case url
		when /\,|\;/; urls=url.split(%r{\,|\;\s+})
		else; urls.push(url)
	end
	ip=String.new
	urls.map do |entry|
		entry.strip!
		next if entry.nil?
		host=Wmap::HostTracker.instance.url_2_host(entry)
		if Wmap::HostTracker.instance.is_ip?(host)
			ip = host
		else
			ip = Wmap::HostTracker.instance.local_host_2_ip(host)
			ip = Wmap::HostTracker.instance.host_2_ip(host) unless ip.nil?
		end
	end
	if known?(ip)
		puts "#{url}|Yes"
	else
		puts "#{url}|No"
	end
end
f_ips.close

