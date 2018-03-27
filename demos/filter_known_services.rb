# Compare the scan lists and flag out the new site
# Usage: filter_known_@services.rb [last quarter list] [this quarter list]

require "wmap"


# Create a known service map by parsing last quarter scan list
def parse_old
	host_tracker=Wmap::HostTracker.new
	@services=Hash.new
	f_site=File.open(ARGV[0],'r')
	f_site.each do |line|
		site=line.chomp.strip
		site=host_tracker.url_2_site(site)
		abort "Error on processing site: #{site}" if site.nil?
		host=host_tracker.url_2_host(site)
		abort "Error on processing host: #{host}" if host.nil?
		ip=host_tracker.local_host_2_ip(host)
		ip=host_tracker.host_2_ip(host) if ip.nil?
		next if ip.nil?
		next unless host_tracker.is_ip?(ip)
		port=host_tracker.url_2_port(site)
		key=ip+":"
		key+=port.to_s
		@services[key]=true unless @services.key?(key)
	end
	f_site.close
	host_tracker=nil
end

# Go through the new scan list and look up for known service from last quarter
def diff
	host_tracker=Wmap::HostTracker.new
	f_new = File.open(ARGV[1],'r')
	f_new.each do |line|
		site=line.chomp.strip
		site1=host_tracker.url_2_site(site)
		abort "Error on processing site: #{site}" if site1.nil?
		host=host_tracker.url_2_host(site1)
		abort "Error on processing host: #{host}" if host.nil?
		ip=host_tracker.local_host_2_ip(host)
		ip=host_tracker.host_2_ip(host) if ip.nil?
		abort "Error resolve host: #{host}" if ip.nil?
		port=host_tracker.url_2_port(site1)
		abort "Error retrieve service port on site: #{site}" if port.nil?
		key=ip+":"
		key+=port.to_s
		if @services.key?(key)
			puts "No"
		else
			puts "Yes"
		end
	end
	f_new.close
	host_tracker=nil 
end

parse_old
diff
