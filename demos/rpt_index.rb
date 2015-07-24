#!/usr/bin/ruby
# Simple script to create an index.html page for the Dynamic MP summary report
# Usage: ./rpt_index.rb [list of report paths] 
################################################################################################
# Developed by: Yang Li, Version: 0.8, Last Modification: 09/28/2013
################################################################################################
require "resolv"

@verbose=true			# set debugging bit
@MAP=Hash.new		# Store site mapping matrix
@RPT_DB=Hash.new		# Store the final report matrix 
@INDEX_HTML="index.html"
@Map_file="Q1_map_key.csv"

def url_2_host (url)
# Extract Fully Qualified Domain Name (FQDN) from the url 
# For example: "https://login.yahoo.com/email/help" -> "login.yahoo.com"
	url = url.downcase.gsub(/(http:\/\/|https:\/\/)/, "")
	record1 = url.split(%r{\/})
	if record1[0].nil?
		puts "Error process url: #{url}" 
		return nil
	else
		record2 = record1[0].split(%r{\:})		
		return record2[0]
	end
end

def url_2_port (url)
	port=""
	if url=~/\:(\d+)/
		port=$1
	elsif url =~ /https/i
		port="443"
	else
		port="80"
	end
end

def url_2_site (url)
# Extract site in (host:port) format from the url 
# For example: "https://login.yahoo.com:8443/email/help" -> "login.yahoo.com:8443"
	port=url_2_port(url)
	host=url_2_host(url)
	site=host+":"+port
end

def file_2_list(f)
# loader for the reports
	list=Array.new
	file = File.open(f, "r")
	file.each_line do |line|
		list.push(line.chomp)
	end
	file.close
	return list
end

def load_map_from_file (map)
# load the site index (i.e. url => IP, Hosting, Netname, GeoIP, Res Code)
	begin
		f=File.open(map, 'r')
		f.each do |line|
			next if not line =~ /\,/
			puts "Loading: #{line.chomp}" if @verbose
			entry=line.chomp.split(%r{\,})
			site=url_2_site(entry[1])
			@MAP[site] = Hash.new if not @MAP.key?(site)
			@MAP[site]['index']=entry[0]
			@MAP[site]['url']=entry[1]
			@MAP[site]['ip'] = entry[2]
			@MAP[site]['hosting'] = entry[3]
			@MAP[site]['netname'] = entry[4]
			#@MAP[site]['rescode'] = entry[5]
			@MAP[site]['geoip'] = entry[5]
			@MAP[site]['server']=entry[6]
			@MAP[site]['status']=entry[7]
		end
		f.close
	rescue => ee			
		puts "Error: #{ee}" if @verbose
	end
end

def print_map
	puts "Summary of Site URI to SSE Lead Matrix:"
	@MAP.each do |key|
		name=@MAP[key]
		puts "#{key}, #{name}"
	end
	puts "End of the summary"
end

def file_path_2_host (path)
# extract host from the file path
	begin
		puts "Process file path: #{path}"
		file=path.split(%r{\/})[4]
		host=file.gsub(/^_/,'').gsub(/MP - /,'').gsub(/(http|https)\_+/,'').gsub(/\_*\.(pdf|xml)/,'').gsub(/\_\d+/,'')#.gsub(/\_+/,'')
		puts "Extracted host: #{host}"
		return host
	rescue => ee 
		puts "Exception on method #{__method__}: #{ee}"
	end
end

def file_path_2_rpt_name (path)
# extract report name from the file path
	file=path.split(%r{\/})[4]
	return file
end

def file_path_2_site(path)
# extract site in (host:port) format from the file path, as the unique identifier for the mapping process
	file=path.split(%r{\/})[4]
	puts "Extracted file: #{file}" if @verbose
	host=file_path_2_host(path)
	port=""
	site=host
	if file =~ /\_(\d+)\_\_\.(xml|pdf)/
		port=$1
		puts "Found uncommon web port from #{path}: #{$1}" if @verbose
	elsif file =~ /https/i
		port="443"
	else
		port="80"
	end
	site=host+":"+port
	puts "Extracted site: #{site}" if @verbose
	return site
end

def build_rpt_index (file)
# input is a list of report path. load it into the hash with tracking info, i.e. (site => link, IP)
	# load the report list 
	l = file_2_list(file)
	l.each do |x|	# build report db
		file=file_path_2_rpt_name(x)
		#host=file_path_2_host(x)
		site=file_path_2_site(x)
		link="<a href='#{x}'>#{file}</a>"
		@RPT_DB[site]=Hash.new unless @RPT_DB.key?(site)
		@RPT_DB[site]['link']=link
		@RPT_DB[site]['file']=file
		@RPT_DB[site]['hosting']=@MAP[site]['hosting'] if @MAP.key?(site)
		@RPT_DB[site]['ip']=@MAP[site]['ip'] if @MAP.key?(site)
		@RPT_DB[site]['geoip']=@MAP[site]['geip'] if @MAP.key?(site)
		@RPT_DB[site]['hosting']=@MAP[site]['hosting'] if @MAP.key?(site)
		#@RPT_DB[site]['rescode']=@MAP[site]['rescode'] if @MAP.key?(site)
		@RPT_DB[site]['netname']=@MAP[site]['netname'] if @MAP.key?(site)
		@RPT_DB[site]['url']=@MAP[site]['url'] if @MAP.key?(site)
		@RPT_DB[site]['server']=@MAP[site]['server'] if @MAP.key?(site)
		@RPT_DB[site]['status']=@MAP[site]['status'] if @MAP.key?(site)
		@RPT_DB[site]['index']=@MAP[site]['index'] if @MAP.key?(site)
		puts "build_rpt_index: #{site}, #{link}," if @verbose
	end
end

def print_rpt_index
	puts "Summary of Report Matrix:"
	@RPT_DB.each do |key,value|
		next if key.nil?
		link=@RPT_DB[key]['link']
		netname=@RPT_DB[key]['netname']
		puts "#{key}, #{link}, #{netname}"
	end
	puts "End of the summary"
end
################################################################################################
# Main 
################################################################################################
# load the inventory list into the application matrix
# Typical map entry: 
# "http://chconnect.barclays.com/,141.228.106.100,int_hosted,BARCLAYS-CIBWM,GBR H9 London,302 "
abort "Error: incorrect program argument. \nUsage: ./rpt_index.rb [list of report paths]" unless ARGV.size>0
load_map_from_file (@Map_file) 
print_map if @verbose
build_rpt_index (ARGV[0])
print_rpt_index if @verbose
# write the HTML index page
open(@INDEX_HTML, 'w') do |f|
	f.puts "<html>\n<title>Barclays Perimeter Application Scan Report Index Page</title>\n<body>"
	f.puts "<table border='1'>"
	f.puts "<tr><td>Index</td><td>Test Site</td><td>Report Link</td><td>Primary IP</td><td>Hosting Status</td><td>Netname</td><td>GeoIP Location</td><td>Server</td><td>Status Code</td></tr>"
	f.puts "<b>Barclays 2015 Q1 Perimeter Application Scan Report Index - Barclaycard US</b><p>"
	@MAP.each do |key,values|
		index=@MAP[key]['index']
		url=@MAP[key]['url']
		pip=@MAP[key]['ip']
		hosting=@MAP[key]['hosting']
		netname=@MAP[key]['netname']
		geoip=@MAP[key]['geoip']
		server=@MAP[key]['server']
		status=@MAP[key]['status']
		#rescode=@MAP[key]['rescode']
		site=key
		if @RPT_DB.key?(site)			
			link=@RPT_DB[site]['link'] if @RPT_DB.key?(site)
			f.puts "<tr>"
			f.puts "<td>#{index}</td><td>#{url}</td><td>#{link}</td><td>#{pip}</td><td>#{hosting}</td><td>#{netname}</td><td>#{geoip}</td><td>#{server}</td><td>#{status}</td>"
			f.puts "</tr>"
		else
			f.puts "<tr>"
			f.puts "<td>#{index}</td><td>#{url}</td><td>TBD</td><td></td><td></td><td></td><td></td><td></td>"
			f.puts "</tr>"
		end
	end
	f.puts "</table><p>"
	f.puts "<i><b>Further Info & Feedback</b>: Please contact the Barclays Application Security team at <a href='mailto:GRBApplicationSecurity@barclayscorp.com'>GRBApplicationSecurity@barclayscorp.com</a> for further information and / or any feedback. <p>"
	f.puts "<b>Barclays Internal Only</b>: Please restrict the report data from the public distribution outside of the Barclays.</i> "
	f.puts "</body></html>"
end
