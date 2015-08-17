# Sample CIDR Tracker - Given a trusted IP, print out all tracked CIDR information  
# Usage: ruby sslscan_parser.rb [list of xml report] [file_target]
# version 0.2, Date 12/10/2014, by Yang Li
require "nokogiri"

@verbose=false
@ciphers=Hash.new

def parse_xml (xml)
	f = File.open(xml)
	doc = Nokogiri::XML(f)
	f.close
	return doc
end

def get_ciphers (doc)
	begin
		node=doc.css("ssltest")
		puts "#{node[0]['host']}, #{node[0]['port']}" if @verbose
		host=node[0]['host']
		port=node[0]['port']
		key=host+":"+port
		@ciphers[key]=Hash.new {|h,k| h[k]=Array.new} unless @ciphers.key?(key)
		cipher=node[0].css("cipher").select { |leaf| leaf["status"]=="accepted" }
		puts cipher if @verbose
		cipher.each do |line|
			puts "line: #{line}" if @verbose
			entry=line.to_s.chomp.split(' ')
			ssl_v=entry[2].gsub("\"","").gsub("sslversion=","")
			bits=entry[3].gsub("\"","").gsub("bits=","")
			cr=entry[4].gsub("\"","").gsub("\/\>","")
			suite=cr+"("+bits+" bits)"
			puts "suite: #{suite}" if @verbose
			@ciphers[key][ssl_v]<<suite
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" # if @verbose
	end
end

##################### Main #################
# 1. parsing all the sslscan xml reports in one short
f_rpts=File.open(ARGV[0], 'r')
f_rpts.each do |rpt|
	doc=parse_xml(rpt.chomp)
	ciphers=get_ciphers(doc)
end
f_rpts.close
puts @ciphers if @verbose

# 2. print the result in the desired order
f_targets=File.open(ARGV[1],'r')
f_targets.each do |line|
	target=line.chomp
	if @ciphers.key?(target)
		puts "#{target} | #{@ciphers[target]}"
	else
		puts target
	end
end
f_targets.close
