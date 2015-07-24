#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "whois"

# Wrapper class of the 'ruby-whois' library
class Wmap::Whois
	include Wmap::Utils
	
	attr_accessor :timeout, :verbose
	
	# Set default instance variables
	def initialize (params = {})		
		@verbose=params.fetch(:verbose, false)
		@timeout=params.fetch(:timeout, 10)
	end

	# Wrapper for the Ruby Whois client class
	def lookup(object)	
		puts "Perform whois lookup on: #{object}" if @verbose
		return Whois.lookup(object)
	end	
	alias_method :query, :lookup
	
	# Method to extract the netname information from the whois data repository query for an IP
	def get_netname (ip)
		puts "Perform whois lookup on an IP address. Then extract the netname from the query result for the IP: #{ip}" if @verbose
		begin 
			ip.strip!
			raise "Unknown IP/CIDR format: #{ip}" unless is_ip?(ip) or is_cidr?(ip)
			content_to_parse=query(ip).to_s
			if content_to_parse =~ /^netname:(.+)\n/i
				return $1.strip
			elsif content_to_parse =~ /^.+\((NET\-.+)\).+\n/i
				return $1.strip
			else
				return "UNKNOWN"
			end
			return "UNKNOWN"
		rescue Exception => ee
			puts "Exception on method get_netname: #{ee}" if @verbose
			return "UNKNOWN"		
		end
	end

	# Method to extract the netname description from the whois data repository query for an IP
	def get_net_desc (ip)
		puts "Perform whois lookup on an IP address. Then extract the netname description from the query result for the IP: #{ip}" if @verbose
		begin 
			ip.strip!
			raise "Unknown IP/CIDR format: #{ip}" unless is_ip?(ip) or is_cidr?(ip)
			desc=String.new
			content_to_parse=query(ip).to_s
			content_to_parse.scan(/^descr:(.+)\n/i).flatten.map do |entry|
				desc=desc + " " + entry.strip
			end
			if desc.empty?
				if content_to_parse =~ /^(.+)\((NET\-.+)\).+\n/i
					desc=$1.strip
				elsif content_to_parse =~ /^OrgName:(.+)\n/i
					desc=$1.strip
				else
					desc="UNKNOWN"
				end
			end
			return desc
		rescue Exception => ee
			puts "Exception on method get_net_desc: #{ee}" if @verbose
			return "UNKNOWN"		
		end
	end
end
