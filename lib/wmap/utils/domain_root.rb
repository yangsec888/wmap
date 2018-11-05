#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++


module Wmap
 module Utils
  # Module to validate and retrieve the top or second level domain name from a host-name (FQDN).
  module DomainRoot
	extend self
	# Internet Domain Architecture Definitions
	File_ccsld=File.dirname(__FILE__)+'/../../../dicts/ccsld.txt'
	File_cctld=File.dirname(__FILE__)+'/../../../dicts/cctld.txt'
	File_gtld=File.dirname(__FILE__)+'/../../../dicts/gtld.txt'
  File_tld=File.dirname(__FILE__)+'/../../../dicts/tlds.txt'

	# Main function to retrieve the registered domain ('domain root' from the 'registrant' perspective) from a hostname, for example, "www.telegraph.co.uk" -> "telegraph.co.uk"
	def get_domain_root (host)
		puts "Retrieve the root domain for host: #{host}" if @verbose
		begin
      # Comnplete Top Level Domain List - loading once
      @tlds=file_2_hash(File_tld) if @tlds.nil?
			# Generic Top Level Domain List - loading once
			@gtld=file_2_hash(File_gtld) if @gtld.nil?
			# Country code top-level domain list - loading once
			@cctld=file_2_hash(File_cctld) if @cctld.nil?
			# Country code second level domain - loading once
			@ccsld=load_ccsld_from_file(File_ccsld) if @ccsld.nil?

			if host.strip.nil?
				puts "Error: empty record found. Please check your input and remove any empty line." if @verbose
				return nil
			else
				host=host.downcase.strip
			end
			found_tld=false
			found_cctld=false
			# search the  top level domain list first
			root_domain=""
			dn=host.split(".")
			if @tlds.key?(dn.last)
				cc_found=false
				if @cctld.key?(dn[dn.length-2])
					cc_found=true
				end
				if cc_found
					root_domain=dn[dn.length-3] + "." + dn[dn.length-2] + "." + dn.last
				else
					root_domain=dn[dn.length-2] + "." + dn.last
				end
				found_tld=true
			end
			# search the country code top level domain list secondly
			if @cctld.key?(dn.last)
				found=false
				# reverse search of general top level domain
				if @gtld.key?(dn[dn.length-2])
					found=true
				end
				# search country code second level domain list
				if @ccsld.key?(dn.last)
					@ccsld[dn.last].each do |v|
						if ( v =~ /#{dn[dn.length-2]}/i )
							found=true
							break
						end
					end
					# 1/8/2015: additional logic to handle invalid ccsld string: reserved gtld string
					#unless found
					#	if @gtld.key?(dn[dn.length-2])
					#		puts "Invalid ccsld: #{dn[dn.length-2]} for host: #{host}"
					#		return nil
					#	end
					#end
				end
				if found
					root_domain=dn[dn.length-3] + "." + dn[dn.length-2] + "." + dn.last
				else
					root_domain=dn[dn.length-2] + "." + dn.last
				end
				found_cctld=true
			end
			unless (found_tld or found_cctld)
				puts "#{host} - the top level domain is unknown. Please check out your record #{root_domain} " if @verbose
				return nil
			else
				puts "Domain root found: #{root_domain}" if @verbose
				return root_domain
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :get_root_domain, :get_domain_root
	alias_method :root_domain, :get_domain_root
	alias_method :domain_root, :get_domain_root
	alias_method :host_2_domain, :get_domain_root

	# 'setter' to parse and load the known country code second level domain table from the file
	# data structure example: {"uk" =>["co","plc"],"za"=>["mil","nom","org"]}
	def load_ccsld_from_file (file_ccsld)
		begin
			ccsld=Hash.new
			puts "Loading known country code second level domain list from file: #{file_ccsld}" if @verbose
			f=File.open(file_ccsld, 'r:ISO-8859-1:UTF-8')   # transcoded magic bit
			f.each do |line|
				next unless line =~ /^\s+\.\w/
				line=line.chomp.strip.downcase
				entry=line.split(' ')[0].split('.')
				if entry.length > 2
					key=entry.last
					ccsld[key] = Array.new if not ccsld.key?(key)
					val=entry[entry.length-2]
					#puts "Loading country code second level domain table with - Country code: #{key}, Second level domain: #{val}" if @verbose
					ccsld[key].push(val) unless key.nil?
				end
			end
			f.close
			# Sort the blocks once in descendant order once for better performance
			return ccsld
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Test a host string to see if it's a valid Internet root domain
	def is_domain_root? (domain)
		puts "Validate the domain name is valid: #{domain}" if @verbose
		begin
			domain=domain.strip.downcase
			return domain == get_domain_root(domain)
		rescue => ee
			puts "Exception on method #{__method__} for #{domain}: #{ee}" if @verbose
			return false
		end
	end
	alias_method :is_root_domain?, :is_domain_root?
	alias_method :is_domain?, :is_domain_root?
	alias_method :is_root?, :is_domain_root?

	# Function to retrieve the sub-domain from a Fully Qualified Domain Name(FQDN), for example, "www.secure.telegraph.co.uk" -> "secure.telegraph.co.uk"
	def get_sub_domain (host)
		puts "Retrieve sub-domain from host: #{host}" if @verbose
		begin
			subdomain=String.new
			host=host.strip.downcase
			domain=get_domain_root(host)
			record_h=host.split(".")
			record_d=domain.split(".")
			if (record_h.length - record_d.length) >= 2
				subdomain=record_h[record_h.length-record_d.length-1]+"."+domain
				puts "Sub domain found: #{subdomain}" if @verbose
				return subdomain
			else
				return nil
			end
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :get_subdomain, :get_sub_domain

	# Function to print instance variable - General top level domain list
	def print_gtld
		puts @gtld
	end

	# Function to print instance variable - Country code top-level domain list
	def print_cctld
		puts @cctld
	end

	# Function to print instance variable - Country code second-level domain list
	def print_ccsld
		puts @ccsld
	end

	private :load_ccsld_from_file

  end
 end
end
