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
		if host.strip.nil?
			puts "Error: empty record found. Please check your input and remove any empty line." if @verbose
			return nil
		else
			host=host.downcase.strip
		end
    # First order - search country code second level domain list
    root_domain = get_domain_root_by_ccsld(host)
    if root_domain.nil?
  		# Second order - search the country code top level domain list
      root_domain = get_domain_root_by_cctld(host)
      if root_domain.nil?
        # Third order - search top level domain list
        root_domain = get_domain_root_by_tlds(host)
        if root_domain.nil?
          # do nothing - no further search
        else
          return root_domain
        end
      else
        return root_domain
      end
    else
      return root_domain
    end
    puts "#{host} - the top level domain is unknown. Please check out your record #{root_domain} " if @verbose
    return nil
	#rescue => ee
	#	puts "Exception on method #{__method__}: #{ee}" if @verbose
	#	return nil
	end
	alias_method :get_root_domain, :get_domain_root
	alias_method :root_domain, :get_domain_root
	alias_method :domain_root, :get_domain_root
	alias_method :host_2_domain, :get_domain_root

  # get domain root by lookup Country Code Second Level Domain list
  def get_domain_root_by_ccsld(host)
    puts "First order search - domain root lookup by Country Code Second Level Domain list ..." if @verbose
    root_domain = nil
    dn = host.split(".")
    # Country code second level domain - loading once
		@ccsld=load_ccsld_from_file(File_ccsld) if @ccsld.nil?
    # search country code second level domain list
    if @ccsld.key?(dn.last)
      @ccsld[dn.last].each do |v|
        if ( v =~ /#{dn[dn.length-2]}/i )
          return dn[dn.length-3] + "." + dn[dn.length-2] + "." + dn.last
        end
      end
    end
    return root_domain
  #rescue => ee
	#	puts "Exception on method #{__method__}: #{ee}" if @verbose
	#	return nil
  end

  # get domain root by lookup Country Code Top Level Domain list
  def get_domain_root_by_cctld(host)
    puts "Second order search - domain root lookup by Country Code Top Level Domain list ..." if @verbose
    root_domain = nil
    dn = host.split(".")
    # Country code top-level domain list - loading once
    @cctld=file_2_hash(File_cctld) if @cctld.nil?
    # Generic Top Level Domain List - loading once
    @gtld=file_2_hash(File_gtld) if @gtld.nil?
    # Country code second level domain - loading once
		@ccsld=load_ccsld_from_file(File_ccsld) if @ccsld.nil?
    # search the country code top level domain list
    if @cctld.key?(dn.last)
      # reverse search of general top level domain
      if @gtld.key?(dn[dn.length-2])
        root_domain=dn[dn.length-3] + "." + dn[dn.length-2] + "." + dn.last
      else
        root_domain=dn[dn.length-2] + "." + dn.last
      end
    end
    return root_domain
  #rescue => ee
	#	puts "Exception on method #{__method__}: #{ee}" if @verbose
	#	return nil
  end

  # get domain root by lookup Top Level Domain list
  def get_domain_root_by_tlds(host)
    puts "Third order search - domain root lookup by Top Level Domain list ..." if @verbose
    root_domain = nil
    dn = host.split(".")
    # Comnplete Top Level Domain List - loading once
    @tlds=file_2_hash(File_tld) if @tlds.nil?
    # Country code top-level domain list - loading once
    @cctld=file_2_hash(File_cctld) if @cctld.nil?
    cc_found=false
    if @tlds.key?(dn.last)
      if @cctld.key?(dn[dn.length-2])
        cc_found=true
      end
      if cc_found
        root_domain=dn[dn.length-3] + "." + dn[dn.length-2] + "." + dn.last
      else
        root_domain=dn[dn.length-2] + "." + dn.last
      end
    end
    return root_domain
    #rescue => ee
  	#	puts "Exception on method #{__method__}: #{ee}" if @verbose
  	#	return nil
  end

	# 'setter' to parse and load the known country code second level domain table from the file
	# data structure example: {"uk" =>["co","plc"],"za"=>["mil","nom","org"]}
	def load_ccsld_from_file (file_ccsld)
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

	# Test a host string to see if it's a valid Internet root domain
	def is_domain_root? (domain)
	  puts "Validate the domain name is valid: #{domain}" if @verbose
		domain=domain.strip.downcase
		return domain == get_domain_root(domain)
	rescue => ee
		puts "Exception on method #{__method__} for #{domain}: #{ee}" if @verbose
		return false
	end
	alias_method :is_root_domain?, :is_domain_root?
	alias_method :is_domain?, :is_domain_root?
	alias_method :is_root?, :is_domain_root?

	# Function to retrieve the sub-domain from a Fully Qualified Domain Name(FQDN), for example, "www.secure.telegraph.co.uk" -> "secure.telegraph.co.uk"
	def get_sub_domain (host)
		puts "Retrieve sub-domain from host: #{host}" if @verbose
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
	alias_method :get_subdomain, :get_sub_domain

	# Function to print instance variable - General top level domain list
	def print_gtld
		puts @gtld
    return @gtld 
	end

	# Function to print instance variable - Country code top-level domain list
	def print_cctld
		puts @cctld
    return @cctld
	end

	# Function to print instance variable - Country code second-level domain list
	def print_ccsld
		puts @ccsld
    return @ccsld
	end

	private :load_ccsld_from_file

  end
 end
end
