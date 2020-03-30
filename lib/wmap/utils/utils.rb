#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++

require "resolv"
require "netaddr"

# Main utility module to provide the common functions across different classes
module Wmap
  module Utils
	include Wmap::Utils::DomainRoot
	include Wmap::Utils::UrlMagic
	include Wmap::Utils::Logger
	extend self

	# Load entries from a text file and return an array
	def file_2_list(f,lc=true)
		puts "Loading records from file: #{f}" if @verbose
		begin
			list=Array.new
			file = File.open(f, "r")
			file.each_line do |line|
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.downcase if lc==true
				list.push(line.chomp.strip)
			end
			file.close
			return list
		rescue => ee
			puts "Exception on method #{__method__} for file #{f}: #{ee}" if @verbose
			return nil
		end
	end

	# Save an array into a file
	def list_2_file (list,file)
		puts "Save list #{list} to plain file #{file}" if @verbose
		begin
			f = File.open(file, "w")
			list.map do |ent|
				#ent.strip!
				# Append the unix line break
				f.write("#{ent}\n")
			end
			f.close
		rescue => ee
			puts "Exception on method #{__method__} for file #{file}: #{ee}" if @verbose
			return nil
		end
	end

	# Load entries from a text file and return a hash
	def file_2_hash(f,lc=true)
		puts "Loading records from file: #{f}" if @verbose
		begin
			hs=Hash.new
			file = File.open(f, "r")
			file.each_line do |line|
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				line=line.downcase if lc==true
				next if line =~ /^\s*#/
				hs[line]=true unless hs.key?(line)
			end
			file.close
			return hs
		rescue => ee
			puts "Exception on method #{__method__} on #{f}: #{ee}" if @verbose
			return nil
		end
	end

	# Query the name-server to see if the dns record is still valid
	def valid_dns_record? (hostname)
		puts "Validate the hostname record: #{hostname}" if @verbose
		begin
			ips=Resolv.getaddresses(hostname)
			if ips.empty?
				return false
			else
				puts "Found: #{hostname}" if @verbose
				return true
			end
		rescue => ee
			puts "Exception on method #{__method__} for host #{hostname}: #{ee}" if @verbose
			return false
		end
	end
	alias_method :is_record? , :valid_dns_record?
	alias_method :a_record? , :valid_dns_record?

	# Test the DNS server if zone transfer is allowed. If allowed, save the found hosts into the class variable.
	def zone_transferable?(domain)
		puts "Check if the domain allows free zone transfer: #{domain}"
		begin
			transferable=false
			domain=domain.downcase
			nameservers = get_nameservers(domain)
			raise "Unable to determine the name servers for domain #{domain}" if nameservers.nil?
			puts "Retrieved name servers: #{nameservers}" if @verbose
			nameservers.each do |nssrv|
				begin
					puts "Attempt zone transfer on name server: #{nssrv}"
					if nssrv.nil?
						abort "Method input variable error: no name server found!" if @verbose
						next
					end
					zt = Dnsruby::ZoneTransfer.new
					zt.server=(nssrv) if nssrv!=""
					records = zt.transfer(domain)
					if records==nil
						puts "#{domain} zone transfer is not allowed on name server: #{nssrv}"
						next
					else
						puts "#{domain} zone transfer is allowed!"
						transferable=true
					end
				rescue Exception=>ee
					puts "Exception on method zone_transferable? for domain #{domain}: #{ee}"
				end
			end
			return transferable
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return false
		end
	end

	# Test if it's a legitimate IP4 address
	def is_ip? (ip)
		puts "Validate the IP format is valid: #{ip}" if @verbose
		begin
			ip=ip.strip
			raise "This is an URL: #{ip}" if is_url?(ip)
			if ip =~ /\d+\.\d+\.\d+.\d+/ and ip !~ /\/\d+/
				octs=ip.split('.')
				return false unless octs.size==4
				octs.map { |x| return false unless x.to_i >=0 and x.to_i <=255 }
			else
				return false
			end
			puts "Confirmed as a valid IP: #{ip}" if @verbose
			return true
		rescue => ee
			puts "Exception on method is_ip? for #{ip}: #{ee}" if @verbose
			return false
		end
	end
	alias_method :is_valid_ip?, :is_ip?

	# Simple test a host string format. Return true if it contains a valid internet domain sub-string. Note: Don't be confused with another method 'valid_dns_record?', which is a stricter and time-consuming test on the DNS server for a resolvable internet host.
	def is_fqdn? (host)
		puts "Validate the host-name format is valid: #{host}" if @verbose
		return false if is_ip?(host) or is_url?(host)
		domain=get_domain_root(host)
		if domain.nil?
			return false
		elsif is_domain_root?(domain)
			return true
		else
			return false
		end
#	rescue => ee
#		puts "Exception on method is_fqdn? for #{host}: #{ee}" if @verbose
#		return false
	end
	alias_method :is_host?, :is_fqdn?

	# Simple test to determine if the entry is in valid network cidr format
	def is_cidr?(cidr)
		puts "Validate if the entry is valid CIDR format: #{cidr}" if @verbose
		begin
		cidr=cidr.strip
			if cidr =~  /^(\d+\.\d+\.\d+.\d+)\/(\d+)$/
				ip=$1
				mask=$2.to_i
				if is_ip?(ip)
					if mask >0 and mask <=32
						puts "confirmed as a valid CIDR entry: #{cidr}" if @verbose
						return true
					else
						return false
					end
				else
					return false
				end
			else
				return false
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return false
		end
	end

	# Sort an array of IPs in the ascendant order
	def sort_ips (ips)
		begin
			"Sort the list of IP address in the ascendant order: #{ips}" if @verbose
			return NetAddr.sort(ips)
		rescue => ee
			puts "Exception on method sort_ips for IPs #{ips}: #{ee}" # if @verbose
		end
	end

	# Perform the DNS query on a hostname over the Internet. Return the resolved IP(s) in an array
	def host_2_ips (hostname)
		begin
			ips=Array.new
			if is_ip?(hostname)
				ips.push(hostname)
				return ips
			else
				ips = Resolv.getaddresses(hostname)
				if (ips.empty?) then
					puts "Failed to resolve #{hostname}" if @verbose
					return nil
				else
					return ips
				end
			end
		rescue => ee
			puts "Exception on method host_2_ips for host #{hostname}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :ns_lookup, :host_2_ips

	# Perform DNS query on a hostname.  Return the first resolved IP as a string
	def host_2_ip (hostname)
		puts "Perform DNS query on host: #{hostname}" if @verbose
		begin
			ips=Array.new
			if is_ip?(hostname)
				puts "No change - same IP is returned. " if @verbose
				return hostname.strip
			else
				ips=Resolv.getaddresses(hostname)
				if (ips.empty?) then
					puts "Failed to resolve #{hostname}" if @verbose
					return nil
				else
					puts "IP found: #{ips.first}" if @verbose
					return ips.first.strip
				end
			end
		rescue => ee
			puts "Exception on method host_2_ip for host #{hostname}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve a list of the authoritative name servers from the Internet whois data repository for the host / subdomain / domain
	def get_nameservers (host)
		puts "Retrieve a list of authoritative name server for: #{host}" if @verbose
		begin
			domain=get_domain_root(host)
			w=Wmap::Whois.new
			ns = w.query(domain).nameservers.map! { |x| x.name }
			if ns.empty?
				puts "No name server found for domain root: #{domain}" if @verbose
				return nil
			else
				return ns
			end
		rescue => ee
			puts "Exception on method get_nameservers for #{host}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve the first name server from the Internet whois data repository for the host / subdomain / domain
	def get_nameserver (host)
		puts "Retrieve the first authoritative name server for: #{host}" if @verbose
		begin
			domain=get_domain_root(host)
			w=Wmap::Whois.new
			ns = w.query(domain).nameservers.map! { |x| x.name }
			if ns.empty?
				puts "No name server found for domain root: #{domain}" if @verbose
				return nil
			else
				return ns.first
			end
		rescue => ee
			puts "Exception on method get_nameservers for #{host}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :get_ns, :get_nameserver

	# Perform reverse dns lookup for an IP. Return the found 'hostname' if found, or the original IP if not
	def reverse_dns_lookup (ip)
		puts "Retrieve the hostname by the reverse DNS lookup on IP: #{ip}"
		hostname = ip
		begin
			hostname = Socket.gethostbyaddr(ip.split('.').collect{ |x| x.to_i}.pack("CCCC"))[0]
			return hostname.downcase
		rescue => ee
			puts "Exception on method reverse_dns_lookup: #{ee}" if @verbose
			return hostname
		end
	end
	alias_method :ip_2_host, :reverse_dns_lookup

	# Convert a CIDR to a list of IPs:  Input is a CIDR expression such as '192.168.1.1/30', output is an array of IPs
	def cidr_2_ips (cidr)
		puts "Method to convert a CIDR block into a list of IPs: #{cidr}" if @verbose
		begin
			cidr4 = NetAddr::CIDR.create(cidr)
			ips = cidr4.enumerate(:Limit => 0, :Bitstep => 1)
			#ips2 = ips.slice!(1, (ips.length-2))
			return ips
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end



  end
end
