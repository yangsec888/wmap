#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "netaddr"

# Class to track host/IP to the known (trusted) network CIDR blocks
class Wmap::CidrTracker
	include Wmap::Utils

	attr_accessor :cidr_seeds, :verbose, :known_cidr_blks, :data_dir

	# Set class default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		@file_cidr_seeds=params.fetch(:cidr_seeds, @data_dir + 'cidrs')
		@known_cidr_blks={}
		@known_cidr_blks_desc_index=[]
		@known_cidr_blks_asce_index=[]
		File.write(@file_cidr_seeds, "") unless File.exist?(@file_cidr_seeds)
		load_cidr_blks_from_file(@file_cidr_seeds)
	end

	# Main worker method to retrieve known network information for a host / ip
	def cidr_worker (host)
		puts "Starting tracking of known CIDR information for host: #{host}" if @verbose
		begin
			host=host.strip.downcase
			ip=host_2_ip(host)
			cidr=cidr_lookup(ip)
			ref=get_cidr_ref(cidr)
			netname=get_cidr_netname(cidr)
			# save the data
			tracker=Hash.new
			tracker['host']=host
			tracker['ip']=ip
			tracker['cidr']=cidr
			tracker['ref']=ref
			tracker['netname']=netname
			return tracker
		rescue => ee
			puts "Exception on method #{__method__} for host #{host}: #{ee}" # if @verbose
			return nil
		end
	end
	alias_method :track, :cidr_worker

	# 'setter' to load the known CIDR blocks into an instance variable @known_cidr_blks
	def load_cidr_blks_from_file (file_cidrs=@file_cidr_seeds)
		puts "Load the known CIDR seed file: #{file_cidrs}" if @verbose
		begin
			f=File.open(file_cidrs, 'r')
			f.each do |line|
				entry=line.chomp.split(',')
				next unless is_cidr?(entry[0])
				puts "Loading: #{entry[0]}" if @verbose
				key=entry[0].strip
				@known_cidr_blks[key] = Hash.new if not @known_cidr_blks.key?(key)
				@known_cidr_blks[key]['ref']=entry[1].nil? ? nil : entry[1].strip
				@known_cidr_blks[key]['netname']=entry[2].nil? ? nil : entry[2].strip
			end
			f.close
			# Sort the blocks in order once for better performance. Update 10/29/2018 to support Netaddr 2.x syntax
			#@known_cidr_blks_desc_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>true)
			#@known_cidr_blks_asce_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>false)
			@known_cidr_blks_asce_index=@known_cidr_blks.keys.sort
			@known_cidr_blks_desc_index=@known_cidr_blks_asce_index.reverse
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" # if @verbose
		end
	end

	# 'setter' to add an entry to CIDR store @known_cidr_blks
	def add (cidr,ref=nil,netname=nil)
		puts "Load the entry into the CIDR store: #{cidr}"
		#begin
			raise "Unknown CIDR format: #{cidr}" unless is_cidr?(cidr)
			# Obtain the 'ref' and 'netname' value automatically in case not passed as method parameters
			if ref.nil? or netname.nil?
				whois = Wmap::Whois.new
				# Note 11/1/2014: Use IP instead of the CIDR to perform the query, as the current ruby-whois query does not support CIDR as query input
				ip=cidr.split("/")[0]
				ref=whois.get_net_desc(ip)
				netname=whois.get_netname(ip)
				whois=nil
			end
			if @known_cidr_blks.key?(cidr)
				puts "Skip! Entry is already exist: #{cidr}"
				return nil
			else
				@known_cidr_blks[cidr] = Hash.new
				@known_cidr_blks[cidr]['ref']=ref
				@known_cidr_blks[cidr]['netname']=netname
				puts "Entry loaded!"
			end
			# Re-sort the blocks in order for better performance
			#@known_cidr_blks_desc_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>true)
			#@known_cidr_blks_asce_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>false)
			@known_cidr_blks_asce_index=@known_cidr_blks.keys.sort
			@known_cidr_blks_desc_index=@known_cidr_blks_asce_index.reverse
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}" # if @verbose
		#end
	end

	# 'setter' to remove an entry to CIDR store @known_cidr_blks
	def delete (cidr,ref=nil,netname=nil)
		puts "Remove the entry from the CIDR store: #{cidr}"
		begin
			#cidr.strip!
			raise "Unknown CIDR format: #{cidr}" unless is_cidr?(cidr)
			if @known_cidr_blks.key?(cidr)
				puts "Deleting ..."
				@known_cidr_blks.delete(cidr)
				puts "Entry cleared!"
			else
				raise "Unknown CIDR entry: #{cidr}"
			end
			# Re-sort the blocks in order for better performance
			#@known_cidr_blks_desc_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>true)
			#@known_cidr_blks_asce_index=NetAddr.sort(@known_cidr_blks.keys, :Desc=>false)
			@known_cidr_blks_asce_index=@known_cidr_blks.keys.sort
			@known_cidr_blks_desc_index=@known_cidr_blks_asce_index.reverse
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" # if @verbose
		end
	end
	alias_method :del, :delete

	# Count numbers of CIDR object entries in the CIDR cache table
	def count
		puts "Counting number of entries in the CIDR cache table ..." if @verbose
		begin
			cnt=0
			@known_cidr_blks.keys.map do |key|
				if is_cidr?(key)
					cnt=cnt+1
				end
			end
			puts "Current number of CIDR object entries: #{cnt}" if @verbose
			return cnt
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Count numbers of IPs within the trusted CIDR objects
	def counts
		puts "Counting number of IPs within the CIDR store:" if @verbose
		begin
			cnt=0
			@known_cidr_blks.keys.map do |key|
				cnt=cnt+size(key)
			end
			puts "Total number of trusted IPs: #{cnt}" if @verbose
			return cnt
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Check if the specific IP within the range of a list of known CIDR blocks
	def ip_trusted? (ip)
		puts "Check if the IP within the range of the known CIDR blocks: #{ip}" if @verbose
		known = false
		begin
			return false if @known_cidr_blks==nil
			first_octet_ip = ip.split('.').first.to_i
			@known_cidr_blks_desc_index.each do |line|
				first_octet_blk = line.split('.').first.to_i
				next if first_octet_blk > first_octet_ip
				cidr4 = NetAddr::CIDR.create(line)
				known = cidr4.contains?(ip+'/32')
				break if known
			end
		rescue => ee
			if @verbose
				puts "Exception on method #{__method__}: #{ee}"
			end
			return false
		end
		return known
	end
	alias_method :is_trusted?, :ip_trusted?

	# Return the matching CIDR block for a ip
	def cidr_lookup (ip)
		puts "Lookup the CIDR name from the known CIDR list for the IP: #{ip}" if @verbose
		begin
			return nil if @known_cidr_blks==nil
			puts "CIDR Lookup: #{ip} ..." if @verbose
			@known_cidr_blks_desc_index.each do |line|
				first_octet_ip = ip.split('.').first.to_i
				first_octet_blk = line.split('.').first.to_i
				next if first_octet_blk > first_octet_ip
				cidr4 = NetAddr::CIDR.create(line)
				known = cidr4.contains?(ip+'/32')
				return line if known
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
		return nil
	end
	alias_method :lookup, :cidr_lookup
	alias_method :query, :cidr_lookup

	# Determine if a CIDR entry is already known
	def cidr_known? (cidr)
		puts "Determine if the CIDR is known: #{cidr}" if @verbose
		known=false
		cidr=cidr.strip unless cidr.nil?
		cidr=cidr+"/32" if is_ip?(cidr)
		begin
			raise "Invalid CIDR format: #{cidr}" unless is_cidr?(cidr)
			return false if @known_cidr_blks==nil
			return true if @known_cidr_blks.key?(cidr)
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return false
		end
		return known
	end
	alias_method :is_known?, :cidr_known?

	# Determine if a cidr is within the range of our known network CIDR blocks
	def cidr_trusted? (cidr)
		puts "Determine if the CIDR within our ranges: #{cidr}" if @verbose
		trusted=false
		cidr=cidr.strip unless cidr.nil?
		cidr=cidr+"/32" if is_ip?(cidr)
		begin
			raise "Invalid CIDR format: #{cidr}" unless is_cidr?(cidr)
			return false if @known_cidr_blks==nil
			return true if @known_cidr_blks.key?(cidr)
			@known_cidr_blks_asce_index.each do |line|
				cidr4 = NetAddr::CIDR.create(line)
				return true if cidr4.contains?(cidr)
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return false
		end
		return trusted
	end
	alias_method :is_trusted?, :cidr_trusted?

	# NetAddr wrapper to determine number of IPs within the CIDR object.
	def size (cidr)
		puts "Determine the size of CIDR object: #{cidr}" if @verbose
		begin
			raise "Invalid CIDR format: #{cidr}" unless is_cidr?(cidr)
			obj = NetAddr::CIDR.create(cidr)
			return obj.size.to_i
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve the CIDR reference text for tracking purpose, if it's a known CIDR entry
	def get_cidr_ref (cidr)
		puts "Lookup CIDR block #{cidr} reference text ..." if @verbose
		cidr=cidr.strip unless cidr.nil?
		return nil unless @known_cidr_blks.key?(cidr)
		return @known_cidr_blks[cidr]['ref']
	end

	# Retrieve the CIDR netname field for tracking purpose, if it's a known CIDR entry
	def get_cidr_netname (cidr)
		puts "Lookup CIDR block #{cidr} netname ..." if @verbose
		cidr=cidr.strip unless cidr.nil?
		return nil unless @known_cidr_blks.key?(cidr)
		return @known_cidr_blks[cidr]['netname']
	end

	# Save the current cidr hash table into a file
	def save_cidrs_to_file!(file_cidrs=@file_cidr_seeds)
		puts "Saving the current cidrs cache table from memory to file: #{file_cidrs} ..." if @verbose
		#begin
			timestamp=Time.now
			f=File.open(file_cidrs, 'w')
			f.write "# Local cidrs file created by Wmap::CidrTracker.save method at: #{timestamp}\n"
			f.write "Network CIDR, CIDR RIPE Reference Text, CIDR NETNAME\n"
			@known_cidr_blks_asce_index.map do |key|
				ref=get_cidr_ref(key)
				netname=get_cidr_netname(key)
				f.write "#{key},#{ref},#{netname}\n"
			end
			f.close
			puts "CIDR cache table is successfully saved: #{file_cidrs}"
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}" if @verbose
		#end
	end
	alias_method :save!, :save_cidrs_to_file!

	# Print summary report of a list of known CIDR blocks
	def print_known_cidr_blks
		puts "Print the known CIDR Netblocks in ascendant order" if @verbose
		puts "Network CIDR, RIPE Reference Text, NETNAME"
		@known_cidr_blks_asce_index.map do |key|
			ref=@known_cidr_blks[key]['ref']
			netname=@known_cidr_blks[key]['netname']
			puts "#{key}, #{ref}, #{netname}"
		end
		puts "End of the summary"
	end
	alias_method :inspect, :print_known_cidr_blks

	# Print summary report of a list of known CIDR blocks in the descendant order
	def print_known_cidr_blks_desc
		puts "\nIndex of known CIDR Net blocks in Descendant Order:"
		puts @known_cidr_blks_desc_index
		puts "End of the Index"
	end

	# Print summary report of a list of known CIDR blocks in the ascendant order
	def print_known_cidr_blks_asce
		puts "\nIndex of known CIDR Net blocks in Ascending  Order:"
		puts @known_cidr_blks_asce_index
		puts "End of the Index"
	end
	alias_method :print, :print_known_cidr_blks_asce

	private :load_cidr_blks_from_file

end
