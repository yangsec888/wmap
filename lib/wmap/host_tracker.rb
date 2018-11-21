#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "parallel"
#require "singleton"		# Implement singleton pattern to avoid race condition under parallel engine


# Class to handle the local host data repository file where lists of known hosts from discovery and past assessment efforts are stored
class Wmap::HostTracker
	#include Singleton
	include Wmap::Utils

	attr_accessor :hosts_file, :max_parallel, :verbose, :data_dir
	attr_reader :known_hosts, :alias

	# Instance default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		# Set default instance variables
		@file_hosts=@data_dir + 'hosts'
		file=params.fetch(:hosts_file, @file_hosts)
		@max_parallel=params.fetch(:max_parallel, 40)
		# Initialize the instance variables
		File.write(@file_hosts, "") unless File.exist?(@file_hosts)
		@known_hosts=load_known_hosts_from_file(file)
	end

	# Setter to load the known hosts from the local hosts file into a class instance
	def load_known_hosts_from_file (f_hosts=@file_hosts)
		#begin
			puts "Loading local hosts from file: #{f_hosts} ..." if @verbose
			known_hosts=Hash.new
			@alias = Hash.new
			f=File.open(f_hosts, 'r')
			f.each do |line|
				next unless line =~ /\d+\.\d+\.\d+\.\d+/
				entry=line.chomp.split(%r{\t+|\s+|\,})
				key=entry[0].downcase
				value=entry[1]
				puts "Loading key value pair: #{key} - #{value}" if @verbose
				known_hosts[key] = Hash.new unless known_hosts.key?(key)
				known_hosts[key]= value
				# For reverse host lookup
				known_hosts[value] = Hash.new unless known_hosts.key?(value)
				known_hosts[value] = key
				# Count the number of alias for the recorded IP
				if @alias.key?(value)
					@alias[value]+=1
				else
					@alias[value]=1
				end
			end
			f.close
			return known_hosts
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}"
		#	return known_hosts
		#end
	end

	# Save the current local hosts hash table into a (random) data repository file
	def save_known_hosts_to_file!(f_hosts=@file_hosts)
		#begin
			puts "Saving the local host repository from memory to file: #{f_hosts} ..."
			timestamp=Time.now
			f=File.open(f_hosts, 'w')
			f.write "# local hosts file created by the #{self.class} class #{__method__} method at: #{timestamp}"
			@known_hosts.keys.sort.map do |key|
				unless key =~ /\d+\.\d+\.\d+\.\d+/
					f.write "\n#{key}\t#{@known_hosts[key]}"
				end
			end
			f.close
			puts "local host repository is successfully saved to: #{f_hosts}"
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}"
		#end
	end
	alias_method :save!, :save_known_hosts_to_file!

	# Count numbers of entries in the local host repository
	def count
		puts "Counting number of entries in the local host repository ..."
		begin
			cnt=0
			@known_hosts.keys.map do |key|
				unless is_ip?(key)
					cnt=cnt+1
				end
			end
			puts "Current number of entries: #{cnt}"
			return cnt
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# Setter to add host entry to the cache once at a time
	def add(host)
		puts "Add entry to the local host repository: #{host}"
		#begin
			host=host.strip.downcase unless host.nil?
			unless @known_hosts.key?(host)
				ip=host_2_ip(host)
				record=Hash.new
				if is_ip?(ip)
					# filter host to known domains only
					root=get_domain_root(host)
					if Wmap::DomainTracker.new(:data_dir=>@data_dir).domain_known?(root)
						record[host]=ip
						record[ip]=host
						puts "Host data repository entry loaded: #{host} <=> #{ip}"
						# Replace instance with the class variable to avoid potential race condition under parallel engine
						# add additional logic to update the sub-domain table as well, 02/10/2014
						sub=get_sub_domain(host)
						if sub!=root
							tracker=Wmap::DomainTracker::SubDomain.new(:data_dir=>@data_dir)
							unless tracker.domain_known?(sub)
								tracker.add(sub)
								tracker.save!
							end
							tracker=nil
						end
						@known_hosts.merge!(record)
						return record
					else
						puts "Error - host #{host} has an untrusted internet root domain: #{root}\nPlease update the trusted domain seeds file first if necessary."
					end
				else
					puts "Problem resolve host #{host} - unknown IP: #{ip}"
				end
			else
				puts "Host is already exist. Skip: #{host}"
			end
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}" if @verbose
		#end
	end

	# Setter to add host entry to the local hosts in batch (from an array)
	def bulk_add(list, num=@max_parallel)
		#begin
			puts "Add entries to the local host repository: #{list}"
			results=Hash.new
			if list.size > 0
				puts "Start parallel host update processing on:\n #{list}" if @verbose
				Parallel.map(list, :in_processes => num) { |target|
					add(target)
				}.each do |process|
					if process.nil?
						next
					elsif process.empty?
						#do nothing
					else
						results.merge!(process)
					end
				end
				@known_hosts.merge!(results)
				puts "Done loading entries."
				return results
			else
				puts "Error: empty list - no entry is loaded. Please check your input list and try again."
			end
			return results
#		rescue => ee
#			puts "Exception on method #{__method__}: #{ee}"
#		end
	end
	alias_method :adds, :bulk_add

	# 'setter' to add host entry to the local hosts in batch (from a file)
	def file_add(file)
		begin
			puts "Add entries to the local host repository from file: #{file}"
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			hosts=file_2_list(file)
			changes=bulk_add(hosts)
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# 'setter' to remove entry from the local hosts one at a time
	def delete(host)
		puts "Remove entry from the local host repository: #{host} "
		begin
			host=host.strip.downcase
			if @known_hosts.key?(host)
				@known_hosts.delete(host)
				puts "Entry cleared."
				return host
			else
				puts "Entry not fund. Skip: #{host}"
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# 'setter' to delete host entry to the cache in batch (from an array)
	def bulk_delete(list)
		puts "Delete entries to the local host repository from:\n #{list}"
		begin
			hosts=list
			changes=Array.new
			if hosts.size > 0
				hosts.map do |x|
					host=delete(x)
					changes.push(host) unless host.nil?
				end
				puts "Done deleting hosts."
				return changes
			else
				puts "Error: empty list - no entry is loaded. Please check your list and try again."
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end
	alias_method :dels, :bulk_delete

	# Setter to delete host entries in the local hosts in batch (from a file)
	def file_delete(file)
		begin
			puts "Delete the local host repository entries from file: #{file}"
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			hosts=file_2_list(file)
			changes=bulk_delete(hosts)
			puts "Delete done."
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# Setter to refresh the entry from the cache one at a time
	def refresh(host)
		#begin
			puts "Refresh the local host repository for host: #{host} "
			host=host.strip.downcase
			if @known_hosts.key?(host)
				old_ip=@known_hosts[host]
				new_ip=host_2_ip(host)
				if is_ip?(new_ip)
					if old_ip==new_ip
						puts "No change for the host entry: #{host}\t#{old_ip}"
						return nil
					else
						@known_hosts[host]=new_ip
						@known_hosts[new_ip]=host
						puts "Entry refreshed: #{host}\t#{@known_hosts[host]}"
						return host
					end
				else
					puts "Host can no longer be resolved in the Internet. Entry removed: #{host}\t#{@known_hosts[host]}"
					@known_hosts.delete(host)
					return host
				end
			else
				puts "Error entry non exist: #{host}"
			end
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}"
		#end
	end

	#	Refresh all the entries in the local hosts by querying the Internet
	def refresh_all
		puts "Refresh all the entries in the local host repository in one shot."
		#begin
			changes=Hash.new
			hosts=@known_hosts.keys
			@known_hosts=Hash.new
			changes=bulk_add(hosts)
			@known_hosts.merge!(changes)
			#@known_hosts.keys.map do |key|
			#	unless is_ip?(key)
			#		host=refresh(key)
			#		changes.push(host) unless host.nil?
			#	end
			#end
			puts "\n#{changes.size} Entries Refreshed:" if changes.size>0
			#changes.map { |x| puts x }
			puts "Done refreshing the local hosts."
			return changes
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}"
		#end
	end

	# Extract known root domains from the local host repository @known_hosts
	def get_root_domains
		puts "Dump out all active root domains from the cache."
		begin
			zones=Array.new
			(@known_hosts.keys-["",nil]).map do |hostname|
				next if is_ip?(hostname)
				hostname = hostname.strip
				zone = get_domain_root(hostname)
				zones.push(zone) unless zone.nil?
			end
			zones.uniq!.sort!
			return zones
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end
	alias_method :dump_root_domains, :get_root_domains

	# Extract hostname without the root domain part from the @known_hosts. Data can be used for statistics study.
	def get_a_records
		puts "Dump out all known A records from the local hosts."
		begin
			records=Array.new
			(@known_hosts.keys-["",nil]).map do |hostname|
				next if is_ip?(hostname)
				hostname = hostname.strip
				root = get_domain_root(hostname)
				record = hostname.sub('.'+root,'')
				records.push(record) unless record.nil?
			end
			records.sort!
			return records
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end
	alias_method :dump_a_records, :get_a_records

	# Print summary report on the cache
	def print_known_hosts
		puts "\nSummary of local hosts Table:"
		puts "Total entries: #{@known_hosts.size}"
		(@known_hosts.keys.sort-["",nil]).each do |key|
			value=@known_hosts[key]
			puts "#{key}\t#{value}" if is_fqdn?(key)
		end
		puts "End of the summary"
	end
	alias_method :print_all, :print_known_hosts

	# Print summary report on the cache
	def print_host(host)
		puts "Local host store entry for #{host}"
		begin
			host.strip!
			raise "Invalid input: #{host}" unless is_fqdn?(host)
			if @known_hosts.key?(host)
				value=@known_hosts[host]
				puts "#{host}\t#{value}"
			else
				puts "Unknown host in the local store: #{host}"
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end
	alias_method :print, :print_host

	# Check if the specific IP within @known_hosts table
	def ip_known? (ip)
		known = false
		begin
			ip=ip.strip unless ip.nil?
			return false if @known_hosts==nil
			return @known_hosts.key?(ip.strip)
		rescue => ee
			if @verbose
				puts "IP Lookup Error: #{ee}"
			end
			return false
		end
		return known
	end
	alias_method :has_a_record?, :ip_known?

	# Check if the specific host within @known_hosts table
	def host_known? (host)
		begin
			host=host.strip.downcase unless host.nil?
			return false if @known_hosts==nil
			return @known_hosts.key?(host.strip)
		rescue => ee
			if @verbose
				puts "Host Lookup Error: #{ee}"
			end
			return false
		end
	end
	alias_method :is_known?, :host_known?

	# Perform reverse DNS lookup on the local host repository. Not to confuse with the reverse DNS lookup from the Internet
	def local_ip_2_host (ip)
		puts "Reverse DNS lookup from the local host repository" if @verbose
		begin
			ip=ip.strip unless ip.nil?
			if @known_hosts.key?(ip)
				return @known_hosts[ip]
			else
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
		return nil
	end

	# Perform DNS lookup on the local host repository. Not to confuse with the DNS lookup from the Internet
	def local_host_2_ip (host)
		puts "DNS lookup from the local host repository" if @verbose
		begin
			host=host.strip unless host.nil?
			if @known_hosts.key?(host)
				return @known_hosts[host]
			else
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			return nil
		end
	end

	# Extract a list of sub-domains from the local host repository @known_hosts
	def dump_sub_domains
		puts "Dump out all active sub domains from the local hosts." if @verbose
		begin
			subs=Array.new
			@known_hosts.keys.each do |hostname|
				next if is_ip?(hostname)
				hostname = hostname.strip
				sub = get_subdomain(hostname)
				subs.push(sub) unless sub.nil?
			end
			subs.uniq!.sort!
			puts "Found sub domains: #{subs}" if @verbose
			return subs
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}"
			return subs
		end
	end
	alias_method :get_sub_domains, :dump_sub_domains

	# Based on the current host store, to determine if an entry is a known sub-domain
	def sub_domain_known?(domain)
		puts "Validate sub-domain: #{domain}" if @verbose
		begin
			domain=domain.strip.downcase
			subs=dump_sub_domains
			return subs.include?(domain)
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# Search potential matching sites from the host store by using simple regular expression. Note that any upper-case char in the search string will be automatically converted into lower case
	def search (pattern)
		puts "Search host store based on the regular expression: #{pattern}" if @verbose
		begin
			pattern=pattern.strip.downcase
			results=Array.new
			@known_hosts.keys.map do |key|
				if key =~ /#{pattern}/i
					results.push(key)
				end
			end
			return results
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}"
			return nil
		end
	end
	alias_method :find, :search

	# Search local host repository and return a list of aliases for the host
	def host_aliases (host)
		puts "Search aliases in the local hosts data repository for host: #{host}" if @verbose
		begin
			host.strip!
			raise "Unknown method input: #{host} We expect a FQDN host-name string from you. " unless is_fqdn?(host)
			aliases=Array.new
			if @known_hosts.key?(host)
				ip=local_host_2_ip(host)
				@known_hosts.keys.map do |key|
					my_ip=local_host_2_ip(key)
					if ip == my_ip
						aliases.push(key)
					end
				end
			else
				raise "Unknown host-name in the local hosts data repository: #{host}"
			end
			return aliases-[host]
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}"
			return nil
		end
	end
	alias_method :aliases, :host_aliases

	# Top hostname - sort out most common host-name in the host store in descendant order
	def top_hostname (num)
		puts "Sort the host store for the most common hostname. " if @verbose
		h=Hash.new
		host_store=Hash.new
		top=Array.new
		begin
			# Build a host table from the host file
			f=File.open(@file_hosts, 'r')
			f.each do |line|
				next unless line =~ /\d+\.\d+\.\d+\.\d+/
				# skip the domain roots in the host list
				next if is_domain_root?(line.chomp)
				entry=line.chomp.split(%r{\t+|\s+|\,})
				key=entry[0].downcase
				value=entry[1]
				puts "Loading key value pair: #{key} - #{value}" if @verbose
				host_store[key] = Hash.new unless known_hosts.key?(key)
				host_store[key]= value
			end
			f.close
			host_store.keys.map do |key|
				host=key.split('.')
				if h.key?(host[0])
					h[host[0]]+=1
				else
					h[host[0]]=1
				end
			end
			result = h.keys.sort { |a,b| h[b] <=> h[a] } # Sort by value descendantly
			num = result.size if result.size < num
			for i in 0...num
				top.push(result[i])
			end
			return top
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}"
			return nil
		end
	end

	private :load_known_hosts_from_file
end
