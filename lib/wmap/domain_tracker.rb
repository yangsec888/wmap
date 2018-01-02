#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "parallel"
#require "singleton"


# Class to track the known (trusted) Internet domains
class Wmap::DomainTracker
	include Wmap::Utils
	#include Singleton


	attr_accessor :verbose, :max_parallel, :domains_file, :file_domains
	attr_reader :known_internet_domains

	# Set default instance variables
	def initialize (params = {})
		# Initialize the instance variables
		@verbose=params.fetch(:verbose, false)
		@file_domains=params.fetch(:domains_file,File.dirname(__FILE__)+'/../../data/domains')
		@max_parallel=params.fetch(:max_parallel, 40)
		# Hash table to hold the trusted domains
		File.write(@file_domains, "") unless File.exist?(@file_domains)
		@known_internet_domains=load_domains_from_file(@file_domains)
		#@known_internet_sub_domains=Hash.new
	end

	# 'setter' to load the known Internet domains into an instance variable
	def load_domains_from_file (file=@file_domains, lc=true)
		puts "Loading trusted domain file: #{file}"	if @verbose
		begin
			known_internet_domains=Hash.new
			f_domains=File.open(file, 'r')
			f_domains.each_line do |line|
				puts "Processing line: #{line}" if @verbose
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.downcase if lc==true
				entry=line.split(',')
				if known_internet_domains.key?(entry[0])
					next
				else
					if entry[1] =~ /yes/i
						known_internet_domains[entry[0]]=true
					else
						known_internet_domains[entry[0]]=false
					end
				end

			end
			f_domains.close
			return known_internet_domains
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Save the current domain hash table into a file
	def save_domains_to_file!(file_domains=@file_domains, domains=@known_internet_domains)
		puts "Saving the current domains cache table from memory to file: #{file_domains} ..." if @verbose
		begin
			timestamp=Time.now
			f=File.open(file_domains, 'w')
			f.write "# Local domains file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
			f.write "# domain name, free zone transfer detected?\n"
			domains.keys.sort.map do |key|
				if domains[key]
					f.write "#{key}, yes\n"
				else
					f.write "#{key}, no\n"
				end
			end
			f.close
			puts "Domain cache table is successfully saved: #{file_domains}"
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :save!, :save_domains_to_file!

	# Count numbers of entries in the domain cache table
	def count
		puts "Counting number of entries in the domain cache table ..."
		begin
			cnt=0
			@known_internet_domains.map do |key|
				unless key =~ /\w+\.\w+/
					cnt=cnt+1
				end
			end
			puts "Current number of entries: #{cnt}"
			return cnt
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :size, :count

	# 'setter' to add domain entry to the cache one at a time
	def add(host)
		puts "Add entry to the local domains cache table: #{host}" if @verbose
		#begin
			host=host.strip.downcase
			if @known_internet_domains.key?(host)
				puts "Domain is already exist. Skipping: #{host}"
			else
				root=get_domain_root(host)
				sub=get_subdomain(host)
				record=Hash.new
				if host == root
					if zone_transferable?(root)
						record[root]=true
						#@known_internet_domains[root]=true
					else
						record[root]=false
						#@known_internet_domains[root]=false
					end
					puts "Entry loaded: #{record}"
					@known_internet_domains.merge!(record)
					return record
				elsif sub.nil?				# 2/10/2014, additional logic to support sub-domains
					# do nothing
				elsif host != sub
					if zone_transferable?(sub)
						#@known_internet_domains[sub]=true
						record[sub]=true
					else
						#@known_internet_domains[sub]=false
						record[sub]=false
					end
					puts "Entry loaded: #{record}"
					@known_internet_domains.merge!(record)
					return record
				else
					puts "Problem add domain #{host} - please use legal root domain or sub domain only."
				end
			end
		#rescue => ee
			#puts "Exception on method #{__method__}: #{ee}" if @verbose
		#end
	end

	# 'setter' to add domain entry to the cache in batch (from a file)
	def file_add(file)
		begin
			puts "Add entries to the local domains cache table from file: #{file}" if @verbose
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			changes=Array.new
			domains=file_2_list(file)
			changes=bulk_add(domains)
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# 'setter' to add domain entry to the cache in batch (from a list)
	def bulk_add(list, num=@max_parallel)
		puts "Add entries to the local domains cache table from list: #{list}" if @verbose
		begin
			results=Hash.new
			domains=list
			if domains.size > 0
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
				@known_internet_domains.merge!(results)
				puts "Done loading entries."
				return results
			else
				puts "Error: no entry is loaded. Please check your list and try again."
			end
			return results
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :adds, :bulk_add

	# 'setter' to remove entry from the cache one at a time
	def delete(domain)
		puts "Remove entry from the domains cache table: #{domain} " if @verbose
		begin
			domain=domain.strip.downcase
			if @known_internet_domains.key?(domain)
				@known_internet_domains.delete(domain)
				puts "Entry cleared: #{domain}"
				return domain
			else
				puts "Entry not fund. Skipping: #{domain}"
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# 'setter' to delete domain entry to the cache in batch (from a list)
	def bulk_delete(list)
		puts "Delete entries to the local domains cache table from list: #{list}" if @verbose
		begin
			domains=list
			changes=Array.new
			if domains.size > 0
				domains.map do |x|
					domain=delete(x)
					changes.push(domain) unless domain.nil?
				end
				puts "Done deleting domains from list: #{list}"
				return changes
			else
				puts "Exception on method bulk_delete: no entry is loaded. Please check your list and try again."
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :dels, :bulk_delete

	# 'setter' to delete domain entry to the cache in batch (from a file)
	def file_delete(file)
		begin
			puts "Delete entries to the local domains cache table from file: #{file}" if @verbose
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			domains=file_2_list(file)
			changes=bulk_delete(domains)
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# 'setter' to remove all entries from the store
	def delete_all
		puts "Delete all entries in the domain store! " if @verbose
		begin
			@known_internet_domains.keys.map do |domain|
				delete(domain)
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Refresh the domain entry one at a time
	def refresh(domain)
		begin
			abort "Trusted Internet domain file not loaded properly! " if @known_internet_domains.nil?
			domain=domain.strip.downcase unless domain.nil?
			if domain_known?(domain)
				delete(domain)
				add(domain)
				return domain
			else
				puts "Unknown domain: #{domain}"
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__} for #{domain}: #{ee}" if @verbose
			return nil
		end
	end

	# Simple method to check if a domain is already within the domain cache table
	def domain_known?(domain)
		begin
			#abort "Trusted Internet domain file not loaded properly! " if @known_internet_domains.nil? or @known_internet_sub_domains.nil?
			domain=domain.strip.downcase unless domain.nil?
			case self.class.name
			when "Wmap::DomainTracker"
				return @known_internet_domains.key?(domain)
			when "Wmap::DomainTracker::SubDomain"
				return @known_internet_sub_domains.key?(domain)
			else
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
		return false
	end
	alias_method :is_known?, :domain_known?
	alias_method :is_domain_known?, :domain_known?

	# Dump out the list of known domains
	def get_domains
		puts "Retrieve a list of known domain ..." if @verbose
		begin
			return @known_internet_domains.keys
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :dump_domains, :get_domains
	alias_method :dump, :get_domains

	# Search potential matching domains from the domain store by using simple regular expression. Note that any upper-case char in the search string will be automatically converted into lower case
	def search (pattern)
		puts "Search domain store for the regular expression: #{pattern}" if @verbose
		begin
			pattern=pattern.strip.downcase
			results=Array.new
			@known_internet_domains.keys.map do |key|
				if key =~ /#{pattern}/i
					results.push(key)
				end
			end
			return results
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :find, :search

	# Print summary report on all known / trust domains in the domain cache table
	def print_known_domains
		puts "\nSummary of known Internet Domains:"
		@known_internet_domains.keys.sort.each do |domain|
			puts domain
		end
		puts "End of the summary"
	end
	alias_method :print, :print_known_domains

	private :load_domains_from_file
end
