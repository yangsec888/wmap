#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "singleton"


module Wmap
class DomainTracker

# Class to differentiate the sub-domain from the top domain for the enterprise. This is needed for better managing
# of the sub-domains and the associated entities
class SubDomain < Wmap::DomainTracker
	include Wmap::Utils
	include Singleton

	attr_accessor :verbose, :sub_domains_file, :max_parallel, :data_dir, :known_internet_sub_domains

	# Set default instance variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@max_parallel=params.fetch(:max_parallel, 40)
		# Hash table to hold the trusted domains
		@sub_domains_file=params.fetch(:sub_domains_file, @data_dir + 'sub_domains')
		File.new(@sub_domains_file, "w") unless File.exist?(@sub_domains_file)
		@known_internet_sub_domains=load_domains_from_file(@sub_domains_file) #unless @known_internet_sub_domains.size>0
	end

	# 'setter' to add sub-domain entry to the cache one at a time
	def add(sub)
		puts "Add entry to the local sub domain cache table: #{sub}" if @verbose
		record=Hash.new
		sub=sub.strip.downcase
		if @known_internet_sub_domains.key?(sub)
			puts "Skip on known sub-domain: #{sub}" if @verbose
			return nil
		end
		if zone_transferable?(sub)
			record[sub]=true
		else
			record[sub]=false
		end
		puts "Adding new record into the data store: #{record}" if @verbose
		@known_internet_sub_domains.merge!(record)
		return record
	rescue => ee
		puts "Exception on method #{__method__} for #{sub}: #{ee}" if @verbose
	end

	# 'setter' to add domain entry to the cache in batch (from a list)
	def bulk_add(list, num=@max_parallel)
		puts "Add entries to the local domains cache table from list: #{list}" if @verbose
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
			@known_internet_sub_domains.merge!(results)
			puts "Done loading sub_domain entries."
			return results
		else
			puts "Error: no entry is loaded. Please check your list and try again."
		end
		return results
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
	end
	alias_method :adds, :bulk_add

	# Procedures to identify sub-domain from the hosts store
	def update_from_host_store!
		puts "Invoke internal procedures to update the sub-domain list from the host store."
		# Step 1 - obtain the latest sub-domains
		my_tracker = Wmap::HostTracker.instance
		my_tracker.data_dir = @data_dir
		my_tracker.hosts_file = my_tracker.data_dir + "/" + "hosts"
		my_tracker.load_known_hosts_from_file(my_tracker.hosts_file)
		subs = my_tracker.dump_sub_domains - [nil,""]
		my_tracker = nil
		# Step 2 - update the sub-domain list
		unless subs.empty?
			#subs.map { |x| self.add(x) unless domain_known?(x) }
			self.bulk_add(subs,@max_parallel)
		end
		puts "Update discovered sub-domains into the store: #{@known_internet_sub_domains}"
		self.save!(file_domains=@file_sub_domains, domains=@known_internet_sub_domains)
	rescue Exception => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end
	alias_method :update!, :update_from_host_store!

	# Save the current domain hash table into a file
	def save_sub_domains_to_file!(file_domains=@file_sub_domains, domains=@known_internet_sub_domains)
		puts "Saving the current domains cache table from memory to file: #{file_domains} ..." if @verbose
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
	alias_method :save!, :save_sub_domains_to_file!

	# Print summary report on all known / trust domains in the domain cache table
	def print_known_sub_domains
		puts "\nSummary of known Internet Sub-domains:"
		self.known_internet_sub_domains.keys.sort.each do |domain|
			puts domain
		end
		puts "End of the summary"
	end

end
end
end
