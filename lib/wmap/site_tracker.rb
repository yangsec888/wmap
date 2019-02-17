#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "parallel"
require "singleton"
require "nokogiri"


# Main class to automatically track the site inventory
class Wmap::SiteTracker
	include Wmap::Utils
	include Singleton

	attr_accessor :sites_file, :max_parallel, :verbose, :data_dir
	attr_reader :known_sites

	# Set default instance variables
	def initialize (params = {})
		# Initialize the instance variables
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@file_sites=@data_dir+'sites'
		@file_stores=params.fetch(:sites_file, @file_sites)
		@verbose=params.fetch(:verbose, false)
		@max_parallel=params.fetch(:max_parallel, 30)
		# Hash table to hold the site store
		File.write(@file_stores, "") unless File.exist?(@file_stores)
		@known_sites=load_site_stores_from_file(@file_stores)
	end

	# Setter to load the known hosts into an instance variable
	def load_site_stores_from_file (file)
		puts "Loading the site store data repository from file: #{file} " if @verbose
		begin
			known_sites=Hash.new
			f=File.open(file, 'r')
			f.each do |line|
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				entry=line.split(%r{\t+|\,})
				site=entry[0].downcase
				ip=entry[1]
				port=entry[2]
				status=entry[3]
				server=entry[4]
				res=entry[5].to_i
				fp=entry[6]
				loc=entry[7]
				timestamp=entry[8]
				puts "Loading entry: #{site} - #{ip} - #{status}" if @verbose
				known_sites[site]= Hash.new unless known_sites.key?(site)
				known_sites[site]['ip']=ip
				known_sites[site]['port']=port
				known_sites[site]['status']=status
				known_sites[site]['server']=server
				known_sites[site]['code']=res
				known_sites[site]['md5']=fp
				known_sites[site]['redirection']=loc
				known_sites[site]['timestamp']=timestamp
			end
			f.close
			puts "Successfully loading file: #{file}" if @verbose
			return known_sites
		rescue => ee
			puts "Exception on method #{__method__} for file #{file}: #{ee}"
		end
	end

	# Save the current site store hash table into a file
	def save_sites_to_file!(file_sites=@file_stores)
		puts "Saving the current site store table from memory to file: #{file_sites}"
		begin
			timestamp=Time.now
			f=File.open(file_sites, 'w')
			f.write "# Local site store created by class #{self.class} method #{__method__} at: #{timestamp}\n"
			f.write "# Website,Primary IP,Port,Hosting Status,Server,Response Code,MD5 Finger-print,Redirection,Timestamp\n"
			@known_sites.keys.sort.map do |key|
				f.write "#{key},#{@known_sites[key]['ip']},#{@known_sites[key]['port']},#{@known_sites[key]['status']},#{@known_sites[key]['server']},#{@known_sites[key]['code']},#{@known_sites[key]['md5']},#{@known_sites[key]['redirection']},#{@known_sites[key]['timestamp']}\n"
			end
			f.close
			puts "site store table is successfully saved: #{file_sites}"
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end
	alias_method :save!, :save_sites_to_file!

	# Count numbers of entries in the site store table
	def count
		puts "Counting number of entries in the site store table ..."
		begin
			return @known_sites.size
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# Setter to add site entry to the cache one at a time
	def add(site)
		puts "Add entry to the site store: #{site}"
		begin
			# Preliminary sanity check
			site=site.strip.downcase unless site.nil?
			raise "Site is already exist. Skip #{site}" if site_known?(site)
			site=normalize_url(site) if is_url?(site)
			site=url_2_site(site) if is_url?(site)
			puts "Site in standard format: #{site}" if @verbose
			raise "Exception on method #{__method__}: invalid site format of #{site}. Expected format is: http://your_website_name/" unless is_site?(site)
			trusted=false
			host=url_2_host(site)
			ip=host_2_ip(host)
			# Additional logic to refresh deactivated site, 02/12/2014
			deact=Wmap::SiteTracker::DeactivatedSite.new(:data_dir=>@data_dir)
			# only trust either the domain or IP we know
			if is_ip?(host)
				trusted=Wmap::CidrTracker.new(:data_dir=>@data_dir).ip_trusted?(ip)
			else
				root=get_domain_root(host)
				if root.nil?
					raise "Invalid web site format. Please check your record again."
				else
					trusted=Wmap::DomainTracker.instance.new(:data_dir=>@data_dir).domain_known?(root)
				end
			end
			# add record only if trusted
			if trusted
				# Add logic to check site status before adding it
				checker=Wmap::UrlChecker.new(:data_dir=>@data_dir).check(site)
				raise "Site is currently down. Skip #{site}" if checker.nil?
				# Skip the http site if it's un-responsive; for the https we'll keep it because we're interested in analysing the SSL layer later
				if is_https?(site)
					# do nothing
				else
					raise "Site is currently down. Skip #{site}" if checker['code']==10000
				end
				raise "Exception on add method - Fail to resolve the host-name: Host - #{host}, IP - #{ip}. Skip #{site}" unless is_ip?(ip)
				my_tracker = Wmap::HostTracker.instance(:data_dir=>@data_dir)
				# Update the local host table when necessary
				if is_ip?(host)
					# Case #1: Trusted site contains IP
					if my_tracker.ip_known?(host)
						# Try local reverse DNS lookup first
						puts "Local hosts table lookup for IP: #{ip}" if @verbose
						host=my_tracker.local_ip_2_host(host)
						puts "Host found from the local hosts table for #{ip}: #{host}" if @verbose
						site.sub!(/\d+\.\d+\.\d+\.\d+/,host)
					else
						# Try reverse DNS lookup over Internet as secondary precaution
						puts "Reverse DNS lookup for IP: #{ip}" if @verbose
						host1=ip_2_host(host)
						puts "host1: #{host1}" if @verbose
						if is_fqdn?(host1)
							if Wmap::HostTracker.instance(:data_dir=>@data_dir).domain_known?(host1)
								# replace IP with host-name only if domain root is known
								puts "Host found from the Internet reverse DNS lookup for #{ip}: #{host1}" if @verbose
								host=host1
								site.sub!(/\d+\.\d+\.\d+\.\d+/,host)
							end
						end
					end
					# Adding site for Case #1
					raise "Site already exist! Skip #{site}" if @known_sites.key?(site)
					puts "Adding site: #{site}" if @verbose
					@known_sites[site]=Hash.new
					@known_sites[site]=checker
					if deact.site_known?(site)
						deact.delete(site)
						deact.save!
					end
					puts "Site entry loaded: #{checker}"
					if is_fqdn?(host)
					# Add logic to update the hosts table for case #1 variance
					# -  case that reverse DNS lookup successful
						puts "Update local hosts table for host: #{host}"
						if my_tracker.host_known?(host)
							old_ip=my_tracker.local_host_2_ip(host)
							if old_ip != ip
								my_tracker.refresh(host)
								my_tracker.save!
							else
								puts "Host resolve to the same IP #{ip} - no need to update the local host table." if @verbose
							end
						else
							my_tracker.add(host)
							my_tracker.save!
						end
					end
				else
					# Case #2: Trusted site contains valid FQDN
					puts "Ading site: #{site}" if @verbose
					@known_sites[site]=Hash.new
					@known_sites[site]=checker
					if deact.site_known?(site)
						deact.delete(site)
						deact.save!
					end
					puts "Site entry loaded: #{checker}"
					# Add logic to update the hosts table for case #2
					puts "Update local hosts table for host: #{host}"
					if my_tracker.host_known?(host)
						old_ip=my_tracker.local_host_2_ip(host)
						if old_ip != ip
							my_tracker.refresh(host)
							my_tracker.save!
						else
							# Skip - no need to update the local hosts table
						end
					else
						my_tracker.add(host)
						my_tracker.save!
					end
				end
				deact=nil
				my_tracker=nil
				return checker
			else
				puts "Problem found: untrusted Internet domain or IP. Skip #{site}"
				deact=nil
				my_tracker=nil
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			deact=nil
			return nil
		end
	end

	# Setter to add site entry to the cache table in batch (from a file)
	def file_add(file)
		puts "Add entries to the local site store from file: #{file}"
		begin
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			changes=Hash.new
			sites=file_2_list(file)
			changes=bulk_add(sites) unless sites.nil? or sites.empty?
			puts "Done loading file #{file}. "
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
		end
	end

	# Setter to add site entry to the cache in batch (from a list)
	def bulk_add(list,num=@max_parallel)
		puts "Add entries to the local site store from list:\n #{list}"
		#begin
			results=Hash.new
			if list.size > 0
				puts "Start parallel adding on the sites:\n #{list}"
				Parallel.map(list, :in_processes => num) { |target|
					add(target)
				}.each do |process|
					if process.nil?
						next
					elsif process.empty?
						#do nothing
					else
						results[process['url']]=Hash.new
						results[process['url']]=process
					end
				end
				@known_sites.merge!(results)
			else
				puts "Error: no entry is added. Please check your list and try again."
			end
			puts "Done adding site entries."
			if results.size>0
				puts "New entries added: #{results}"
			else
				puts "No new entry added. "
			end
			return results
		#rescue => ee
			#puts "Exception on method #{__method__}: #{ee}" if @verbose
		#end
	end
	alias_method :adds, :bulk_add

	# Setter to remove entry from the site store one at a time
	def delete(site)
		puts "Remove entry from the site store: #{site} " if @verbose
		begin
			# Additional logic to deactivate the site properly, by moving it to the DeactivatedSite list, 02/07/2014
			deact=Wmap::SiteTracker::DeactivatedSite.new(:data_dir=>@data_dir)
			site=site.strip.downcase
			site=url_2_site(site)
			if @known_sites.key?(site)
				site_info=@known_sites[site]
				deact.add(site,site_info)
				deact.save!
				deact=nil
				del=@known_sites.delete(site)
				puts "Entry cleared: #{site}"
				return del
			else
				puts "Entry not fund. Skip #{site}"
				deact=nil
				return nil
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			deact=nil
		end
	end
	alias_method :del, :delete

	# Setter to delete site entry to the cache in batch (from a file)
	def file_delete(file)
		begin
			puts "Delete entries to the local site store from file: #{file}" if @verbose
			raise "File non-exist. Please check your file path and name again: #{file}" unless File.exist?(file)
			sites=file_2_list(file)
			changes=Array.new
			changes=bulk_delete(sites) unless sites.nil? or sites.empty?
		rescue => ee
			puts "Exception on method file_delete: #{ee} for file: #{file}" if @verbose
		end
	end
	alias_method :file_del, :file_delete

	# Setter to delete site entry to the cache in batch (from a list)
	def bulk_delete(list)
		puts "Delete entries to the local site store from list:\n #{list}" if @verbose
		begin
			sites=list
			changes=Array.new
			if sites.size > 0
				sites.map do |x|
					x=url_2_site(x)
					site=delete(x)
					changes.push(site) unless site.nil?
				end
				puts "Done deleting sites from the list:\n #{list}"
				return changes
			else
				puts "Error: no entry is loaded. Please check your list and try again."
			end
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :dels, :bulk_delete

	# Setter to refresh the entry in the site store one at a time
	def refresh(site)
		puts "Refresh the local site store for site: #{site} "
		begin
			raise "Invalid site: #{site}" if site.nil? or site.empty?
			site=site.strip.downcase
			if @known_sites.key?(site)
				delete(site)
				site_info=add(site)
				puts "Done refresh entry: #{site}"
				return site_info
			else
				puts "Error entry non exist: #{site}"
			end
			return nil
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# 'Refresh sites in the site store in batch (from a file)
	def file_refresh(file)
		puts "Refresh entries in the site store from file: #{file}" if @verbose
		begin
			changes=Hash.new
			sites=file_2_list(file)
			changes=bulk_refresh(sites) unless sites.nil? or sites.empty?
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee} for file: #{file}" if @verbose
		end
	end

	# 'Refresh unique sites in the site store only
	def refresh_uniq_sites
		puts "Refresh unique site entries in the site store. " if @verbose
		begin
			changes=Hash.new
			sites=get_uniq_sites
			if sites.size > 0
				changes=bulk_refresh(sites)
			else
				puts "Error: no entry is refreshed. Please check your site store and try again."
			end
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# 'Refresh sites in the site store in batch (from a list)
	def bulk_refresh(list,num=@max_parallel)
		puts "Refresh entries in the site store from list:\n #{list}" if @verbose
		begin
			results=Hash.new
			if list.size > 0
				puts "Start parallel refreshing on the sites:\n #{list}"
				Parallel.map(list, :in_processes => num) { |target|
					refresh(target)
				}.each do |process|
					if process.nil?
						next
					elsif process.empty?
						#do nothing
					else
						results[process['url']]=Hash.new
						results[process['url']]=process
					end
				end
				# Clean up old entries, by Y.L. 03/30/2015
				list.map {|x| @known_sites.delete(x)}
				# Add back fresh entries
				@known_sites.merge!(results)
				puts "Done refresh sites."
			else
				puts "Error: no entry is loaded. Please check your list and try again."
			end
			return results
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :refreshs, :bulk_refresh


	# Refresh all site entries in the stores in one shot
	def refresh_all
		puts "Refresh all the entries within the local site store ... "
		begin
			changes=Hash.new
			changes=bulk_refresh(@known_sites.keys)
			@known_sites.merge!(changes)
			puts "Done refresh all entries."
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Refresh all site entries in the stores that contains an IP instead of a hostname
	def refresh_ip_sites
		puts "Refresh all entries that contain an IP address instead of a FQDN ... "
		begin
			sites=get_ip_sites
			live_sites=sites.delete_if { |x| @known_sites[x]['code'] == 10000 or  @known_sites[x]['code'] == 20000 }
			changes=Hash.new
			changes=bulk_refresh(live_sites)
			@known_sites.merge!(changes)
			puts "Done refresh IP sites."
			return changes
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Quick validation if a site is already covered under the site store
	def site_known?(site)
		begin
			raise "Web site store not loaded properly! " if @known_sites.nil?
			site=site.strip.downcase unless site.nil?
			site=url_2_site(site)
			return @known_sites.key?(site) unless site.nil?
		rescue => ee
			puts "Error checking web site #{site} against the site store: #{ee}"
		end
		return false
	end
	alias_method :is_known?, :site_known?

	# Quick validation check on an IP is already part of the site store
	def site_ip_known?(ip)
		begin
			ip=ip.chomp.strip
			known=false
			if is_ip?(ip)
				@known_sites.keys.map do |site|
					if @known_sites[site]['ip']==ip
						return true
					end
				end
			end
			myDis=nil
			return known
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			return false
		end
	end
	alias_method :siteip_known?, :site_ip_known?

	# Quick check of the stored information of a site within the store
	def site_check(site)
		begin
			raise "Web site store not loaded properly! " if @known_sites.nil?
			site=site.strip.downcase unless site.nil?
			site=url_2_site(site)
			return @known_sites[site] unless site.nil?
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			return nil
		end
	end
	alias_method :check, :site_check

	# Retrieve external hosted sites into a list
	def get_ext_sites
		puts "getter to retrieve all the external hosted sites. " if @verbose
		begin
			sites=Array.new
			@known_sites.keys.map do |key|
				if @known_sites[key]['status']=="ext_hosted"
					sites.push(key)
				end
			end
			sites.sort!
			return sites
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :get_ext, :get_ext_sites

	# Retrieve a list of internal hosted site URLs
	def get_int_sites
		puts "getter to retrieve all the internal hosted sites." if @verbose
		begin
			sites=Array.new
			@known_sites.keys.map do |key|
				if @known_sites[key]['status']=="int_hosted"
					sites.push(key)
				end
			end
			sites.sort!
			return sites
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :get_int, :get_int_sites

	# Retrieve a list of sites that contain an IP in the site URL
	def get_ip_sites
		puts "Getter to retrieve sites contain an IP instead of a host-name ." if @verbose
		begin
			sites=Array.new
			@known_sites.keys.map do |key|
				host=url_2_host(key)
				if is_ip?(host)
					sites.push(key)
				end
			end
			sites.sort!
			return sites
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve a list of unique sites within the known site store
	def get_uniq_sites
		puts "Getter to retrieve unique sites containing unique IP:PORT key identifier." if @verbose
		begin
			#primary_host_tracker=Wmap::HostTracker::PrimaryHost.instance
			sites=Hash.new
			#uniqueness=Hash.new
			my_tracker=Wmap::HostTracker.instance(:data_dir=>@data_dir)
			@known_sites.keys.map do |key|
				port=url_2_port(key).to_s
				host=url_2_host(key)
				md5=@known_sites[key]['md5']
				code=@known_sites[key]['code']
				ip=my_tracker.local_host_2_ip(host)
				ip=host_2_ip(host) if ip.nil?
				# filtering out 'un-reachable' sites
				next if (code == 10000 or code == 20000)
				# filtering out 'empty' sites
				next if (md5.nil? or md5.empty?)
				next if ip.nil?
				# url_new=key
				#if primary_host_tracker.ip_known?(ip)
				#	p_host=primary_host_tracker.known_hosts[ip]
				#	url_new=key.sub(host,p_host)
				#end
				id=ip+":"+port
				# filtering out duplicates by 'IP:PORT' key pair
				unless sites.key?(id)
					#if @known_sites.key?(key)
					#	sites[id]=url_new
					#else
						# Further filtering out redundant site by checking MD5 finger-print
						#unless uniqueness.key?(md5)
							sites[id]=key
						#	uniqueness[md5]=true
						#end
					#end
				end
			end
			#primary_host_tracker=nil
			my_tracker=nil
			return sites.values
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :uniq_sites, :get_uniq_sites

	# Retrieve a list of sites that contain an IP in the site URL
	def get_ssl_sites
		puts "getter to retrieve https sites from the site store." if @verbose
		begin
			sites=Array.new
			@known_sites.keys.map do |key|
				key =~ /https/i
				sites.push(key)
			end
			sites.sort!
			return sites
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve a list of redirection URLs from the site store
	def get_redirection_urls
		puts "getter to retrieve all the redirection URLs from the site store." if @verbose
		begin
			urls=Array.new
			@known_sites.keys.map do |key|
				unless @known_sites[key]['redirection'].nil?
					urls.push(@known_sites[key]['redirection'])
				end
			end
			urls.sort!
			return urls
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Retrieve redirection URL if available
	def get_redirection_url (site)
		puts "getter to retrieve the redirection URL from the site store." if @verbose
		begin
			site=site.strip.downcase
			if @known_sites.key?(site)
				return @known_sites[site]['redirection']
			else
				puts "Unknown site: #{site}" if @verbose
				return nil
			end
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Perform local host table reverse lookup for the IP sites, in hope that the hostname could now be resolved since the site was discovered
	def resolve_ip_sites
		puts "Resolve sites that contain an IP address. Update the site cache table once a hostname is found in the local host table." if @verbose
		begin
			updates=Array.new
			sites=get_ip_sites
			my_tracker=Wmap::HostTracker.instance(:data_dir=>@data_dir)
			sites.map do |site|
				puts "Work on resolve the IP site: #{site}" if @verbose
				ip=url_2_host(site)
				hostname=my_tracker.local_ip_2_host(ip)
				if hostname.nil?
					puts "Can't resolve #{ip} from the local host store. Skip #{site}" if @verbose
				else
					puts "Host-name found for IP #{ip}: #{hostname}" if @verbose
					updates.push(site)
					refresh(site)
				end
			end
			updates.sort!
			puts "The following sites are now refreshed: #{updates}" if @verbose
			my_tracker=nil
			return updates
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Search potential matching sites from the site store by using simple regular expression. Note that any upper-case char in the search string will be automatically converted into lower case
	def search (pattern)
		puts "Search site store based on the regular expression: #{pattern}" if @verbose
		begin
			pattern=pattern.strip.downcase
			results=Array.new
			@known_sites.keys.map do |key|
				if key =~ /#{pattern}/i
					results.push(key)
				end
			end
			return results
		rescue Exception => ee
			puts "Exception on method search: #{ee}" if @verbose
			return nil
		end
	end

	# Print summary report on all sites that contain an IP in the site URL
	def print_ip_sites
		puts "Print sites contain an IP instead of a host-name."
		sites=get_ip_sites
		sites.map { |x| puts x }
		puts "End of report. "
	end

	# Retrieve and print specific information of a site in the site store
	def print_site(site)
		puts "Site Information Report for: #{site}" if @verbose
		begin
			site=site.strip unless site.nil?
			raise "Unknown site: #{site}" unless @known_sites.key?(site)
			ip=@known_sites[site]['ip']
			port=@known_sites[site]['port']
			status=@known_sites[site]['status']
			server=@known_sites[site]['server']
			fp=@known_sites[site]['md5']
			loc=@known_sites[site]['redirection']
			res=@known_sites[site]['code']
			timestamp=@known_sites[site]['timestamp']
			puts "#{site},#{ip},#{port},#{status},#{server},#{res},#{fp},#{loc},#{timestamp}"
		rescue => ee
			puts "Exception on method #{__method__} for #{site}: #{ee}"
		end
	end
	alias_method :print, :print_site


	# Print summary report of all sites URL in the site store
	def print_all_sites
		puts "\nSummary Report of the site store:"
		sites=@known_sites.keys.sort
		sites.each do |site|
			puts site
		end

		puts "End of the summary"
		#return sites
	end
	alias_method :print_all, :print_all_sites

	# Retrieve and save unique sites information for the quarterly scan into a plain local file
	def save_uniq_sites(file)
		puts "Save unique sites information into a flat file: #{file}\nThis may take a long while as it go through a lengthy self correction check process, please be patient ..."
		begin
			prime_sites=get_prim_uniq_sites
			puts "Primary Sites: #{prime_sites}" if @verbose
			f=File.open(file,"w")
			f.write "Unique Sites Information Report\n"
			f.write "Site, IP, Port, Server, Hosting, Response Code, MD5, Redirect, Timestamps\n"
			prime_sites.map do |key|
				next if key.nil?
				site=key.strip
				raise "Unknown site: #{site}. You may need to add it into the site store first. Execute the following shell command before trying again: \n\wadd #{site}\n" unless @known_sites.key?(site)
				ip=@known_sites[site]['ip']
				port=@known_sites[site]['port']
				status=@known_sites[site]['status']
				server=@known_sites[site]['server']
				fp=@known_sites[site]['md5']
				loc=@known_sites[site]['redirection']
				res=@known_sites[site]['code']
				timestamp=@known_sites[site]['timestamp']
				f.write "#{site},#{ip},#{port},#{server},#{status},#{res},#{fp},#{loc},#{timestamp}\n"
			end
			f.close
			puts "Done!"
			return true  # success
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			return false # fail
		end
	end
	alias_method :dump, :save_uniq_sites

	# Retrieve and save unique sites information for the quarterly scan into a XML file
	def save_uniq_sites_xml(file)
		puts "Save unique sites information into XML file: #{file}\nThis may take a long while as it go through lengthy self correctness check, please be patient ..."
		begin
			prime_sites=get_prim_uniq_sites
			builder = Nokogiri::XML::Builder.new do |xml|
				xml.root {
					xml.websites {
						prime_sites.each do |key|
							next if key.nil?
							site=key.strip
							raise "Unknown site: #{site}. You may need to add it into the site store first. Execute the following shell command before trying again: \n\twmap #{site}\n" unless @known_sites.key?(site)
							xml.site {
								xml.name site
								xml.ip_ @known_sites[site]['ip']
								xml.port_ @known_sites[site]['port']
								xml.status_ @known_sites[site]['status']
								xml.server_ @known_sites[site]['server']
								xml.fingerprint_ @known_sites[site]['md5']
								xml.redirection_ @known_sites[site]['redirection']
								xml.responsecode_ @known_sites[site]['code']
								xml.timestamp_ @known_sites[site]['timestamp']
							}
						end
					}
				}
			end
			puts builder.to_xml if @verbose
			f=File.new(file,'w')
			f.write(builder.to_xml)
			f.close
			puts "Done!"
			return true
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}"
			return false
		end
	end
	alias_method :dump_xml, :save_uniq_sites_xml

	# Retrieve the unique sites from the local site store in the primary host format
	def get_prim_uniq_sites
		puts "Retrieve and prime unique sites in the site store. " if @verbose
		#begin
			host_tracker=Wmap::HostTracker.instance(:data_dir=>@data_dir)
			primary_host_tracker=Wmap::HostTracker::PrimaryHost.instance(:data_dir=>@data_dir)
			# Step 1. Retrieve the unique site list first
			sites=get_uniq_sites
			prim_uniq_sites=Array.new
			# Step 2. Iterate on the unique site list, spit out the site in the primary host format one at a time
			sites.map do |site|
				puts "Work on priming unique site: #{site}" if @verbose
				host=url_2_host(site)
				# case#1, for the IP only site, do nothing (presuming 'refresh_ip_sites' or 'refresh_all' method already take care of the potential discrepancy here).
				if is_ip?(host)
					prim_uniq_sites.push(site)
					next
				end
				ip=@known_sites[site]['ip']
				# case#2, for site with an unique IP, do nothing
				puts "Local hosts table entry count for #{ip}: #{host_tracker.alias[ip]}" if @verbose
				if host_tracker.alias[ip] == 1
					prim_uniq_sites.push(site)
					next
				end
				# case#3, case of multiple IPs for A DNS record, where the site IP may have 0 alias count, do nothing
				if host_tracker.alias[ip] == nil
					prim_uniq_sites.push(site)
					next
				end
				# case#4, for the site has a duplicate IP with others, we try to determine which one is the primary site
				# raise "Error: inconsistency detected on record: #{site}. Please run the following shell command to refresh it first: \n\srefresh #{site}" if tracker1.alias[ip].nil?
				if ( primary_host_tracker.known_hosts.key?(ip) and (host_tracker.alias[ip] > 1) )
					new_host=primary_host_tracker.prime(host)
					puts "Host: #{host}, New host:#{new_host}" if @verbose
					unless host==new_host
						new_site=site.sub(host,new_host)
						raise "Site not found in the site tracking data repository: #{new_site}. You may need to add it into the site store first. Execute the following shell command before trying again: \n\twadd #{new_site}\n" unless @known_sites.key?(new_site)
						new_ip=@known_sites[new_site]['ip']
						if new_ip==ip		# consistency check
							site=new_site
						else
							# TBD - case of multiple IPs for A DNS record
							#raise "Inconsistency found on prime host entrance: #{new_ip}, #{ip}; #{new_site}, #{site}. Please refresh your entries by running the following shell command: \n\s refresh #{new_site}"
						end
					end
				end
				prim_uniq_sites.push(site)
			end
			primary_host_tracker=nil
			host_tracker=nil
			return prim_uniq_sites
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}"
		#end
	end
	alias_method :get_prime, :get_prim_uniq_sites

	# Print summary report of external hosted sites URL in the
	def print_ext_sites
		puts "\nSummary Report of the External Hosted Site"
		sites=get_ext_sites
		sites.each do |site|
			puts site
		end
		return nil
	end
	alias_method :print_ext, :print_ext_sites

	# Print summary report of internal hosted site URLs
	def print_int_sites
		puts "\nSummary Report of the Internal Hosted Site"
		sites=get_int_sites
		sites.each do |site|
			puts site
		end
		return nil
	end
	alias_method :print_int, :print_int_sites

	# Print summary report of internal hosted site URLs
	def print_ssl_sites
		puts "\nSummary Report of the HTTPS Sites from the Site Store"
		sites=get_ssl_sites
		sites.each do |site|
			puts site
		end
		return nil
	end

	# Print summary report of unique sites in the site store
	def print_uniq_sites
		puts "Summary Report for the Unique sites:"
		puts "Website,Primary IP,Port,Hosting Status,Server,Response Code,Site MD5 Finger-print,Site Redirection,Timestamp"
		sites=get_uniq_sites
		sites.each do |site|
			print_site(site)
		end
	end

	private

end
