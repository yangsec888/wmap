#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "singleton"		# Implement singleton pattern to avoid race condition under parallel engine


module Wmap
  class HostTracker

	# Class to differentiate the primary host-name from the potential aliases. This is needed in order to minimize the confusion on our final site inventory list, as it contains a large number of duplicates (aliases). More specifically, a filter could be built by using this class to track the primary url of a website.
	class PrimaryHost < Wmap::HostTracker
		include Wmap::Utils
		include Singleton

		attr_accessor :hosts_file, :verbose, :data_dir, :known_hosts, :known_ips

		# Initialize the instance variables
		def initialize (params = {})
			@verbose=params.fetch(:verbose, false)
      @data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../../data/')
			# Set default instance variables
			@hosts_file=params.fetch(:hosts_file, @data_dir + 'prime_hosts')
			# Initialize the instance variables
      File.write(@hosts_file, "") unless File.exist?(@hosts_file)
			@known_hosts=load_known_hosts_from_file(@hosts_file)
			@known_ips=Hash.new
			de_duplicate
		end

		# Procedures to identify primary host-name from the site store SSL certificates. The assumption is that the CN used in the cert application must be primary hostname and used by the users.
		def update_from_site_store!
			#begin
        puts "Invoke internal procedures to update the primary host-name table from the site store."
        # Step 1 - update the prime host table based on the SSL cert CN fields
				cns=Hash.new
				checker=Wmap::UrlChecker.new(:data_dir=>@data_dir)
        my_tracker = Wmap::SiteTracker.instance
        my_tracker.sites_file = @data_dir + "sites"
        my_tracker.load_site_stores_from_file
				my_tracker.get_ssl_sites.map do |site|
					puts "Exam SSL enabled site entry #{site} ..."
					my_host=url_2_host(site)
					next if @known_hosts.key?(my_host) # add the logic to optimize the process
					puts "Pull SSL cert details on site: #{site}"
					cn=checker.get_cert_cn(site)
					unless cn.nil? or cns.key?(cn)
						cns[cn]=true
					end
				end
				cns.keys.map do |cn|
					if is_fqdn?(cn)
						next if @known_hosts.key?(cn)
						self.add(cn)
						puts "New entry added: #{cn}\t#{@known_hosts[cn]}"
					end
				end
				# Step 2 - Save the cache into the file
				self.save!
        checker=nil
        my_tracker=nil
			#rescue Exception => ee
			#	puts "Exception on method #{__method__}: #{ee}" if @verbose
      #  checker=nil
      #  my_tracker=nil
			#	return nil
			#end
		end
		alias_method :update!, :update_from_site_store!

		# Procedures to identify primary host-name from the site store redirection URLs. The assumption is that on site redirection, it must be directed to the well known primary site.
		def update_from_site_redirections!
			puts "Invoke internal procedures to update the primary host-name table from the site store."
			begin
				my_tracker=Wmap::SiteTracker.instance
        my_tracker.sites_file=@data_dir + "sites"
        my_tracker.load_site_stores_from_file
        urls = my_tracker.get_redirection_urls
        my_tracker = nil
				urls.map do |url|
					if is_url?(url)
						host=url_2_host(url)
						if is_fqdn?(host)
							ip=host_2_ip(host)
							# Add duplication check
							unless @known_hosts.key?(ip)
								self.add(host)
							end
						end
					end
				end
				self.save!
			rescue Exception => ee
				puts "Exception on method #{__method__}: #{ee}" if @verbose
				return nil
			end
		end

		# Procedures to remove the redundant entries in the primary hosts data repository
		def de_duplicate
			@known_hosts.keys.map do |key|
				ip=@known_hosts[key]
				if @known_ips.key?(ip)
					@known_hosts.delete(key)
				else
					@known_ips[ip]=true
				end
			end
		end
		alias_method :deduplicate, :de_duplicate

		# Method to replace hostname with known primary hostname
		def prime (host)
			begin
				raise "Unknown hostname format: #{host}" unless is_fqdn?(host)
				ip=local_host_2_ip(host)
				ip=host_2_ip(host) if ip.nil?
				if @known_ips.key?(ip)
					return @known_hosts[ip]
				end
				return host
			rescue Exception => ee
				puts "Exception on method #{__method__}: #{ee}" if @verbose
				return host
			end
		end

	end

  end
end
