#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "parallel"
#require "singleton"


module Wmap
class SiteTracker

class WpTracker < Wmap::SiteTracker
	include Wmap::Utils
	include Wmap::Utils::WpDetect
	#include Singleton

	attr_accessor :http_timeout, :max_parallel, :verbose, :sites_wp, :data_dir
  attr_reader :known_wp_sites

  # WordPress checker instance default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
    	@sites_wp=params.fetch(:sites_wp, @data_dir+"wp_sites")
		@http_timeout=params.fetch(:http_timeout, 5000)
		@max_parallel=params.fetch(:max_parallel, 40)
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@log_file=@data_dir + "wp_checker.log"
		File.new(@sites_wp, "w") unless File.exist?(@sites_wp)
    	load_from_file(@sites_wp)
	end

  # 'setter' to load the known wordpress sites into an instance variable
	def load_from_file (file=@sites_wp, lc=true)
		puts "Loading trusted file: #{file}"	if @verbose
		@known_wp_sites=Hash.new
		f_wp_sites=File.open(file, 'r')
		f_wp_sites.each_line do |line|
			puts "Processing line: #{line}" if @verbose
			line=line.chomp.strip
			next if line.nil?
			next if line.empty?
			next if line =~ /^\s*#/
			line=line.downcase if lc==true
			entry=line.split(',')
			site = entry[0].strip()
			next if site.nil?
			if @known_wp_sites.key?(site)
				next
			else
				@known_wp_sites[site] = Hash.new
				@known_wp_sites[site]['site'] = site
				@known_wp_sites[site]['version'] = entry[1].strip()
				@known_wp_sites[site]['redirection'] = entry[2].strip()
			end
		end
		f_wp_sites.close
		return @known_wp_sites
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return Hash.new
	end

	# Save the current hash table into a file
	def save_to_file!(file_wps=@sites_wp, wps=@known_wp_sites)
		puts "Saving the current wordpress site table from memory to file: #{file_wps} ..." if @verbose
		timestamp=Time.now
		f=File.open(file_wps, 'w')
		f.write "# Local wps file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
		f.write "# WP Site URL, WP Version, Redirection \n"
		(wps.keys - [nil,'']).sort.map do |key|
			f.write "#{key}, #{wps[key]['version']}, #{wps[key]['redirection']}\n"
		end
		f.close
		puts "WordPress site cache table is successfully saved: #{file_wps}"
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
	end
	alias_method :save!, :save_to_file!

  # Add wordpress entry to the cache one at a time
	def add(url, use_cache=true)
	  puts "Add entry to the local cache table: #{url}" if @verbose
    site=url_2_site(url)
		if use_cache && @known_wp_sites.key?(site)
			puts "Site is already exist. Skipping: #{site}"
		else
			record=Hash.new
			redirection = landing_location(site)
			if not [nil, ''].include?(redirection)
				if is_wp?(redirection)
					version = wp_ver(redirection)
	        record['site'] = site
					record['version'] = version
					record['redirection'] = redirection
					@known_wp_sites[site]=record
					puts "Entry added: #{record}"
				end
			else
				if is_wp?(site)
					version = wp_ver(site)
					record['version'] = version
					record['redirection'] = redirection
					@known_wp_sites[site]=record
					puts "Entry added: #{record}"
				end
			end
		end
    return record
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}: #{url}" if @verbose
	end

	# Method to load wp sites in parallel
	def bulk_add(list,num=@max_parallel,use_cache=true)
		puts "Add entries to the local wp_site store from list:\n #{list}"
		results=Hash.new
		list = list - [nil,""]
		if list.size > 0
			puts "Start parallel adding on the sites:\n #{list}"
			Parallel.map(list, :in_processes => num) { |target|
				add(target,use_cache)
			}.each do |process|
				if process.nil?
					next
				elsif process.empty?
					next #do nothing
				else
					results[process['site']]=Hash.new
					results[process['site']]=process
				end
			end
			@known_wp_sites.merge!(results)
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
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
	end
	alias_method :adds, :bulk_add

	# Refresh one site entry then update the instance variable (cache)
	def refresh (target,use_cache=false)
		return add(target,use_cache)
	end

  # Refresh wordpress site entries within the sitetracker list
	def refreshs (num=@max_parallel,use_cache=false)
	  puts "Add entries to the local cache table from site tracker: " if @verbose
		results=Hash.new
		wps=@known_wp_sites.keys
		if wps.size > 0
			Parallel.map(wps, :in_processes => num) { |target|
				refresh(target,use_cache)
			}.each do |process|
				if process.nil?
					next
				elsif process.empty?
					#do nothing
				else
					site = process['site']
					results[site] = process
				end
			end
			@known_wp_sites.merge!(results)
			puts "Done loading wp entries."
			return results
		else
			puts "Error: no entry is loaded. Please check your list and try again."
		end
		wps=nil
		return results
	#rescue => ee
	#	puts "Exception on method #{__method__}: #{ee}" if @verbose
	#	return Hash.new
	end


end
end
end
