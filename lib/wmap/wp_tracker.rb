#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "parallel"
#require "singleton"
require "open-uri"
require "open_uri_redirections"
require "nokogiri"
require "css_parser"


# Main class to automatically track the site inventory
class Wmap::WpTracker
	include Wmap::Utils
	#include Singleton

	attr_accessor :http_timeout, :max_parallel, :verbose, :sites_wp, :data_dir
  attr_reader :known_wp_sites
  # set hard stop limit of http time-out to 8 seconds, in order to avoid severe performance penalty for certain 'weird' site(s)
	Max_http_timeout=8000

  # WordPress checker instance default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
    wp_sites=@data_dir+'wp_sites'
    @file_wps=params.fetch(:sites_wp, wp_sites)
		@http_timeout=params.fetch(:http_timeout, 5000)
		@max_parallel=params.fetch(:max_parallel, 40)
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@log_file=@data_dir + "wp_checker.log"
    @known_wp_sites=load_from_file(@file_wps)
	end


  # 'setter' to load the known wordpress sites into an instance variable
	def load_from_file (file=@file_stores, lc=true)
		puts "Loading trusted file: #{file}"	if @verbose
		begin
			known_wp_sites=Hash.new
			f_wp_sites=File.open(file, 'r')
			f_wp_sites.each_line do |line|
				puts "Processing line: #{line}" if @verbose
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.downcase if lc==true
				entry=line.split(',')
				if known_wp_sites.key?(entry[0])
					next
				else
					if entry[1] =~ /yes/i
						known_wp_sites[entry[0]]=true
					else
						known_wp_sites[entry[0]]=false
					end
				end

			end
			f_wp_sites.close
			return known_wp_sites
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Save the current domain hash table into a file
	def save_to_file!(file_wps=@file_wps, wps=@known_wp_sites)
		puts "Saving the current wordpress site table from memory to file: #{file_wps} ..." if @verbose
		begin
			timestamp=Time.now
			f=File.open(file_wps, 'w')
			f.write "# Local wps file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
			f.write "# domain name, free zone transfer detected?\n"
			wps.keys.sort.map do |key|
				if wps[key]
					f.write "#{key}, yes\n"
				else
					f.write "#{key}, no\n"
				end
			end
			f.close
			puts "Domain cache table is successfully saved: #{file_wps}"
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :save!, :save_to_file!

  # 'setter' to add wordpress entry to the cache one at a time
	def add(url)
    begin
		  puts "Add entry to the local cache table: #{url}" if @verbose
      site=url_2_site(url)
			if @known_wp_sites.key?(site)
				puts "Site is already exist. Skipping: #{site}"
			else
				record=Hash.new
				if wp_readme?(site)
          record[site]=true
        elsif wp_css?(site)
          record[site]=true
        elsif wp_meta?(site)
          record[site]=true
        else
          record[site]=false
        end
				puts "Entry loaded: #{record}"
			end
      @known_wp_sites.merge!(record)
      return record
		rescue => ee
			#puts "Exception on method #{__method__}: #{ee}: #{url}" if @verbose
		end
	end

  # add wordpress site entries (from a sitetracker list)
	def refresh (num=@max_parallel)
    #begin
		  puts "Add entries to the local cache table from site tracker: " if @verbose
			results=Hash.new
			wps=Wmap::SiteTracker.new.known_sites.keys
			if wps.size > 0
				Parallel.map(wps, :in_processes => num) { |target|
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
				@known_wp_sites.merge!(results)
				puts "Done loading entries."
				return results
			else
				puts "Error: no entry is loaded. Please check your list and try again."
			end
			return results
		#rescue => ee
		#	puts "Exception on method #{__method__}: #{ee}" if @verbose
		#end
	end

  # Wrapper to use OpenURI method 'read' to return url body contents
	def read_url(url)
    begin
      puts "Wrapper to return the OpenURI object for url: #{url}" if @verbose
			url_object=open_url(url)
			html_body=url_object.read
      doc = Nokogiri::HTML(html_body)
      return doc
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}" if @verbose
      return nil
    end
	end

  # Wrapper for the OpenURI open method - create an open_uri object and return the reference upon success
	def open_url(url)
		#url_object = nil
		puts "Open url #{url} by creating an open_uri object. Return the reference upon success." if @verbose
		if url =~ /http\:/i
			# patch for allow the 'un-safe' URL redirection i.e. https://www.example.com -> http://www.example.com
			url_object = open(url, :allow_redirections=>:safe, :read_timeout=>Max_http_timeout/1000)
		elsif url =~ /https\:/i
			url_object = open(url,:ssl_verify_mode => 0, :allow_redirections =>:safe, :read_timeout=>Max_http_timeout/1000)
		else
			raise "Invalid URL format - please specify the protocol prefix http(s) in the URL: #{url}"
		end
		return url_object
  end

  # Wordpress detection checkpoint - readme.html
  def wp_readme?(site)
    readme_url=site + "/readme.html"
    k=Wmap::UrlChecker.new
    if k.response_code(readme_url) == 200
      k=nil
      doc=read_url(readme_url)
      title=doc.css('title')
      if title.to_s =~ /wordpress/i
        return true
      else
        return false
      end
    else
      k=nil
      return false
    end
  end

  # Wordpress detection checkpoint - install.css
  def wp_css?(site)
    css_url=site + "/wp-admin/css/install.css"
    k=Wmap::UrlChecker.new
    if k.response_code(css_url) == 200
      k=nil
      parser = CssParser::Parser.new
      parser.load_uri!(css_url)
      rule = parser.find_by_selector('#logo a')
      if rule.length >0
        if rule[0] =~ /wordpress/i
          return true
        end
      end
    else
      k=nil
      return false
    end
    return false
  end

  # Wordpress detection checkpoint - meta generator
  def wp_meta?(site)
    k=Wmap::UrlChecker.new
    if k.response_code(site) == 200
      k=nil
      doc=read_url(site)
      meta=doc.css('meta')
      if meta.to_s =~ /wordpress/i
        return true
      else
        return false
      end
    else
      k=nil
      return false
    end
  end

end
