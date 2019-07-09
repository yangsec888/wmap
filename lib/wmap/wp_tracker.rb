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

  # WordPress checker instance default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
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
			site = entry[0].strip()
			if known_wp_sites.key?(site)
				next
			else
				known_wp_sites[site] = Hash.new
				known_wp_sites[site]['site'] = site
				known_wp_sites[site]['version'] = entry[1].strip()
				known_wp_sites[site]['redirection'] = entry[2].strip()
			end

		end
		f_wp_sites.close
		return known_wp_sites
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return Hash.new
	end

	# Save the current hash table into a file
	def save_to_file!(file_wps=@file_wps, wps=@known_wp_sites)
		puts "Saving the current wordpress site table from memory to file: #{file_wps} ..." if @verbose
		timestamp=Time.now
		f=File.open(file_wps, 'w')
		f.write "# Local wps file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
		f.write "# WP Site URL, WP Version, Redirection \n"
		wps.keys.sort.map do |key|
			f.write "#{key}, #{wps[key]['version']}, #{wps[key]['redirection']}\n"
		end
		f.close
		puts "WordPress site cache table is successfully saved: #{file_wps}"
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
	end
	alias_method :save!, :save_to_file!

  # 'setter' to add wordpress entry to the cache one at a time
	def add(url, use_cache=true)
	  puts "Add entry to the local cache table: #{url}" if @verbose
    site=url_2_site(url)
		if use_cache && @known_wp_sites.key?(site)
			puts "Site is already exist. Skipping: #{site}"
		else
			record=Hash.new
			redirection = landing_location(site)
			if is_wp?(redirection)
				version = wp_ver(site)
        record['site'] = site
				record['version'] = version
				record['redirection'] = redirection
				@known_wp_sites[site]=record
				puts "Entry loaded: #{record}"
			end
		end
    return record
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}: #{url}" if @verbose
	end

  # logic to determin if it's a wordpress site
  def is_wp?(url)
		site=url_2_site(url)
		if wp_readme?(site)
			found=true
		elsif wp_css?(site)
			found=true
		elsif wp_meta?(site)
			found=true
		elsif wp_login?(site)
			found=true
		elsif wp_rpc?(site)
			found=true
		else
			found=false
		end
		return found
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}: #{url}" if @verbose
	end

	# Refresh one site entry then update the instance variable (cache)
	def refresh (target,use_cache=false)
		return add(target,use_cache)
	end

  # Refresh wordpress site entries within the sitetracker list
	def refreshs (num=@max_parallel,use_cache=false)
	  puts "Add entries to the local cache table from site tracker: " if @verbose
		results=Hash.new
		wps=Wmap::SiteTracker.instance.known_sites.keys
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
			puts "Done loading entries."
			return results
		else
			puts "Error: no entry is loaded. Please check your list and try again."
		end
		wps=nil
		return results
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return Hash.new
	end

  # Wordpress detection checkpoint - readme.html
  def wp_readme?(url)
		site = url_2_site(url)
    readme_url=site + "readme.html"
    k=Wmap::UrlChecker.new
    if k.response_code(readme_url) == 200
      k=nil
      doc=open_page(readme_url)
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
	rescue => ee
		puts "Exception on method #{__method__} for site #{url}: #{ee}" if @verbose
		return false
  end

  # Wordpress detection checkpoint - install.css
  def wp_css?(url)
		site = url_2_site(url)
    css_url = site + "wp-admin/css/install.css"
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
	rescue => ee
		puts "Exception on method #{__method__} for site #{url}: #{ee}" if @verbose
		return false
  end

  # Wordpress detection checkpoint - meta generator
  def wp_meta?(url)
		site=url_2_site(url)
    k=Wmap::UrlChecker.new
    if k.response_code(site) == 200
      k=nil
      doc=open_page(site)
      meta=doc.css('meta')
      if meta.to_s =~ /wordpress/i
        return true
      else
        return false
      end
    end
		return false
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return false
  end

	# Wordpress detection checkpoint - wp-login
  def wp_login?(url)
		site=url_2_site(url)
		login_url=site + "wp-login.php"
    k=Wmap::UrlChecker.new
    if k.response_code(login_url) == 200
      k=nil
      doc=open_page(login_url)
      links=doc.css('link')
      if links.to_s =~ /login.min.css/i
        return true
      else
        return false
      end
    end
		return false
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return false
  end

	# Wordpress detection checkpoint - xml-rpc
  def wp_rpc?(url)
		site=url_2_site(url)
		rpc_url=site + "xmlrpc.php"
    k=Wmap::UrlChecker.new
		#puts "res code", k.response_code(rpc_url)
    if k.response_code(rpc_url) == 405 # method not allowed
      k=nil
      return true
    end
		return false
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return false
  end

	# Extract the WordPress version
	def wp_ver(url)
		if !wp_ver_readme(url).nil?
			return wp_ver_readme(url)
		elsif !wp_ver_meta(url).nil?
			return wp_ver_meta(url)
		elsif !wp_ver_login(url,"login.min.css").nil?
			return wp_ver_login(url,"login.min.css")
		elsif !wp_ver_login(url,"buttons.min.css").nil?
			return wp_ver_login(url,"buttons.min.css")
		elsif !wp_ver_login(url,"wp-admin.min.css").nil?
			return wp_ver_login(url,"wp-admin.min.css")
		else
			return nil
		end
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return nil
	end

	# Identify wordpress version through the login page
  def wp_ver_login(url,pattern)
		puts "Check for #{pattern}" if @verbose
		site=url_2_site(url)
		login_url=site + "wp-login.php"
    k=Wmap::UrlChecker.new
		#puts "Res code: #{k.response_code(login_url)}" if @verbose
    if k.response_code(login_url) == 200
      doc=open_page(login_url)
			#puts doc.inspect
      links=doc.css('link')
			#puts links.inspect if @verbose
			links.each do |tag|
	      if tag.to_s.include?(pattern)
					puts tag.to_s if @verbose
					k=nil
	        return tag.to_s.scan(/[\d+\.]+\d+/).first
	      end
			end
    end
    k=nil
    return nil
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return nil
  end

	# Identify wordpress version through the meta link
  def wp_ver_meta(url)
		site=url_2_site(url)
    k=Wmap::UrlChecker.new
    if k.response_code(site) == 200
      doc=open_page(site)
			#puts doc.inspect
      meta=doc.css('meta')
			#puts meta.inspect
			meta.each do |tag|
	      if tag.to_s =~ /wordpress/i
					#puts tag.to_s
					k=nil
	        return tag.to_s.scan(/[\d+\.]+\d+/).first
	      end
			end
    end
    k=nil
    return nil
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return nil
  end

	# Wordpress version detection via - readme.html
  def wp_ver_readme(url)
		site=url_2_site(url)
    readme_url=site + "readme.html"
    k=Wmap::UrlChecker.new
		puts "Res code: #{k.response_code(readme_url)}" if @verbose
    if k.response_code(readme_url) == 200
      k=nil
      doc=open_page(readme_url)
			puts doc if @verbose
      logo=doc.css('h1#logo')[0]
      puts logo.inspect if @verbose
			return logo.to_s.scan(/[\d+\.]+\d+/).first
    end
    k=nil
    return nil
	rescue => ee
		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
		return nil
	end


end
