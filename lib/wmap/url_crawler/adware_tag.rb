#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++


module Wmap
  class UrlCrawler

	# Class to identify and track adware within the site store
	include Wmap::Utils
	attr_accessor :signature_file, :tag_file, :verbose, :data_dir
	attr_reader :tag_signatures, :tag_store


  class AdwareTag < Wmap::UrlCrawler

		# Initialize the instance variables
		def initialize (params = {})
			@verbose=params.fetch(:verbose, false)
      @data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../../data/')
      Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
			# Set default instance variables
			@signature_file=File.dirname(__FILE__) + '/../../../settings/' + 'tag_signatures'
			file=params.fetch(:signature_file, @signature_file)
			@tag_signatures=load_sig_from_file(file)
      @tag_file=params.fetch(:tag_file, @data_dir + 'tag_sites')
      File.write(@tag_file, "") unless File.exist?(@tag_file)
      # load the known tag store
      load_tag_from_file(@tag_file)
      @landings = Hash.new  # cache landing page to reduce redundant browsing
		end

    # load the known tag signatures into an instance variable
  	def load_sig_from_file (file, lc=true)
      puts "Loading data file: #{file}"	if @verbose
			data_store=Hash.new
			f = File.open(file, 'r')
			f.each_line do |line|
				puts "Processing line: #{line}" if @verbose
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.downcase if lc==true
				entry=line.split(',')
				if data_store.key?(entry[0])
					next
				else
					data_store[entry[0]]=entry[1].strip
				end
			end
			f.close
			return data_store
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
  	end

    # load the known tag store cache into an instance variable
  	def load_tag_from_file (file, lc=false)
      puts "Loading tag data file: #{file}"	if @verbose
			@tag_store=Hash.new
			f = File.open(file, 'r')
			f.each_line do |line|
				puts "Processing line: #{line}" if @verbose
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.downcase if lc==true
				entry=line.split(',')
				if @tag_store.key?(entry[0])
					next
				else
					@tag_store[entry[0]]=[entry[1].strip, entry[2].strip, entry[3], entry[4]]
				end
			end
			f.close
			return @tag_store
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
  	end

    # Save the current tag store hash table into a file
  	def save_to_file!(file_tag=@tag_file, tags=@tag_store)
      puts "Saving the current wordpress site table from memory to file: #{file_tag} ..." if @verbose
			timestamp=Time.now
			f=File.open(file_tag, 'w')
			f.write "# Local tag file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
			f.write "# Site, Landing URL, Detected Adware Tag, Tag Version, Tag Description\n"
			tags.each do |key, val|
				f.write "#{key}, #{val[0]}, #{val[1]}, #{val[2]}, #{val[3]}\n"
			end
			f.close
			puts "Tag store cache table is successfully saved: #{file_tag}"
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
  	end
  	alias_method :save!, :save_to_file!

    # Refresh adware tag store signatures
  	def refresh (num=@max_parallel,use_cache=true)
		  puts "Add entries to the local cache table from site tracker: " if @verbose
			results = Hash.new
			tags = @tag_store.keys
			if tags.size > 0
				Parallel.map(tags, :in_processes => num) { |target|
					check_adware(target,use_cache)
				}.each do |process|
					if !process
						next
					else
						results.merge!(process)
					end
				end
				@tag_store.merge!(results)
				puts "Done loading entries."
        tags = nil
				return results
			else
				puts "Error: no entry is loaded. Please check your list and try again."
			end
      tags = nil
			return results
		rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
  	end

    # Give a  site, locate the landing page, then sift out the adware tag if found
  	def check_adware(site,use_cache=true)
		  puts "Check the site for known Adware tags: #{site}" if @verbose
      record = Hash.new
			if use_cache && @tag_store.key?(site)
			  puts "Site entry already exist. Skipping: #{site}" if @verbose
			else
        url = fast_landing(site)
        if @landings.key?(url)
          record[site] = @landings[url]
          return record
        end
        tags = find_tags(url)
        return record if tags.size==0
        tag_vers=tags.map do |tag|
          get_ver(url,tag)
        end
        tag_descs=tags.map do |tag|
          Base64.urlsafe_encode64(get_desc(url,tag))
        end
				if tags
          record[site] = [url, tags.join("|"), tag_vers.join("|"), tag_descs.join("|")]
          @landings[url] = [url, tags.join("|"), tag_vers.join("|"), tag_descs.join("|")]
          @tag_store.merge!(record)
          puts "Tag entry loaded: #{record}" if @verbose
        else
          puts "No tag found. Skip site #{site}" if @verbose
        end
			end
      return record
    rescue => ee
			puts "Exception on method #{__method__}: #{ee}: #{site}" if @verbose
  	end

    # Given a site, determine the landing url
    def fast_landing(site)
      puts "Locate the landing url for: #{site}" if @verbose
      my_tracker=Wmap::SiteTracker.instance
      if my_tracker.known_sites.key?(site)
        # looking into the cache first
        if my_tracker.known_sites[site]['code'] >= 300 && my_tracker.known_sites[site]['code'] < 400
          url = my_tracker.known_sites[site]['redirection']
        else
          url = site
        end
        my_tracker = nil
      else
        # no cache, then need to do it fresh
        my_checker = Wmap::UrlChecker.new
        url = my_checker.landing_location(site)
        my_checker = nil
      end
      puts "Landing url found: #{url}" if @verbose
      return url
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}" if @verbose
    end

    # Search the page for known tag signatures. If found return them in an array
  	def find_tags(url)
			puts "Search and return tags within the url payload: #{url}" if @verbose
			tag_list = []
      doc = open_page(url)
      doc.text.each_line do |line|
        my_line = line.downcase
        @tag_signatures.keys.map do |tag|
          tag_list.push(tag) if my_line.include?(tag)
        end
      end
      return tag_list
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}" if @verbose
      return []
    end

    # Search the url payload for known tag version identifier. If found return a string, else empty string.
  	def get_ver(url,tag)
      puts "Search and return tag version within the url payload: #{url}, #{tag}" if @verbose
      tag_ver=""
      doc = open_page(url)
      case tag
      when "utag.js"          # sample: ...,"code_release_version":"cb20190312032612",...
        doc.text.each_line do |line|
          my_line = line.downcase
          if my_line.include?("code_release_version")
            puts "Extract tag version from line: #{my_line}" if @verbose
            m = my_line.match(/\"code\_release\_version\"\:\"(?<ver>[a-z]+\d+)\"/)
            tag_ver = m[:ver]
            break
          end
        end
      when "analytics.js"         # sample #1:   ga('create', 'UA-19175804-2', 'knopfdoubleday.com');
        doc.text.each_line do |line|
          my_line = line.downcase
          if my_line.include?("ga") && my_line.include?("create")   #sample #2: __gaTracker('create', 'UA-121313929-1', 'auto');
            puts "Extract tag version from line: #{my_line}" if @verbose
            m = my_line.match(/[\'|\"]create[\'|\"]\s*\,\s*[\'|\"](?<ver>\w+\-\d+\-\d+)[\'|\"]\s*\,/)
            tag_ver = m[:ver]
            break
          end
        end
      when "ga.js"
        doc.text.each_line do |line|
          my_line = line.downcase
          puts my_line if @verbose
          if my_line.include?("push") && my_line.include?("_setaccount")  # # sample #1:   _gaq.push(['_setAccount', 'UA-13205363-65']);
            m = my_line.match(/[\'|\"]\_setaccount[\'|\"]\s*\,\s*[\'|\"](?<ver>\w+\-\d+\-\d+)[\'|\"]/)
            tag_ver = m[:ver]
            break
          end
          if my_line.include?("_gettracker")  # sample #2: var pageTracker = _gat._getTracker("UA-12487327-1");
            puts "Extract tag version from line: #{my_line}" if @verbose
            m = my_line.match(/\_gettracker\s*\(\s*[\'|\"](?<ver>\w+\-\d+\-\d+)[\'|\"]/)
            tag_ver = m[:ver]
            break
          end

        end
      when "all.js"          # sample:    appId      : '749936668352954',
        doc.text.each_line do |line|
          my_line = line.downcase
          if my_line.include?("appid") && my_line.include?(":")
            puts "Extract tag version from line: #{my_line}" if @verbose
            m = my_line.match(/appid\s+\:\s+[\'|\"](?<ver>\d+)[\'|\"]\s*\,/)
            tag_ver = m[:ver]
            break
          end
        end

      else
        puts "Don't know how to locate Adware Tag version: #{tag}"
        # do nothing
      end
      doc = nil
      return tag_ver.upcase
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}: #{url} : #{tag}" if @verbose
      return tag_ver
    end

    # Search the url payload for known tag. If found return the base64 encode whole script snippet.
  	def get_desc(url,tag)
      puts "Search and return tag script in url payload: #{url}, #{tag}" if @verbose
      recording=false
      tag_found=false
      tag_desc=""
      doc = open_page(url)
      doc.search('script').map do |script|
        if script.text.include?(tag) && script.text.length < 65535
          return script.text
        end
      end
      doc = nil
      return tag_desc
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}: #{url}: #{tag}" if @verbose
      return tag_desc
    end



	end
  end
end
