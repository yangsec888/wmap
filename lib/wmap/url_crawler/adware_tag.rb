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
	attr_accessor :signature_file, :tag_file, :verbose, :data_dir, :data_store
	attr_reader :tag_store, :tag_signatures


  class AdwareTag < Wmap::UrlCrawler

		# Initialize the instance variables
		def initialize (params = {})
			@verbose=params.fetch(:verbose, false)
      @data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../../data/')
      @tag_file=@data_dir + 'tag_sites'
			# Set default instance variables
			@signature_file=File.dirname(__FILE__) + '/../../../settings/' + 'tag_signatures'
			file=params.fetch(:signature_file, @signature_file)
			@tag_signatures=load_from_file(file)
      file2=params.fetch(:tag_file, @tag_file)
      File.write(file2, "") unless File.exist?(@tag_file)
      # load the known tag store
      @tag_store=load_tag_from_file(file2)

		end


    # load the known tag signatures into an instance variable
  	def load_from_file (file, lc=true)
  		begin
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
  	end

    # load the known tag store cache into an instance variable
  	def load_tag_from_file (file, lc=true)
  		begin
        puts "Loading tag data file: #{file}"	if @verbose
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
  					data_store[entry[0]]=[entry[1].strip, entry[2].strip]
  				end

  			end
  			f.close
  			return data_store
  		rescue => ee
  			puts "Exception on method #{__method__}: #{ee}" if @verbose
  			return nil
  		end
  	end

    # Save the current tag store hash table into a file
  	def save_to_file!(file_tag=@tag_file, tags=@tag_store)
      begin
        puts "Saving the current wordpress site table from memory to file: #{file_tag} ..." if @verbose
  			timestamp=Time.now
  			f=File.open(file_tag, 'w')
  			f.write "# Local tag file created by class #{self.class} method #{__method__} at: #{timestamp}\n"
  			f.write "# Site, Landing URL, Detected Adware Tags\n"
  			tags.each do |key, val|
  				f.write "#{key}, #{val[0]}, #{val[1]}\n"
  			end
  			f.close
  			puts "Tag store cache table is successfully saved: #{file_tag}"
  		rescue => ee
  			puts "Exception on method #{__method__}: #{ee}" if @verbose
  		end
  	end
  	alias_method :save!, :save_to_file!

    # add tag entries (from the sitetracker list)
  	def refresh (num=@max_parallel,use_cache=true)
      begin
  		  puts "Add entries to the local cache table from site tracker: " if @verbose
  			results=Hash.new
  			tags=Wmap::SiteTracker.instance.known_sites.keys
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
          tags=nil
  				return results
  			else
  				puts "Error: no entry is loaded. Please check your list and try again."
  			end
        tags=nil
  			return results
  		rescue => ee
  			puts "Exception on method #{__method__}: #{ee}" if @verbose
        return false
  		end
  	end

    # Give a  site, locate the landing page, then sift out the adware tag if found
  	def check_adware(site,use_cache=true)
      begin
  		  puts "Check the site for known Adware tags: #{site}" if @verbose
  			if use_cache && @tag_store.key?(site)
				  puts "Site entry already exist. Skipping: #{site}" if @verbose
          return nil
  			else
  				record=Hash.new
          url = fast_landing(site)
          tags=find_tags(url)
  				if tags
            record[site]=[url, tags]
            @tag_store.merge!(record)
            puts "Tag entry loaded: #{record}" if @verbose
          else
            puts "No tag found. Skip site #{site}" if @verbose
          end
          return record
  			end
      rescue => ee
  			puts "Exception on method #{__method__}: #{ee}: #{site}" if @verbose
  		end
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
    end

    # Search the page for known tag signatures. If found return them in a string deliminated by '|'
  	def find_tags(url)
  		begin
  			puts "Search and return tags within the url: #{url}" if @verbose
  			tag_list = []
        doc = Nokogiri::HTML(open(url))
        doc.text.each_line do |line|
          my_line = line.downcase
          @tag_signatures.keys.map do |tag|
            tag_list.push(tag) if my_line.include?(tag)
          end
        end
        if tag_list.size > 0
          return tag_list.join("|")
        else
          return false
        end
      rescue => ee
        puts "Exception on method #{__method__}: #{ee}" if @verbose
        return false
  		end
    end




	end
  end
end
