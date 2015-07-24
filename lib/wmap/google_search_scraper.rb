#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li 
#++
require 'open-uri'
require 'nokogiri'


# We build our own Google search class by querying Google search engine from its web interface, by simulating  
# an anonymous web surfer. 
# Note: we don't use the native Google API due to its pricing structure - We don't have budget for 
#    this project, and we can not use the free version due to the limitation of 100 queries per day for free. See https://github.com/google/google-api-ruby-client for details.
class Wmap::GoogleSearchScraper
	include Wmap::Utils

	attr_accessor :verbose, :http_timeout, :keyword_list
	attr_reader :discovered_urls_from_scraper, :discovered_sites_from_scraper
	
	# Google search engine web interface locators
	File_locator = File.dirname(__FILE__)+'/../../settings/google_locator.txt'
	# Google search key words
	File_keywords = File.dirname(__FILE__)+'/../../settings/google_keywords.txt'
	

	# Scraper default variables
	def initialize (params = {})		
		@verbose=params.fetch(:verbose, false)
		@http_timeout=params.fetch(:http_timeout, 5000)
		# Discovered data store		
		@discovered_urls_from_scraper=Hash.new
		@discovered_sites_from_scraper=Hash.new
	end
	
	# Main worker method to simulate extensive google keyword searches on over 100+ countries and regions. The search will extract known web services related to the keyword by the Google Inc.
	def google_worker (keyword)
		begin
			puts "Start the Google worker for: #{keyword}" if @verbose
			links=Array.new
			keyword=keyword.strip
			google_locators = file_2_list(File_locator)
			google_locators.map do |locator|
				doc=google_search(locator,keyword) unless keyword.nil?
				links+=extract_links(doc) unless doc.nil? 
			end
			return links.uniq.sort-["",nil]
		rescue Exception => ee
			puts "Exception on the method google_worker for #{keyword}: #{ee}" if @verbose
			return nil
		end	
	end 
	alias_method :worker, :google_worker
	alias_method :search, :google_worker

	# Main method to collect intelligences on the Google vast data warehouse. It works by hitting the Google engines with the keyword list. This exhausive method will sweep through the Google engines in over 100+ countries and regions one by one, in order to collect all related web service links collected by known the Google, Inc. across the global Internet.
	def google_workers(keyword_list=file_2_list(File_keywords)) 
		begin
			puts "Start the Google worker for: #{keyword_list}" if @verbose
			links=Array.new			
			keyword_list.map do |keyword|
				links+=google_worker(keyword)
			end
			return links.uniq.sort
		rescue Exception => ee
			puts "Exception on the method google_workers for #{keyword_list}: #{ee}" if @verbose
			return nil
		end	
	end 
	alias_method :workers, :google_workers
	
	# Perform a Google web interface keyword search, return as a Nokogiri::HTML:Document object for the search result page 
	def google_search (locator,keyword)
		begin
			puts "Perform the keyword search on the Google web engine for: #{keyword}" if @verbose
			link_search = locator + "search?q=" + URI::encode(keyword)
			doc = Nokogiri::HTML(open(link_search))
			return doc
		rescue Exception => ee
			puts "Exception on method google_search at Google engine location #{link_search} for the keyword #{keyword} : #{ee}" if @verbose
		end
	end
	
	# Search for nodes by css, and extract the hyper links
	def extract_links (doc)
		begin
			puts "Extract the meaningful links from the DOC." if @verbose
			links=Array.new
			doc.css('a').each do |link|
				ref=link.attribute('href').to_s
				if ref =~ /\/url\?/
					my_key=ref.sub(/\/url\?q\=/,'')
					my_site=url_2_site(my_key)
					links.push(my_key)
					@discovered_urls_from_scraper[my_key]=true unless @discovered_urls_from_scraper.key?(my_key)
					@discovered_sites_from_scraper[my_site]=true unless @discovered_sites_from_scraper.key?(my_site)
				end
			end
			return links
		rescue Exception => ee
			puts "Exception on method extract_links: #{ee}" if @verbose
			return nil
		end 
	end
	
	# Method to print out discovery URL result
	def print_discovered_urls_from_scraper		
		puts "Print discovered urls by the scraper. " if @verbose
		begin
			puts "\nSummary Report of Discovered URLs from the Scraper:"
			@discovered_urls_from_scraper.keys.each do |url|
				puts url
			end
			puts "Total: #{@discovered_urls_from_scraper.keys.size} url(s)"
			puts "End of the summary"
        rescue => ee
			puts "Error on method print_discovered_urls_from_scraper: #{ee}" if @verbose
        end
	end	

	# Method to print out discovery Sites result
	def print_discovered_sites_from_scraper		
		puts "Print discovered sites by the scraper. " if @verbose
		begin
			puts "\nSummary Report of Discovered Sites from the Scraper:"
			@discovered_sites_from_scraper.keys.each do |site|
				puts site
			end
			puts "Total: #{@discovered_sites_from_scraper.keys.size} site(s)"
			puts "End of the summary"
        rescue => ee
			puts "Error on method print_discovered_sites_from_scraper: #{ee}" if @verbose
        end
	end	
	
	# 'getter' for the discovered sites from the Google search
	def get_discovered_sites_from_scraper
		puts "Getter for the discovered sites by the scraper. " if @verbose
		begin
			return @discovered_sites_from_scraper.keys.sort
        rescue => ee
			puts "Error on method get_discovered_sites_from_scraper: #{ee}" if @verbose
        end
	end
	alias_method :print, :get_discovered_sites_from_scraper

	# 'getter' for the discovered urls from the Google search
	def get_discovered_urls_from_scraper
		puts "Getter for the discovered urls by the scraper. " if @verbose
		begin
			return @discovered_urls_from_scraper.keys.sort
        rescue => ee
			puts "Error on method get_discovered_urls_from_scraper: #{ee}" if @verbose
        end
	end

	# Save the discovered sites into a local file
	def save_discovered_sites_from_scraper (file)
		puts "Save the discovery result(sites) into a local file: #{file}" if @verbose
		begin
			f=File.open(file, 'w')
			timestamp=Time.now
			f.puts "# Discovery result written by Wmap::GoogleSearchScraper.save_discovered_sites_from_scraper method at #{timestamp}\n"
			@discovered_sites_from_scraper.keys.sort.map { |x| f.puts "#{x}\n" }
			f.close
			raise "Unknown problem saving the result to file: #{file}" unless File.exist?(file)
			puts "Done saving the discovery result into the local file: #{file}" 
        rescue => ee
			puts "Error on method save_discovered_sites_from_scraper: #{ee}" if @verbose
        end
	end
	alias_method :save, :save_discovered_sites_from_scraper
	
	private

end
