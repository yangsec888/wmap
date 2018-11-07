#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li
#++
require "net/http"
require "uri"
require "open-uri"
require "open_uri_redirections"
require "nokogiri"
require "parallel"


# Web site crawler class
class Wmap::UrlCrawler
	include Wmap::Utils

	attr_accessor :http_timeout, :crawl_page_limit, :crawl_depth, :max_parallel, :verbose, :data_dir
	attr_reader :discovered_urls_by_crawler, :visited_urls_by_crawler, :crawl_start, :crawl_done
	# Global variable used to store the combined result of all the forked child processes. Note that class variable
	# would not be able to pass the result due the limitation of IO Pipe communication mechanism used by 'parallel' fork manager
#	$discovered_urls=Hash.new

	# set hard stop limit of http time-out to 8 seconds, in order to avoid severe performance penalty for certain 'weird' site(s)
	Max_http_timeout=8000
	# set hard stop limit of crawler time-out to 1200 seconds or 20 minutes
	Crawl_timeout=1200000

	# Crawler instance default variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		@http_timeout=params.fetch(:http_timeout, 5000)
		@crawl_depth=params.fetch(:crawl_depth, 4)
		@crawl_page_limit=params.fetch(:crawl_page_limit, 1000)
		@max_parallel=params.fetch(:max_parallel, 40)
		# Discovered data store
		@discovered_urls_by_crawler=Hash.new
		@visited_urls_by_crawler=Hash.new
		@crawl_start=Hash.new
		@crawl_done=Hash.new
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@log_file=@data_dir + "crawler.log"
	end

	# Pre-crawl profiler, to be used for network profiling to maximum the crawler performance.
	def pre_crawl(url)
		puts "Perform network profiling works on the web server before the web crawling: #{url}" if @verbose
		begin
			host=url_2_host(url)
			# Use the following formula to 'guess' the right http time-out threshold for the scanner
			nwk_to=Wmap::NetworkProfiler.new.profile(host).to_i
			if (1500 + Wmap::NetworkProfiler.new.profile(host)*2).to_i > Max_http_timeout
				@http_timeout = Max_http_timeout
			else
				@http_timeout = 1500 + nwk_to*2
			end
			puts "Done with the pre-scan works: reset @http_timeout to: #{@http_timeout} ms" if @verbose
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			@http_timeout = Max_http_timeout
		end
	end

	# A web crawler to crawl a known website and search for html links within the same root domain. For example,
    # by crawling 'http://www.yahoo.com/' it could discover 'http://login.yahoo.com/'
	def crawl(url)
		puts "Start web crawling on #{url}"
		#begin
			result=Array.new
			url=url.chomp.strip
			result.push(url_2_site(url))
			raise "Error! Invalid url format: #{urls}" unless is_url?(url)
			# Add logic to profile the web server before crawling; this is used to optimize the crawling speed
			pre_crawl(url)
			status = Timeout::timeout(Crawl_timeout/1000) {
				result+=crawl_worker(url).keys
			}
			puts "Web crawling time-out on #{url}: #{status}" if @verbose
			return result
		#rescue => ee
			#puts "Exception on method #{__method__} for URL #{url}: #{ee}"
			#return result
		#end
	end
	alias_method :query, :crawl

    # The worker instance of crawler who perform the labour work
	def crawl_worker(url0)
		puts "Please be aware that it may take a while to crawl #{url0}, depending on the site's responsiveness and the amount of contents."
		#begin
			# Input URL sanity check first
			if is_url?(url0)
				host=url_2_host(url0)
				ip=host_2_ip(host).to_s
				raise "Invalid IP address: #{url0}" if ip.nil?
				port=url_2_port(url0).to_s
				raise "Invalid port number: #{url0}" if port.nil?
			else
				raise "Invalid URL: #{url0}. Please check it out with your browser again."
			end
			log_info=Hash.new
			log_info[1]="Start working on #{url0}"
			url_stores=Hash.new
			url_stores[url0]=true unless url_stores.key?(url0)
			@discovered_urls_by_crawler[url0]=true unless @discovered_urls_by_crawler.key?(url0)
			@crawl_start[url0]=true unless @crawl_start.key?(url0)
#			$discovered_urls[url0]=true unless $discovered_urls.key?(url0)
			@crawl_depth.times do
				url_stores.keys.each do |url|
					# 10/01/2013 add logic to avoid unnecessary crawling within the same child instance
					next if @visited_urls_by_crawler.key?(url)
					url_object = open_url(url)
					next if url_object == nil
					url = update_url_if_redirected(url, url_object)
					url_body = read_url(url)
					# Protection code - to avoid parsing failure on the empty or nil object
					next if url_body.nil? or url_body.empty?
					url_stores[url]=true unless url_stores.key?(url)
					@discovered_urls_by_crawler[url]=true unless @discovered_urls_by_crawler.key?(url)
#					$discovered_urls[url]=true unless $discovered_urls.key?(url)
					doc = parse_html(url_body)
					next if doc == nil
					if url_stores.size >= @crawl_page_limit
						#@visited_urls_by_crawler.merge!(url_stores)
						@discovered_urls_by_crawler.merge!(url_stores)
#						$discovered_urls.merge!(url_stores)
						puts "Finish web crawling the url: #{url0}"
						return url_stores
					end
					page_urls = find_urls_on_page(doc, url)
					page_urls.uniq!
					page_urls.map do |y|
						y=normalize_url(y)
						url_stores[y]=true unless url_stores.key?(y)
						@discovered_urls_by_crawler[y]=true unless @discovered_urls_by_crawler.key?(y)
#						$discovered_urls[y]=true unless $discovered_urls.key?(y)
					end
				end
			end
			puts "Finish web crawling on: #{url0}"
			log_info[2]="Finish working on: #{url0}"
			wlog(log_info, "UrlCrawler", @log_file)
			@crawl_done[url0]=true unless @crawl_done.key?(url0)
			return url_stores
		#rescue => ee
			#puts "Exception on method #{__method__} for URL #{url0}: #{ee}" if @verbose
			#log_info[3]="Exception on #{url0}"
			#wlog(log_info,"UrlCrawler",@log_file)
			#return url_stores
		#end
	end

	# Fast crawling by utilizing fork manager parallel to spawn numbers of child processes at the same time
	# each child process will continuously work on the target pool until all the works are done
	def crawl_workers (targets,num=@max_parallel)
		begin
			raise "Input error - expecting targets in an array format: #{targets}" unless targets.kind_of? Array
			puts "Sanitize the URL seeds to eliminate the unnecessary duplication(s) ..." if @verbose
			#puts "This could be awhile depending on the list size. Please be patient ..."
			# 09/30/2013 Add additional logic to eliminate the duplicate target site(s) before the crawlers are invoked.
			targets -= ["", nil]
			uniq_sites=Hash.new
			targets.dup.map do |target|
				if is_url?(target)
					host=url_2_host(target)
					ip=host_2_ip(host).to_s
					next if ip.nil?
					port=url_2_port(target).to_s
					next if port.nil?
					site_key=ip+":"+port
					unless uniq_sites.key?(site_key)
						uniq_sites[site_key]=target
					end
				end
			end
			puts "Sanitization done! " if @verbose
			puts "Start the parallel engine on the normalized crawling list:\n #{targets} "
			puts "Maximum number of web crawling sessions allowed: #{num}" #if @verbose
			raise "Error: target list is empty!" if targets.size < 1
			Parallel.map(uniq_sites.values, :in_processes => num) { |target|
				puts "Working on #{target} ..." if @verbose
				crawl(target)
			}.dup.each do |process|
				puts "process.inspect: #{process}" if @verbose
				urls=process
				urls-=["",nil] unless urls.nil?
				if urls.nil?
					next
				elsif urls.empty?
					next
					#do nothing
				else
					urls.map do |url|
						url.strip!
						@discovered_urls_by_crawler[url]=true unless @discovered_urls_by_crawler.key?(url)
						#$discovered_urls[url]=true unless $discovered_urls.key?(url)
					end
				end
			end
			#return sites
			return @discovered_urls_by_crawler.keys
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :crawls, :crawl_workers

	# Fast crawling method - build the target pool from the input file
	def crawl_workers_on_file (file)
		puts "Web crawl the list of targets from file: #{file}"
		begin
			targets=file_2_list(file)
			sites=crawl_workers(targets,num=@max_parallel)
			return sites
		rescue => ee
            puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
		end
	end
	alias_method :query_file, :crawl_workers_on_file
	alias_method :crawl_file, :crawl_workers_on_file

  # Wrapper for the OpenURI open method - create an open_uri object and return the reference upon success
	def open_url(url)
		#url_object = nil
    begin
			puts "Open url #{url} by creating an open_uri object. Return the reference upon success." if @verbose
			if url =~ /http\:/i
				# patch for allow the 'un-safe' URL redirection i.e. https://www.example.com -> http://www.example.com
				url_object = open(url, :allow_redirections=>:safe, :read_timeout=>Max_http_timeout/1000)
				#url_object = open(url)
			elsif url =~ /https\:/i
				url_object = open(url,:ssl_verify_mode => 0, :allow_redirections =>:safe, :read_timeout=>Max_http_timeout/1000)
				#url_object = open(url,:ssl_verify_mode => 0)
			else
				raise "Invalid URL format - please specify the protocol prefix http(s) in the URL: #{url}"
			end
			return url_object
    rescue => ee
      puts "Exception on method #{__method__} for #{url}: #{ee}" if @verbose
      return nil
    end
  end

	# Wrapper to use OpenURI method 'read' to return url body contents
	def read_url(url)
		begin
			puts "Wrapper to return the OpenURI object for url: #{url}" if @verbose
			url_object=open_url(url)
			@visited_urls_by_crawler[url]=true unless @visited_urls_by_crawler.key?(url)
			body=url_object.read
			return body
  	rescue => ee
      puts "Exception on method #{__method__}: #{ee}" if @verbose
      return nil
    end
	end

    # Return the destination url in case of url re-direct
	def update_url_if_redirected(url, url_object)
		#puts "Comparing the original URL with the return object base_uri. Return the one where the true content is found. " if @verbose
		begin
			if url != url_object.base_uri.to_s
				return url_object.base_uri.to_s
			end
			return url
    rescue => ee
      puts "Exception on method #{__method__}: #{ee}" if @verbose
      return nil
    end
  end

    # Wrapper for the Nokogiri DOM parser
	def parse_html(html_body)
        #puts "Parsing the html content: #{html_body}. Return DOM " if @verbose
		begin
            doc = Nokogiri::HTML(html_body)
			#puts "Successfully crawling the url: #{url_object.base_uri.to_s}" if @verbose
			#puts "doc: #{doc}" if @verbose
			return doc
        rescue => ee
            puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
        end
	end

    # Search 'current_url' and return found URLs under the same domain
	def find_urls_on_page(doc, current_url)
        #puts "Search and return URLs within the doc: #{doc}" if @verbose
		begin
			urls_list = []
			# case 1 - search embedded HTML tag <a href='url'> for the url elements
			links=doc.css('a')
			links.map do |x|
				#puts "x: #{x}"
				new_url = x.attribute('href').to_s
				unless new_url == nil
					if new_url.match("http")
						#if urls_on_same_domain?(new_url,current_url)
							urls_list.push(new_url)
						#end
					else
						new_url = make_absolute(current_url, new_url)
						urls_list.push(new_url)
					end
				end
			end
			# case 2 - search client side redirect - <meta http-equiv="refresh" content="5;URL='http://example.com/'">
			elements=doc.css("meta[http-equiv]")
			unless elements.size == 0
				link=elements.attr("content").value.split(/url\=/i)[1]
				unless link.nil?
					new_url = make_absolute(current_url, link)
					urls_list.push(new_url) unless new_url.nil?
				end
			end
			#puts "Found URLs under page #{current_url}:\n#{urls_list}" if @verbose
			return urls_list.uniq-["",nil]
        rescue => ee
            puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
		end
    end

	# Method to print out discovery URL result
	def print_discovered_urls_by_crawler
		puts "Print discovered url by the crawler. " if @verbose
		begin
			puts "\nSummary Report of Discovered URLs from the Crawler:"
			@discovered_urls_by_crawler.keys.each do |url|
				puts url
			end
			puts "Total: #{@discovered_urls_by_crawler.keys.size}"
			puts "End of the summary"
        rescue => ee
            puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
        end
	end
	alias_method :print, :print_discovered_urls_by_crawler

	# Method to save URL discovery  result
	def save_discovered_urls (file)
		puts "Save discovered urls by the crawler to file: #{file} "
		begin
			list_2_file(@discovered_urls_by_crawler.keys, file)
			puts "Done!"
        rescue => ee
            puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
        end
	end
	alias_method :save, :save_discovered_urls

	# Method to retrieve discovery site result
	def get_discovered_sites_by_crawler
		puts "Print summary report of discovered sites. " if @verbose
		begin
			puts "\nSummary Report of Discovered Sites from the Crawler:"
			sites = Hash.new
			@discovered_urls_by_crawler.keys.each do |url|
				site=url_2_site(url)
				sites[site]=true unless sites.key?(site)
			end
			sites.keys.map { |site| puts site }
			puts "Total: #{sites.size}"
			puts "End of the summary"
			return sites.keys
        rescue => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
            return nil
        end
	end
	alias_method :get_sites, :get_discovered_sites_by_crawler

	private :open_url, :read_url, :update_url_if_redirected, :parse_html, :find_urls_on_page
end
