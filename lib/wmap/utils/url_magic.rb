#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "watir"
require "selenium-webdriver"

module Wmap
 module Utils
  module UrlMagic
	extend self

  # set hard stop limit of http time-out to 8 seconds, in order to avoid severe performance penalty for certain 'weird' site(s)
  Max_http_timeout=15000

	# Simple sanity check on a 'claimed' URL string.
	def is_url?(url)
		puts "Validate the URL format is valid: #{url}" if @verbose
		if url =~ /(http|https)\:\/\/((.)+)/i
			host=$2.split('/')[0]
			host=host.split(':')[0]
			if is_ip?(host) or is_fqdn?(host)
				return true
			else
				return false
			end
		else
			puts "Unknown URL format: #{url}" if @verbose
			return false
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return false
	end

	# Simple sanity check on a 'claimed' SSL enabled URL string
	def is_ssl?(url)
		puts "Validate if SSL is enabled on: #{url}" if @verbose
		url=url.strip
		if is_url?(url) && url =~ /https/i
			return true
		else
			return false
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return false
	end
	alias_method :is_https?, :is_ssl?

	# Simple sanity check on a 'claimed' web site base string.
	def is_site?(url)
	  puts "Validate the website string format for: #{url}" if @verbose
		url=url.strip.downcase
		if is_url?(url)
			if url == url_2_site(url)
				return true
			else
				return false
			end
		else
			puts "Unknown site format: #{url}" if @verbose
			return false
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end

	# Extract the web server host's Fully Qualified Domain Name (FQDN) from the url. For example: "https://login.yahoo.com/email/help" -> "login.yahoo.com"
	def url_2_host (url)
		url = url.strip.downcase.gsub(/(http:\/\/|https:\/\/)/, "")
		record1 = url.split('/')
		if record1[0].nil?
			puts "Error process url: #{url}"
			return nil
		else
			record2 = record1[0].split(':')
			return record2[0]
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end

	# Extract web service port from the url. For example: "https://login.yahoo.com/email/help" -> 443
	def url_2_port (url)
		puts "Retrieve service port on URL: #{url}" if @verbose
		ssl = (url =~ /https/i)
		url = url.downcase.gsub(/(http:\/\/|https:\/\/)/, "")
		record1 = url.split('/')
		record2 = record1[0].split(':')
		if (record2.length == 2)
			puts "The service port: #{record2[1]}" if @verbose
			return record2[1].to_i
		elsif ssl
			puts "The service port: 443" if @verbose
			return 443
		else
			puts "The service port: 80" if @verbose
			return 80
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end

	# Extract site in (host:port) format from a url: "https://login.yahoo.com:8443/email/help" -> "http://login.yahoo.com:8443/"
	def url_2_site (url)
		puts "Retrieve the web site base for url: #{url}" if @verbose
		url = url.downcase
		url = url.sub(/^(.*?)http/i,'http')
		entry = url.split(%r{\/\/})
		prot=entry[0]
		# step 1, extract the host:port pair from the url
		host_port=entry[1].split(%r{\/})[0]
		if host_port =~ /\:/
			host=host_port.split(%r{\:})[0]
			port=host_port.split(%r{\:})[1].to_i
		elsif prot =~ /https/i
			host=host_port
			port=443
		elsif prot =~ /http/i
			host=host_port
			port=80
		else
			host=host_port
			#raise "Unknown url format: #{url}"
		end
		# additional logic to handle uncommon url base structures
		unless is_fqdn?(host)
			case host
				# "https://letmechoose.barclays.co.uk?source=btorganic/" => "https://letmechoose.barclays.co.uk"
				when /\?|\#/
					host=host.split(%r{\?|\#})[0]
				else
					#do nothing
			end
		end
		# step 2, put the host:port pair back to the normal site format
		prot="https:" if port==443
		if port==80 || port==443
			site=prot+"//"+host+"/"
		else
			site=prot+"//"+host+":"+port.to_s+"/"
		end
		if site=~ /http/i
			#puts "Base found: #{site}" if @verbose
			return site
		else
			raise "Problem encountered on method url_2_site: Unable to convert #{url}"
			return nil
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end

	# Wrapper to return relative path component of the URL. i.e. http://www.yahoo.com/login.html => /login.html
	def url_2_path(url)
		#puts "Retrieve the relative path component of the url: #{url}" if @verbose
		url.strip!
		base = url_2_site(url).chop
		path=url.sub(base,'')
		#puts "Path component found: #{path}" if @verbose
		return path
	rescue => ee
		puts "Exception on method #{__method__} for #{url}: #{ee}" if @verbose
	end

	# Test if the two URLs are both under the same domain: http://login.yahoo.com, http://mail.yahoo.com => true
	def urls_on_same_domain?(url1, url2)
		puts "Determine if two URLs under the same domain: #{url1}, #{url2}" if @verbose
		host1=url_2_host(url1)
		host2=url_2_host(url2)
		return get_domain_root(host1) == get_domain_root(host2)
  rescue => ee
		puts "Error searching the object content: #{ee}" if @verbose
    return nil
  end

	# Input is host and open port, output is a URL for valid http response code or nil
	def host_2_url (host,port=80)
		puts "Perform simple http(s) service detection on host #{host}, port #{port}" if @verbose
		host=host.strip
		if port.to_i == 80
			url_1 = "http://" + host + "/"
		elsif port.to_i ==443
			url_1 = "https://" + host + "/"
		else
			url_1 = "http://" + host + ":" + port.to_s + "/"
			url_2 = "https://" + host + ":" + port.to_s + "/"
		end
		puts "Please ensure your internet connection is active before running this method: #{__method__}" if @verbose
		checker=Wmap::UrlChecker.new
		if checker.response_code(url_1) != 10000
			puts "Found URL: #{url_1}" if @verbose
			return url_1
		elsif checker.response_code(url_2) != 10000
			puts "Found URL: #{url_2}" if @verbose
			return url_2
		else
			puts "No http(s) service found on: #{host}:#{port}" if @verbose
			return nil
		end
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end

	# Convert a relative URL to an absolute one. For example, from URL base 'http://games.yahoo.com/' and file path '/game/the-magic-snowman-flash.html' => 'http://games.yahoo.com/game/the-magic-snowman-flash.html'
	def make_absolute(base, relative_url)
    puts "Determine and return the absolute URL:\n Base: #{base}, Relative: #{relative_url} " if @verbose
		absolute_url = nil;
		if relative_url =~ /^\//
			absolute_url = create_absolute_url_from_base(base, relative_url)
		else
			absolute_url = create_absolute_url_from_context(base, relative_url)
		end
		puts "Found absolute URL: #{absolute_url}" if @verbose
		return absolute_url
  rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
    return nil
  end

	# Create / construct the absolute URL from a known URL and relative file path. For example, 'http://images.search.yahoo.com/images' + '/search/images?p=raiders' => 'http://images.search.yahoo.com/search/images?p=raiders'
	def create_absolute_url_from_base(potential_base, relative_url)
		#puts "Determine the absolute URL from potential base #{potential_base} and relative URL #{relative_url}" if @verbose
		naked_base = url_2_site(potential_base).strip.chop
		puts "Found absolute URL: #{naked_base+relative_url}" if @verbose
		return naked_base + relative_url
  rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
    return nil
  end

    # Construct the absolute URL by comparing a known URL and the relative file path
	def create_absolute_url_from_context(potential_base, relative_url)
    puts "Determine the absolute URL from context:\n Known base: #{potential_base}, Relative path: #{relative_url}" if @verbose
		absolute_url = nil
		# make relative URL naked by removing the beginning '/'
		relative_url.sub!(/^\//,'')
		if potential_base =~ /\/$/
			absolute_url = potential_base+relative_url.strip
		else
			last_index_of_slash = potential_base.rindex('/')
			if potential_base[last_index_of_slash-2, 2] == ':/'
				absolute_url = potential_base+relative_url
			else
				last_index_of_dot = potential_base.rindex('.')
				if last_index_of_dot < last_index_of_slash
					absolute_url = potential_base.strip.chop+relative_url
				else
					absolute_url = potential_base[0, last_index_of_slash+1] + relative_url
				end
			end
		end
		puts "Found absolute URL: #{absolute_url}" if @verbose
		return absolute_url
  rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
          return nil
  end

	# Normalize the URL to a consistent manner in order to determine if a link has been visited or cached before
	# See http://en.wikipedia.org/wiki/URL_normalization for more explanation
	def normalize_url(url)
		url.strip!
		# Converting the scheme and host to lower case in the process, i.e. 'HTTP://www.Example.com/' => 'http://www.example.com/'
		# Normalize the base
		base=url_2_site(url)
		# Case#1, remove the trailing dot after the hostname, i.e, 'http://www.yahoo.com./' => 'http://www.yahoo.com/'
		base=base.sub(/\.\/$/,'/')
		# Normalize the relative path, case#1
		# retrieve the file path and remove the first '/' or '.',
		# i.e. 'http://www.example.com/mypath' or 'http://www.example.com/./mypath' => 'mypath'
		path=url_2_path(url).sub(/^(\/|\.)*/,'')
		# Normalize the relative path, case#2
		# Replace dot-segments. "/../" and "/./" with "/", i.e. 'http://www.example.com/../a/b/../c/./d.html" => 'http://www.example.com/a/c/d.html'
		path=path.gsub(/\/\.{1,2}\//,'/')
		if path.nil?
			return base
		else
			return base+path
		end
	rescue => ee
		puts "Exception on method #{__method__} for #{url}: #{ee}" if @verbose
		return url
	end


	# Test the URL and return the response code
	def response_code (url)
		puts "Check the http response code on the url: #{url}" if @verbose
		code = 10000	# All unknown url connection exceptions go here
		raise "Invalid url: #{url}" unless is_url?(url)
		url=url.strip.downcase
		timeo = Max_http_timeout/1000.0
		uri = URI.parse(url)
		http = Net::HTTP.new(uri.host, uri.port)
		http.open_timeout = timeo
		http.read_timeout = timeo
		if (url =~ /https\:/i)
			http.use_ssl = true
			#http.ssl_version = :SSLv3
			# Bypass the remote web server cert validation test
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end
		request = Net::HTTP::Get.new(uri.request_uri)
		response = http.request(request)
		puts "Server response the following: #{response}" if @verbose
		code = response.code.to_i
		#response.finish if response.started?()
		@url_code=Hash.new unless @url_code
    @url_code[url]=code
		puts "Response code on #{url}: #{code}" if @verbose
		return code
	rescue Exception => ee
		puts "Exception on method #{__method__} for #{url}: #{ee}" if @verbose
		case ee
		# rescue "Connection reset by peer" error type
		when Errno::ECONNRESET
			code=104
		when Errno::ECONNABORTED,Errno::ETIMEDOUT
			#code=10000
		when Timeout::Error				# Quick fix
			if (url =~ /https\:/i)		# try again for ssl timeout session, in case of default :TLSv1 failure
				http.ssl_version = :SSLv3
				response = http.request(request)
				code = response.code.to_i
				unless code.nil?
					@ssl_version = http.ssl_version
				end
			end
		else
			#code=10000
		end
    @url_code=Hash.new unless @url_code
		@url_code[url]=code
		return code
	end

  # Given an URL, open the page, then return the DOM text from a normal user perspective
  def open_page(url)
    args = {ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE, allow_redirections: :safe, read_timeout: Max_http_timeout/1000}
    doc = Nokogiri::HTML(open(url, args))
    if doc.text.include?("Please enable JavaScript to view the page content")
      puts "Invoke headless chrome through webdriver ..." if @verbose
      #Selenium::WebDriver::Chrome.path = "/usr/local/bin/chromedriver"
      #driver = Selenium::WebDriver.for :chrome
      # http://watir.com/guides/chrome/
      args = ['--ignore-certificate-errors', '--disable-popup-blocking', '--disable-translate', '--disk-cache-size 8192']
      browser = Watir::Browser.new :chrome, headless: true, options: {args: args}
      browser.goto(url)
      sleep(2) # wait for the loading
      doc = Nokogiri::HTML(browser.html)
      browser.close
    end
    puts doc.text if @verbose
    return doc
  rescue => ee
    puts "Exception on method #{__method__} for #{url}: #{ee}"
    browser.close unless browser.nil?
    return doc.text
  end

  # Test the URL / site and return the redirection location (3xx response code only)
	def redirect_location (url)
		puts "Test the redirection location for the url: #{url}" if @verbose
		location=""
		raise "Invalid url: #{url}" unless is_url?(url)
		url=url.strip.downcase
		timeo = Max_http_timeout/1000.0
		uri = URI.parse(url)
		code = response_code (url)
		if code >= 300 && code < 400
			http = Net::HTTP.new(uri.host, uri.port)
			http.open_timeout = timeo
			http.read_timeout = timeo
			if (url =~ /https\:/i)
				http.use_ssl = true
				# Bypass the remote web server cert validation test
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.ssl_version = @ssl_version
			end
			request = Net::HTTP::Get.new(uri.request_uri)
			response = http.request(request)
			puts "Response: #{response}" if @verbose
			case response
			when Net::HTTPRedirection then
				location = response['location']
			end
		end
		return location
	rescue Exception => ee
		puts "Exception on method redirect_location for URL #{url}: #{ee}" if @verbose
		return ""
	end
	alias_method :location, :redirect_location

  # Test the URL / Site and return the landing url location (recursive with the depth = 4 )
	def landing_location (depth=5, url)
		depth -= 1
		return url if depth < 1
		timeo = Max_http_timeout/1000.0
		uri = URI.parse(url)
		code = response_code (url)
		if code >= 300 && code < 400
			url = redirect_location (url)
			url = landing_location(depth,url)
		else
			return url
		end
		return url
	rescue Exception => ee
		puts "Exception on method #{__method__} on URL #{url}: #{ee}" if @verbose
	end


  end
 end
end
