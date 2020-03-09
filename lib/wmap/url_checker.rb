#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "net/http"
require 'httpclient'
require "openssl"
require "uri"
require "digest/md5"
require "parallel"

# A quick checker class to identify / finger-print a URL / site
class Wmap::UrlChecker
	include Wmap::Utils
	attr_accessor :http_timeout, :max_parallel, :verbose, :data_dir

	def initialize (params = {})
		# Set default instance variables
		@verbose=params.fetch(:verbose, false)
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@http_timeout=params.fetch(:http_timeout, 5000)
		@max_parallel=params.fetch(:max_parallel, 40)
		@ssl_version=nil
		@url_code={}
		@url_redirection={}
		@url_finger_print={}
		@url_server={}
	end

	# Main worker method to perform various checks on the URL / site
	def url_worker (url)
		puts "Checking out an unknown URL: #{url}" if @verbose
		url=url.strip.downcase
		raise "Invalid URL format: #{url}" unless is_url?(url)
		timestamp=Time.now
		host=url_2_host(url)
		ip=host_2_ip(host)
		port=url_2_port(url)
		code=10000
		if @url_code.key?(url)
			code=@url_code[url]
		else
			code=response_code(url)
		end
		if code>=300 && code < 400
			loc=landing_location(4,url)
		else
			loc=nil
		end
		if @url_finger_print.key?(url)
			fp=@url_finger_print[url]
		else
			fp=response_body_md5(url)
		end
		if @url_server.key?(url)
			server=@url_server[url]
		else
			server=get_server_header(url)
		end
		# save the data
		checker=Hash.new
		checker['ip']=ip
		checker['port']=port
		checker['url']=url
		checker['code']=code
		checker['redirection']=loc
		checker['md5']=fp
		checker['server']=server
		checker['timestamp']=timestamp
		if Wmap::CidrTracker.new(:data_dir=>@data_dir).ip_trusted?(ip)
			checker['status']="int_hosted"
		else
			checker['status']="ext_hosted"
		end
		return checker
	rescue OpenSSL::SSL::SSLError => es  # handler to temporally hold the openssl bug in bay:  SSL_set_session: unable to find ssl method
		checker=Hash.new
		checker['ip']=ip
		checker['port']=port
		checker['url']=url
		checker['code']=20000
		checker['server']="Unknown SSL error: #{es}"
		checker['md']=nil
		checker['redirection']=nil
		checker['timestamp']=timestamp
		return checker
	rescue Exception => ee
		puts "Exception on method #{__method__} for #{url}: #{ee}" # if @verbose
		return nil
	end
	alias_method :check, :url_worker

	# Parallel scanner - by utilizing fork manager 'parallel' to spawn numbers of child processes on multiple urls simultaneously
	def url_workers (targets,num=@max_parallel)
		results=Array.new
		targets -= ["", nil]
		if targets.size > 0
			puts "Start the url checker on the targets:\n #{targets}"
			Parallel.map(targets, :in_processes => num) { |target|
				url_worker(target)
			}.each do |process|
				if process.nil?
					next
				elsif process.empty?
					#do nothing
				else
					results << process
				end
			end
		end
		return results
	rescue Exception => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return nil
	end
	alias_method :checks, :url_workers

	# Test the URL / site and return the web server type from the HTTP header "server" field
	def get_server_header (url)
		puts "Retrieve the server header field from the url: #{url}" if @verbose
		server=String.new
		raise "Invalid url: #{url}" unless is_url?(url)
		url=url.strip.downcase
		timeo = @http_timeout/1000.0
		uri = URI.parse(url)
		code = response_code (url)
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
		server=response["server"]
		server=server.gsub(/\,/,' ')
		return server
	rescue Exception => ee
		puts "Exception on method get_server_header for URL #{url}: #{ee}" if @verbose
		@url_server[url]=server
		return server
	end

	# Use MD5 algorithm to fingerprint the URL / site response payload (web page content)
	def response_body_md5(url)
		puts "MD5 finger print page body content: #{url}" if @verbose
		raise "Invalid url: #{url}" unless is_url?(url)
		url=url.strip.downcase
		timeo = @http_timeout/1000.0
		uri = URI.parse(url)
		fp=""
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
		response_body = response.body.to_s
		fp=Digest::MD5.hexdigest(response_body) unless response_body.nil?
		@url_finger_print[url] = fp
		return fp
	rescue Exception => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
	end
	alias_method :md5, :response_body_md5

	# Retrieve the remote web server certification, open it and return the cert content as a string
	def get_certificate (url)
		puts "Retrieve the remote web server SSL certificate in clear text: #{url}" if @verbose
		url=url.strip
		raise "Invalid URL string: #{url}" unless is_ssl?(url)
		client = HTTPClient.new
		client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
		response = client.get(url)
		cert = response.peer_cert
		cer = OpenSSL::X509::Certificate.new(cert)
		return cer.to_text
	rescue Exception => ee
		puts "Exception on method #{__method__} from #{url}: #{ee}"
		return nil
	end
	alias_method :get_cert, :get_certificate

	# Retrieve the X509 cert in the clear text from the remote web server, extract and return the common name field within the cert
	def get_cert_cn (url)
		puts "Extract the common name field from a X509 cert: #{cert}" if @verbose
		cert=get_certificate(url)
		subject, cn = ""
		if cert =~ /\n(.+)Subject\:(.+)\n/i
			subject=$2
		end
		if subject =~/CN\=(.+)/i
			cn=$1
		end
		return cn
	rescue Exception => ee
		puts "Error on method #{__method__} from #{url}: #{ee}" if @verbose
		return nil
	end
	alias_method :get_cn, :get_cert_cn

end
