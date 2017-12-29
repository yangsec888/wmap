#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "net/ping"
require "parallel"

# Port scanner class for the web application discovery and tracking
class Wmap::PortScanner
	include Wmap::Utils

	attr_accessor :socket_timeout, :http_timeout, :discovery_tcp_ports, :max_parallel, :verbose
	attr_reader :discovered_urls

	# Use default common web service port list for the discovery
	File_discovery_ports=File.dirname(__FILE__)+'/../../settings/discovery_ports'
	# set hard limit of socket time-out to 3 seconds to avoid performance penalty
	Max_socket_timeout=3000

	# Set default instance variables
	def initialize (params = {})
		@verbose=params.fetch(:verbose, false)
		@socket_timeout=params.fetch(:socket_timeout, 1500)
		@http_timeout=params.fetch(:http_timeout, 5000)
		@max_parallel=params.fetch(:max_parallel, 40)
		# Initialize the instance variables
		@discovery_tcp_ports=params.fetch(:discovery_tcp_ports, file_2_list(File_discovery_ports).map!{|x| x.to_i} )
		@discovered_urls=Hash.new
	end

	# Pre-scan worker, to be used for network profiling to maximum the scan performance, for instance.
	def pre_scan(host)
		puts "Perform pre-scan works on host: #{host}" if @verbose
		begin
			# Use the following formula to 'guess' the right network time-out threshold for the scanner
			nwk_to=Wmap::NetworkProfiler.new.profile(host)
			if (100 + nwk_to*2).to_i > Max_socket_timeout
				@socket_timeout=Max_socket_timeout
			else
				@socket_timeout=(100 + nwk_to*2).to_i
			end
			puts "Done with the pre-scan works: reset @socket_timeout to: #{@socket_timeout}" if @verbose
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			return nil
		end
	end

	# Main worker method that run through the discovery ports list, check if any response to the HTTP request on the open ports, and finally return the findings in the URL format as an array
	def scan (host)
		puts "Perform web service discovery on host: #{host}"
		begin
			pre_scan(host)
			urls=Array.new
			@discovery_tcp_ports.map do |port|
				if tcp_port_open?(host,port)
					url=host_2_url(host,port)
					urls.push(url) unless url.nil?
				end
			end
			if urls.empty?
				puts "No web service detected. "
			else
				urls.map do |url|
					unless @discovered_urls.key?(url)
						@discovered_urls[url]=true
					end
				end
				puts "Detected web service on host #{host}: #{urls}"
			end
			return urls
		rescue Exception => ee
			puts "Exception on method #{__method__}  for #{host}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :query, :scan

	# Parallel scanner - by utilizing fork manager 'parallel' to spawn numbers of child processes on multiple hosts/IPs simultaneously
	def scans (targets,num=@max_parallel)
		begin
			urls=Array.new
			# 10/5/2013 add additional logic to eliminate invalid /duplicate target(s)
			targets -= ["", nil]
			uniq_hosts=Hash.new
			targets.dup.map do |target|
				if is_fqdn?(target) or is_ip?(target)
					ip=host_2_ip(target).to_s
					if uniq_hosts.key?(ip)
						targets.delete(target)
					else
						uniq_hosts[ip]=true
					end
				end
			end
			if targets.size > 0
				puts "Start the parallel port scan on the target list:\n #{targets}"
				Parallel.map(targets.shuffle, :in_processes => num) { |target|
					scan(target)
				}.each do |process|
					if process.nil?
						next
					elsif process.empty?
						#do nothing
					else
						process.map do |url|
							unless @discovered_urls.key?(url)
								@discovered_urls[url]=true
							end
						end
						urls+=process
					end
				end
			end
			puts "Port scanning done successfully with the found web services: #{urls}"
			return urls
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end

	# Parallel scans on a list of CIDRs from the input file, return the findings as the website construct within an array
	def scan_file(file,num=@max_parallel)
		puts "Start the parallel scans on the target file: #{file}"
		begin
			list=load_target_file(file)
			urls=scans(list,num)
		rescue Exception => ee
			puts "Error on method #{__method__}: #{ee}" if @verbose
			return nil
		end
		return urls
	end
	alias_method :file_scan, :scan_file

	# Prepare and load the target list from a target file
	def load_target_file (file)
		puts "Preparing the discovery target file: #{file}" if @verbose
		begin
			targets=Array.new
			f=File.open(file,'r')
			f.each do |line|
				line=line.chomp.strip
				next if line.nil?
				next if line.empty?
				next if line =~ /^\s*#/
				line=line.split(',')[0]
				if is_cidr?(line)
					ips=cidr_2_ips(line)
					targets+=ips
				elsif is_ip?(line) or is_fqdn?(line)
					targets.push(line)
				elsif is_url?(line)
					host=url_2_host(line)
					targets.push(host)
				else
					puts "Unknown entry in the seed file: #{line}"
				end
			end
			f.close
			return targets
		rescue Exception => ee
			puts "Error on method #{__method__} on file #{file} exception: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :load, :load_target_file

	# A simple TCP port scanner. This is the basic element of the port scanner. Notice the default time-out is set by the default instance variable @socket_timeout
	def tcp_port_open? (host,port)
		puts "Perform open port detection on: #{host}:#{port}, time-out: #{@socket_timeout} ms" if @verbose
		#@socket_timeout = socket_timeout
		timeo = @socket_timeout/1000.0						# change time-out unit from sec to ms
		begin
            if Net::Ping::TCP.new(host,port,timeo).ping
				puts "Port open!" if @verbose
                return true
            else
				puts "Port down." if @verbose
                return false
            end
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			return false
		end
	end

	# Print out the summary report of discovered sites
	def print_discovered_urls
		puts "Print out port discovery results." if @verbose
		puts "Summary of Discovered Sites:"
		@discovered_urls.keys.sort.map { |x| puts x }
		puts "End of Summary."
	end
	alias_method :print, :print_discovered_urls

	# Count number of new found sites
	def count
		return @discovered_urls.size
	end

	private :load_target_file

end
