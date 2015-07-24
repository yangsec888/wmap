#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "net/ping"


# Network profiler to optimize the port scanner performance for a specific network / IP. The ultimate goal is to set a reasonable socket time-out parameter for the scanners.
class Wmap::NetworkProfiler
	include Wmap::Utils
	
	attr_accessor :socket_timeout, :search_path, :max_parallel, :verbose
	attr_reader :latency		# Discovered network latency 
	File_discovery_ports=File.dirname(__FILE__)+'/../../settings/discovery_ports'	
	
	# Set default instance variables
	def initialize (params = {})		
		@verbose=params.fetch(:verbose, false)
		@socket_timeout=params.fetch(:socket_timeout, 1500)
		#@http_timeout=params.fetch(:http_timeout, 3000)
		@search_path=["/sbin/","/usr/sbin/","/usr/local/bin/","/usr/bin/","/opt/bin/","/opt/sbin/"]
		# Initialize the instance variables
		@discovery_tcp_ports=params.fetch(:discovery_tcp_ports, file_2_list(File_discovery_ports).map!{|x| x.to_i} )
	end

	# Main worker method that determine the right profiling methods
	def profile(host)	
		puts "Perform web service discovery on host: #{host}" if @verbose
		@latency = @socket_timeout
		begin
			if Process.euid == 0 && socket_icmp_pingable?(host)
				puts "Network profiling by using raw socket ..." if @verbose
			elsif shell_ping_exist? && shell_pingable?(host)
				puts "Network profiling by using external shell ping program ..." if @verbose
			elsif open_tcp_port?(host)
				puts "Network profiling by using TCP ping ..." if @verbose
			else
				puts "No appropriate profiling method for #{host}" if @verbose
				# Do nothing
			end
			puts "Found network latency for #{host}: #{@latency} ms" if @verbose
			return @latency
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			return nil
		end
	end
	
	# Perform raw socket ICMP echo detection on the host. Note that socket ICMP packet manipulation 
	#  need the root privilege access(for example, ICMP 'echo' need to snoop on the interface to detect any replies such as 'ECONNREFUSED'). 
	#  That's why we also use external ping program for the normal users in case they do not has the access.
	def socket_icmp_pingable? (target)
		puts "Perform socket ICMP ping on the target: #{target}" if @verbose
		begin
			timeo = @socket_timeout/1000.0						# change time-out unit from sec to ms
			p=Net::Ping::ICMP.new(target,nil,timeo) 
			if p.ping
				@latency=p.duration * 1000
				puts "Socket ICMP echo test successful on #{target}." if @verbose
				return true
			else
				puts "Socket ICMP echo test fail on #{target}." if @verbose
				return false
			end
		rescue Exception => ee
			puts "Error on method #{__method__} on target #{target}: #{ee}" if @verbose
			return false
		end
	end
	
	# Wrapper for local ping executable. This is needed if the process do not have the root privilege to operate 
	#   on the raw ICMP socket
	def shell_pingable? (target)		
		puts "Perform ping test from the shell on: #{target}" if @verbose
		begin
            sum=0
			test_ping= `#{@which_ping} -c 3 #{target}`
			test_ping.scan(/^(.+?)\stime=(.+)\s(.+?)\n/).map do |entry|
				puts "entry: #{entry}" if @verbose
				sum=sum+entry[1].to_f
			end
			if sum > 0
				@latency = sum / 3
				puts "Ping test from the shell environment successful on #{target}." if @verbose
				return true
			else
				puts "Ping test from the shell environment fail on #{target}." if @verbose
				return false
			end
		rescue Exception => ee
			puts "Exception on method #{__method__} for #{host}: #{ee}" if @verbose
			return false
		end
	end
	
	# Search for local ping executable program. This is helpful for the normal users who has no direct access to generate socket ICMP packets.
	def shell_ping_exist? 
		begin
			puts "Search local shell environment for the ping program ..." if @verbose
			@search_path.map do |path|
				ping_exe=path+"ping"
				if File.exist?(ping_exe) && File.executable?(ping_exe)
					@which_ping=ping_exe
					puts "Local ping program found: #{ping_exe}" if @verbose
					return true
				end
			end
			return false
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return false
		end
	end

	# Perform TCP Ping as a last resort of the network profiling effort, in case of ICMP tests fail.
	def open_tcp_port? (target)
		puts "Check if any TCP port in the list #{@discovery_tcp_ports} is open on the remote host: #{target}" if @verbose
		begin
			timeo = @socket_timeout/1000.0						# change time-out unit from sec to ms
			p=Net::Ping::TCP.new(target,nil,timeo) 
			@discovery_tcp_ports.map do |port|
				p.port=port
				if p.ping
					@which_port=port	
					# Bug in the current Net::Ping.ping module, where the 'duration' is 100 order off. We make it up here without fixing their code
					@latency = p.duration * 1000 * 100
					puts "TCP port detection successful on port: #{@which_port}" if @verbose
					return true
				end
			end
			puts "TCP port detection on remote host #{target} fail. " if @verbose
			return false
		rescue Exception => ee
			puts "Error on method #{__method__} on target #{target}: #{ee}" if @verbose
			return false
		end
	end
	
	private 
	
end
