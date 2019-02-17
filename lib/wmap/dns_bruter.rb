#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "dnsruby"
require "parallel"


# Class to discover valid hosts through either zone transfer or DNS brute-force methods
class Wmap::DnsBruter
	include Wmap::Utils

	attr_accessor :hosts_dict, :verbose, :max_parallel, :data_dir
	attr_reader :discovered_hosts_from_dns_bruter, :fail_domain_cnt

	# Set default instance variables
	def initialize (params = {})
		# Change to your brute-force dictionary file here if necessary
		@data_dir=params.fetch(:data_dir, File.dirname(__FILE__)+'/../../data/')
		Dir.mkdir(@data_dir) unless Dir.exist?(@data_dir)
		@file_hosts = @data_dir + 'hosts'
		@file_hosts_dict = File.dirname(__FILE__)+'/../../dicts/hostnames-dict.txt'

		@verbose=params.fetch(:verbose, false)
		@discovered_hosts_from_dns_bruter=Hash.new
		@hosts_dict=params.fetch(:hosts_dict, @file_hosts_dict)
		@max_parallel=params.fetch(:max_parallel, 30)
		@fail_domain_cnt=Hash.new
	end

	# Main worker to perform the brute-forcing on an Internet domain
	def dns_brute_worker(host)
		puts "Start DNS brute forcer on: #{host}"
		results=Hash.new
		domain=get_domain_root(host)
		begin
			host=host.strip.downcase
			raise "Invalid internet host format: #{host}" unless is_fqdn?(host)
			domain=get_domain_root(host)
			# If we can do the zone transfer, then the brute-force process can be skipped.
			if zone_transferable?(domain)
				hosts=zone_transfer(domain)
			else
				hosts=brute_force_dns(host)
			end
			results[domain]=hosts
			puts "Finish discovery on #{host}: #{results}"
			return results
		rescue Exception=>ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return results
		end
	end
	alias_method :query, :dns_brute_worker
	alias_method :brute, :dns_brute_worker

	# Parallel DNS brute-forcer operating on target domain list - by utilizing fork manager to spawn multiple child processes on multiple domains simultaneously
	def dns_brute_workers(list,num=@max_parallel)
		puts "Start the parallel engine one the domain list: #{list} \nMaximum brute-forcing session: #{num} "
		begin
			targets=list.uniq.keep_if { |x| is_fqdn?(x) }
			results=Hash.new
			Parallel.map(targets, :in_processes => num) { |target|
				dns_brute_worker(target)
			}.each do |process|
				if process.nil?
					next
				elsif process.empty?
					#do nothing in case of thrown an empty array
				else
					#domain=get_domain_root(process.first).downcase
					results.merge!(process)
				end
			end
			puts "Parallel DNS brute-force results: #{results}" if @verbose
			@discovered_hosts_from_dns_bruter.merge!(results)
			return results
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end
	alias_method :queries, :dns_brute_workers
	alias_method :brutes, :dns_brute_workers

	# Parallel DNS brute-forcer operating on target domain file - by utilizing fork manager to spawn multiple child processes on multiple domains simultaneously
	def dns_brute_file(file_target,num=@max_parallel)
		puts "Start the parallel brute-forcing with multiple child processes on target file #{file_target}: #{num}"
		begin
			hosts=Array.new
			targets=file_2_list(file_target)
			hosts=dns_brute_workers(targets,num)
			return hosts
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return hosts
		end
	end

	# Perform zone transfer on a domain, return found host entries in an array
	def zone_transfer(domain)
		puts "Perform zone transfer on zone: #{domain}"
		domain=domain.downcase
		nameservers = get_nameservers(domain)
		hosts=Array.new
		puts "Retrieved name servers: #{nameservers}" if @verbose
		nameservers.each do |nssrv|
			begin
				puts "Attempt zone transfer on name server: #{nssrv}"
				if nssrv.nil?
					abort "Method input variable error: no name server found!" if @verbose
					next
				end
				zt = Dnsruby::ZoneTransfer.new
				zt.server=nssrv unless nssrv.empty?
				records = zt.transfer(domain)
				if records==nil
					puts "Zone transfer failed for zone #{domain} on: #{nssrv}"
					next
				else
					puts "Zone transfer successfully for zone #{domain} on the name server: #{nssrv}"
					records = records.delete_if {|x| not x.to_s=~/(\s+|\t+)IN/ }
					records.each  { |line| puts line.to_s } if @verbose
					hosts=records.collect {|x| x.to_s.split(/\.(\s+|\t+)/).first}
					hosts=hosts.sort!.uniq!
					puts "Found hosts: #{hosts}" if @verbose
					@discovered_hosts_from_dns_bruter[domain] = hosts
					return hosts
				end
			rescue Exception=>ee
				puts "Exception on method #{__method__}: #{ee}" if @verbose
			end
		end
		return hosts
	end

	# Test the DNS server if zone transfer is allowed. If allowed, save the found hosts into the class variable.
	def get_vulnerable_ns(domain)
		puts "Identify the vulnerable DNS servers if zone transfer is allowed."
		domain=domain.strip.downcase
		vuln=Array.new
		begin
			nameservers = get_nameservers(domain)
			nameservers.each do |nssrv|
				zt = Dnsruby::ZoneTransfer.new
				zt.server=nssrv unless nssrv.empty?
				records = zt.transfer(domain)
				unless records==nil
					vuln.push(nssrv)
				end
			end
			return vuln
		rescue Exception=>ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Return a list of valid hosts by brute-forcing the name servers
	def brute_force_dns (host)
		puts "Start dictionary attacks on the DNS server for: #{host}" if @verbose
		begin
			host=host.strip
			valid_hosts = Array.new
			my_host_tracker = Wmap::HostTracker.instance(:data_dir=>@data_dir)
			# build the host dictionary for the brute force method
			dict = Array.new
			if File.exists?(@hosts_dict)
				dict = file_2_list(@hosts_dict)
			elsif File.exists?(@file_hosts)
				dict = my_host_tracker.top_hostname(200)
				my_host_tracker.list_2_file(dict,@hosts_dict)
			else
				abort "Error: Non-existing common hosts dictionary file - #{@host_dict} or hosts file #{@file_hosts}. Please check your file path and name setting again."
			end
			domain=String.new
			unless is_root_domain?(host) or my_host_tracker.sub_domain_known?(host)
				my_hosts=hostname_mutation(host).map {|x| x.split('.')[0]}
				dict+=my_hosts unless my_hosts.empty?
			end
			if is_domain?(host) or my_host_tracker.sub_domain_known?(host)
				domain=host
			elsif
				array_h=host.split('.')
				array_h.shift
				domain=array_h.join('.')
				puts "Domain for #{host}: #{domain}" if @verbose
			end
			dict+=[host.split(".")[0],""]
			puts "Choose Brute-force Dictionary: #{dict}" if @verbose
			cnt=0
			dict.each do |x|
				# 10/09/2013 add logic to skip brute-forcing the domain in case of experiencing more than 2 Dnsruby::ServFail conditions
				if @fail_domain_cnt.key?(domain)
					if @fail_domain_cnt[domain]>2
						puts "Error! Multiple ServFail conditions detected in method #{__method__}. Now skip remaining works on: #{sub_domain}" if @verbose
						return valid_hosts
					end
				end
				cnt=cnt+1
				if x.nil?
					next
				elsif x.empty?
					host=domain
				else
					host=[x,".",domain].join.downcase
				end
				valid_hosts.push(host) if valid_dns_record?(host)
				# Logic to detecting the bluff if the DNS server return hostname we threw to it
				if cnt==10 && valid_hosts.size>=10
					valid_hosts=[host]
					puts "Brute force method fail, as the DNS server response to every host-name threw at it!"
					break
				end
			end
			puts "Found DNS records on domain #{host}: #{valid_hosts}" if @verbose
			@discovered_hosts_from_dns_bruter[host] = valid_hosts
			my_host_tracker = nil
			return valid_hosts.uniq
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Parallel DNS brute-forcer operating on the trusted domains - by utilizing fork manager to spawn multiple child processes on multiple sub_domain domains from the local hosts table simultaneously
	def dns_brute_domains(targets,num=@max_parallel)
		puts "Start the parallel brute-forcing with multiple child processes: #{num}"
		begin
			hosts=Array.new
			# Sliced to chunks of 1,000 domains for each process time, to avoid potential overflow of large array ?
			puts "Brute-forcing the following domain: #{targets}" if @verbose
			targets.each_slice(1000).to_a.map do |slice|
				hosts_new=dns_brute_workers(slice,num)
				hosts << hosts_new
			end
			puts "Parallel bruting result: #{hosts.flatten}" if @verbose
			return hosts.flatten
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return hosts.flatten
		end
	end

	# Parallel DNS brute-force all existing domains
	def brute_all(num=@max_parallel)
		puts "Start the parallel brute-forcing all domains with maximum child processes: #{num}"
		begin
			hosts=Array.new
			my_dis=Wmap::HostTracker.instance(:data_dir=>@data_dir)
			known_domains=my_dis.dump_root_domains
			hosts=dns_brute_domains(num, known_domains)
			my_dis.adds(hosts)
			my_dis.save!
			my_dis=nil
			hosts
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
		end
	end

	# Return a list of hosts in the mutation form from the original, i.e. "ww1.example.com" => ["ww1,example.com","ww2.example.com",...]
	def hostname_mutation(host)
		puts "Start host mutation emulation on: #{host}" if @verbose
		begin
			hosts=Array.new
			host=host.strip.downcase
			raise "Invalid host format: #{host}" unless is_fqdn?(host)
			unless is_domain_root?(host)
				hostname=host.split('.')[0]
				hosts.push(host)
				case hostname
				when /\d+/
					#first form of mutation, i.e. "ww1" => ["ww1","ww2",...]
					hostname.scan(/\d+/).map do |x|
						y=x.to_i
						5.times do |i|
								z=y+i+1
								w=(y-i-1).abs
								mut1=host.sub_domain(x,z.to_s)
								mut2=host.sub_domain(x,w.to_s)
								hosts.push(mut1,mut2)
						end
					end
				else
					puts "No mutation found for: #{host}" if @verbose
				end
			end
			puts "Host mutation found: #{hosts.uniq}" if @verbose
			return hosts.uniq
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return hosts	# fail-safe
		end
	end
	alias_method :mutation, :hostname_mutation

	# Print summary report of found hosts from the brute force attacks
	def print_discovered_hosts_from_bruter
		puts "\nSummary Report of the Discovered Hosts:"
		@discovered_hosts_from_dns_bruter.each do |domain,hosts|
			puts "Domain: #{domain}"
			puts "Found hosts:"
			puts @discovered_hosts_from_dns_bruter[domain]['hosts']
		end
		puts "End of the summary"
	end
	alias_method :print, :print_discovered_hosts_from_bruter
end
