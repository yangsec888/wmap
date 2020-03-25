#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require 'wmap/utils/domain_root'
require 'wmap/utils/url_magic'
require 'wmap/utils/logger'
require 'wmap/utils/wp_detect'
require 'wmap/utils/utils'
require 'wmap/cidr_tracker'
require 'wmap/domain_tracker'
require 'wmap/domain_tracker/sub_domain'
require 'wmap/host_tracker'
require 'wmap/host_tracker/primary_host'
require 'wmap/whois'
require 'wmap/url_checker'
require 'wmap/network_profiler'
require 'wmap/port_scanner'
require 'wmap/url_crawler'
require 'wmap/url_crawler/adware_tag'
require 'wmap/dns_bruter'
require 'wmap/site_tracker'
require 'wmap/site_tracker/deactivated_site'
require 'wmap/site_tracker/wp_tracker'
require 'wmap/geoip_tracker'
require 'wmap/google_search_scraper'

module Wmap

  NAME            = "Wmap"
  GEM             = "wmap"
  VERSION		  = File.dirname(__FILE__) + "/../version.txt"

  class << self
	attr_accessor :known_internet_domains
	attr_writer   :verbose

	# Simple parser for the project version file
	def read_ver
		ver=Hash.new
		f=File.open(VERSION,'r')
		f.each do |line|
			line.chomp!
			case line
			when /^(\s)*#/
				next
			when /\=/
				entry=line.split("=").map! {|x| x.strip}
				ver[entry[0]]=entry[1]
			end
		end
		f.close
		return ver
	end

	# Project banner in ASCII Art 'soft' format, courtesy to http://patorjk.com/software/taag/
	def banner
		ver=read_ver
		art=",--.   ,--.       ,--.       ,--.   ,--.
|  |   |  | ,---. |  |-.     |   `.'   | ,--,--. ,---.  ,---.  ,---. ,--.--.
|  |.'.|  || .-. :| .-. '    |  |'.'|  |' ,-.  || .-. || .-. || .-. :|  .--'
|   ,'.   |\   --.| `-' |    |  |   |  |\ '-'  || '-' '| '-' '\   --.|  |
'--'   '--' `----' `---'     `--'   `--' `--`--'|  |-' |  |-'  `----'`--'
                                                `--'   `--'                  "
		string = "-"*80 + "\n" + art + "\n" + "Version: " + ver["version"] + "\tRelease Date: " + ver["date"] + "\nDesigned and developed by: " + ver["author"] + "\nEmail: " + ver["email"] + "\tLinkedIn: " + ver["linkedin"] + "\n" + "-"*80
	end

  def data_dir(data_path)
    @data_dir=data_path.to_s
  end

	# Explorer to discover and inventory web application / service automatically
	def wmap(seed)
    if @data_dir
      cmd = "bin/wmap" + " -d " + @data_dir + " -t " + seed
    else
		    cmd="bin/wmap" + " -t " + seed
    end
		system(cmd)
	end

	# Crawler to search url contents for new sites
	def crawl(url)
		crawler=Wmap::UrlCrawler.new
		crawler.crawl(url)
	end

	# whois query and sort the result into structured data
	def whois(domain)
		whois=Wmap::Whois.new(:verbose=>false)
		whois.query(domain)
	end

	# Fast tcp port scanner on a single host or IP
	def scan(host)
		scanner=Wmap::PortScanner.new
		scanner.scan(host)
	end

	# Fast multi-processes tcp port scanner on a list of targets
	def scans(target_list)
		scanner=Wmap::PortScanner.new
		scanner.scans(target_list)
	end

	# CIDR Tracking - check the host against the local CIDR seed file, return the CIDR tracking path if found
	def track(host)
		tracker=Wmap::CidrTracker.new
		tracker.cidr_worker(host)
	end

	# GeoIP Tracking - check the host / IP against the GeoIP data repository, return the Geographic information if found
	def geoip(host)
		tracker=Wmap::GeoIPTracker.new
		tracker.query(host)
	end

	# URL checker - check the status of the remote URL
	def check(url)
		checker=Wmap::UrlChecker.new(:verbose=>false)
		checker.url_worker(url)
	end

	# Check if the IP is within the range of the known CIDR blocks
	def ip_trusted?(ip)
		tracker=Wmap::CidrTracker.new
    if @data_dir
      tracker.data_dir=@data_dir
      tracker.cidr_seeds=tracker.data_dir + "/" + "cidrs"
      tracker.load_cidr_blks_from_file(tracker.cidr_seeds)
    end
		tracker.ip_trusted?(ip)
	end

	# Domain Tracking - check with the trust domain seed file locally, to determine if it's a new internet domain
	# NOT to confuse with the Internet 'whois' lookup
	def domain_known?(domain)
		tracker=Wmap::DomainTracker.instance
    if @data_dir
      tracker.data_dir=@data_dir
      tracker.domains_file=tracker.data_dir + "/" + "domains"
      tracker.load_domains_from_file(tracker.domains_file)
    end
		tracker.domain_known?(domain)
	end

	# Host Tracking - check local hosts file to see if this is a hostname known from the host seed file
	# NOT to confuse with a regular DNS lookup over the internet
	def host_known?(host)
		tracker=Wmap::HostTracker.instance
    if @data_dir
      tracker.data_dir = data_dir
      tracker.hosts_file = tracker.data_dir + "/" + "hosts"
      tracker.load_known_hosts_from_file(tracker.hosts_file)
    end
    tracker.host_known?(host)
	end

	# Sub-domain tracking - check local hosts file to see if the sub-domain is already known
	def sub_domain_known?(host)
		tracker=Wmap::HostTracker.instance
    if @data_dir
      tracker.data_dir = data_dir
      tracker.hosts_file = tracker.data_dir + "/" + "hosts"
      tracker.load_known_hosts_from_file(tracker.hosts_file)
    end
    tracker.sub_domain_known?(host)
	end

	# IP Tracking - check local hosts file to see if this is an IP known from the seed file
	# NOT to confuse with a regular reverse DNS lookup over the internet
	def ip_known?(ip)
		tracker=Wmap::HostTracker.instance
    if @data_dir
      tracker.data_dir = data_dir
      tracker.hosts_file = tracker.data_dir + "/" + "hosts"
      tracker.load_known_hosts_from_file(tracker.hosts_file)
    end
    tracker.ip_known?(ip)
	end

	# DNS Brute Forcer
	def dns_brute(domain)
		bruter=Wmap::DnsBruter.new
		bruter.query(domain)
	end

	# Retrieve root domain from a host
	def domain_root(host)
		Wmap::Utils.get_domain_root(host)
	end

	# Log the information into file
	def wlog(msg,agent,log_file)
		Wmap::Utils.wlog(msg,agent,log_file)
	end

	# Host-name mutation for catch easily guessable hostname, i.e. "ww1.example.com" => ["ww1,example.com","ww2.example.com",...]
	def mutation (host)
		Wmap::DnsBruter.new.hostname_mutation(host)
	end

	# Check URL/Site response code
	def response_code(url)
		checker=Wmap::UrlChecker.new
		checker.response_code(url)
	end

	# Search the site repository for all entries that match the pattern
	def search(pattern)
		searcher=Wmap::SiteTracker.instance
    if @data_dir
      searcher.data_dir = @data_dir
      searcher.sites_file = searcher.data_dir + "/" + "sites"
      searcher.load_site_stores_from_file(searcher.sites_file)
    end
		searcher.search(pattern)
	end

	# Dump out the unique sites into a plain file
	def dump(file)
			store=Wmap::SiteTracker.instance
      if @data_dir
        store.data_dir = @data_dir
        store.sites_file = searcher.data_dir + "/" + "sites"
        store.load_site_stores_from_file(searcher.sites_file)
      end
			store.save_uniq_sites(file)
	end

	# Dump out the unique sites into a XML file
	def dump_xml(file)
			store=Wmap::SiteTracker.instance
      if @data_dir
        store.data_dir = @data_dir
        store.sites_file = searcher.data_dir + "/" + "sites"
        store.load_site_stores_from_file(searcher.sites_file)
      end
      store.save_uniq_sites_xml(file)
	end

	# Refresh the site information in the local data repository
	def refresh(site)
			store=Wmap::SiteTracker.instance
      if @data_dir
        store.data_dir = @data_dir
        store.sites_file = searcher.data_dir + "/" + "sites"
        store.load_site_stores_from_file(searcher.sites_file)
      end
			store.refresh(site)
			store.save!
	end

	# Refresh the site information in the local data repository
	def refresh_all
			store=Wmap::SiteTracker.instance
      if @data_dir
        store.data_dir = @data_dir
        store.sites_file = searcher.data_dir + "/" + "sites"
        store.load_site_stores_from_file(searcher.sites_file)
      end
			store.refresh_all
			store.save!
	end

	# Search the Google engines and sort out sites known by Google
	def google
		sites=Wmap::GoogleSearchScraper.new.workers.keys
	end

	# Print a site's full information from the repository
	def print(site)
		searcher=Wmap::SiteTracker.instance
		searcher.print_site(site)
	end

	# Print a site's full information from the repository
	def print_all
		searcher=Wmap::SiteTracker.instance
    if @data_dir
      searcher.data_dir = @data_dir
      searcher.sites_file = searcher.data_dir + "/" + "sites"
      searcher.load_site_stores_from_file(searcher.sites_file)
    end
    searcher.print_all_sites
	end

  private



  end
end
