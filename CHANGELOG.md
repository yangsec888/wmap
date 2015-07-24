#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++

# Change-log


## Mile-stones

- October 2012: Start working on the BESTwebDiscvoery API project
- April 2013: Test on the production process, preparing for the Beta release
- March 2013: Work on the new object oriented framework, rebuild the project from scratch
- May 2013: First release of web_discovery gem package 1.1.0
- November 2014: Re-name from web_discovery to wmap, re-factor the code base to better scale up 
	across the board, and end user friendly
	
### Backward Incompatibilities

- List of features that are backward incompatible:


## Beta Release 1.x

#	04/14/2015	Fix bug in 'trust'/'distrust' executables, so that they could properly handle CIDR as input format.
#	04/02/2015	Removing tracking of the 'un-reponsive' http site under 'Wmap::SiteTracker' class.
#	03/30/2015	Fix a bug in 'bulk_refresh' method under 'Wmap::SiteTracker' class.
#	03/24/2015	Implement 'wcheck' executable support to improve user experience.
#	03/23/2015	Implement 'wadds' executable support to improve user experience.  
#	02/19/2015	Bug fix on url_2_site method to handle rare cases containing "#" or "?" special chars.
#	02/18/2015	Implement the tcp port-scanner executable 'wscan'. 
#	02/17/2015	A bug fix on the Wmap::Utils.normalize_url method, where the rare case of trailing dot after hostname could 
#				  properly removed as well. 
#	02/11/2015	A bug fix on the Wmap::SiteTracker.get_prim_uniq_sites method, where host resolved to multiple IPs could 
#				  cause exception in the rare case. 
#	02/10/2015	Implement the 'singleton' module in the Wmap::HostTracker::PrimaryHost class
#	02/05/2015	Implement singleton pattern on the Wmap::DomainTracker::SubDomain, Wmap::SiteTracker::DeactivatedSite class.  
#	02/03/2015	Implement singleton pattern on the logger module, re-organize the log file structure and location. 
#	01/30/2015	Implement the singleton pattern on the Wmap::SiteTracker, Wmap::DomainTracker class. 
#	01/27/2015	Separate the logger sub-module and implement the singleton pattern on the logger. 
#	01/24/2015	Implement the 'singleton' module in the Wmap::HostTracker class, in order to avoid race condition 
#				  under the parallel engine
#	01/08/2015	Implement the Ruby MiniTest Unit-test frame-work, with the first unit test file 'utils_test.rb'
#	12/15/2014	Replace the instance variables @known_hosts, @known_sites with class variables
#				 across all modules,i.e. enforcing the singleton pattern to avoid race condition under parallel execution.
#	11/17/2014	Re-factor the code Wmap::SiteTracker, optimize the 'dump' and 'dump_xml' methods. 
#	11/14/2014	Change the package name from "WebDiscovery" version 1.5.3 to "Wmap" to simple reason, start with version 1.0  
#	11/13/2014	Add XML support as the program output format, i.e. 'save_uniq_sites_xml' method for WebDiscovery::SiteTracker class 
#	11/01/2014	Add 'add' and 'delete' methods for WebDiscovery::CidrTracker class, in order to make it self-contained and user friendly. 
#	10/31/2014	Add executables (trust, distrust etc..) under bin directory, so that the application is more user friendly 
#	10/28/2014	Add parallel support in the HostTracker, SubDomain classes. 
#	10/27/2014	Add 'prime', 'wdump' bin executables, to manually set the prime host, and to dump out unique sites 
#				 in the site tracking data repository respectively. 
#	10/21/2014	Re-implement bulk_refresh method under WebDiscovery::SiteTracker class,
#				 with parallel engine support.
#	09/29/2014	Add 'save' method to WebDiscovery::UrlCrawler class. 
#	09/08/2014	Support parallel and add 'checks' method to WebDiscovery::UrlChecker class, in order to 
#				 scale up. 
#	08/04/2014	Add brute_all method for WebDiscovery::DnsBruter class. 
#	07/21/2014	Add consistency checks for WebDiscovery::SiteTracker::Dump method. 
#	07/08/2014	Add stop_hostname method in the class WebDiscovery::HostTracker; enhance the DnsBruter methods
#				 accordingly.
#	05/19/2014	Add site_ip_known? method in the class WebDiscovery::SiteTracker
#	03/31/2014	Add deduplicate procedures in the class WebDiscovery::HostTracker::PrimaryHost
#	02/10/2014	Add additional class WebDiscovery::DomainTracker::SubDomain to better manage sub-domains
#				 make changes in DomainTracker, HostTracker, and executable 'wd' accordingly
#	02/07/2014	Add additional class WebDiscovery::SiteTracker::DeactivatedSite and logic to record 
#				 the decommissioned or no longer accessible site
#	01/21/2014	Introduce 'hostname_mutation' method into WebDiscovery::DnsBruter class
#	01/15/2014	Modify WebDiscovery::Utils::UrlMagic class and add URL 'normalize' method
#	01/14/2014	Modify WebDiscovery::UrlCrawler class and set hard stop limit of crawler time-out to 
#				1 0 minutes per instance.
#   01/06/2014	Revamp WebDiscovery::UrlCrawler class, to make it more readable and scalable. 
#   12/19/2013	Add new method 'SiteTracker.site_check', to pull out a record from the site store. 
#   12/04/2013	Extend the usage of the 'parallel' to the 'SiteTracker.refresh_all' method, in order to
#				 scale up the completion time.
#   11/06/2013	Include GeoIPLite into the gem pack and modify the links under GeoIPTracker class.
#   10/29/2013	Fix a small bug in the 'HostTracker.bulk_add' method
#   10/21/2013	Change the data structure of domain_tracker class, to include open zone transfer
#                information. 
#   10/09/2013	Add additional logic to handle Dnsruby::ServFail type error intelligently in order to 
#                optimize the DnsBruter speed. 
#   10/08/2013	Add additional logic to avoid repeating crawling the same link by different child processes. 
#   10/04/2013	Add additional logic to profile the web server to improving the crawler speed
#   09/30/2013	Add additional logic to eliminate crawling duplicate sites for the multi-threaded crawlers.
#   09/23/2013  Optimize the DNS bruter code, as we have a large number of internet domains/sub-domains
#				 that cause overflow when using the array concatenation method.   
#   09/09/2013  Fix of error handling of "Connection reset by peer" in 'url_checker' class,
#				 along with other minors  
#   07/16/2013  Add an intelligent network profiler to maximize the port scanner performance.  
#   06/24/2013  Add support to map CN in the ssl sites into the primary host table. 
#   06/11/2013  Fix some minor bugs within the dns_bruter class
#   05/29/2013  Implement Google search scraper for Google search engine discovery.
#   05/20/2013  Support sub-domain identification and brute-forcing by: a) add 'get_subdomains' method in 
#				 the 'DomainRoot' module; b) add 'dump_sub_domains' method in the 'HostTracker' class; 
#				 c) implement 'dns_brute_subdomains' method in the 'DnsBruter' class 
#   05/16/2013  Add 'server' type into 'SiteTracker' data structure, implement a simple 'search' method. 
#   05/15/2013  Implement the 'get_server_header' method for the UrlChecker class
#   05/08/2013  Implement the 'resolve_ip_sites' method for the SiteTracker class
#   05/07/2013  Implement GeoIP tracker class WebDiscovery::GeoIPTracker, which wrap around the  
#				 Ruby GeoIP 1.1.0 gem - http://geoip.rubyforge.org/
#   05/06/2013  Add methods in the WebDiscovery::Whois class to extract netname and description 
#				 when performing whois lookup for an IP address 
#   05/02/2013  Change data structure for the 'SiteTracker' class, add service port field 
#				 for better tracking purpose; add an ASCII art banner
#   04/25/2013  Add method to retrieve common name from a server cert in the 'UrlChecker' class 
#   04/23/2013  Fully test out the port scanner, DNS bruter and the main executable; 
#				 change README.txt to README.rdoc; create Rakefile
#   04/18/2013  patch main executable 'webDiscovery' to make it flexible for the users 
#   04/15/2013  Finish major re-haul of the code base. Now it's broke into OO code-let 
#	03/11/2013	Add support for country code second level domain lookup
#	02/25/2013	Implement new methods to handle the internet domain seed file
#	12/12/2012	Re-factor the crawler code; add new feature of the hosts cache table for
#				 local domain name (reverse) lookup  
#	11/30/2012	Phase out the dependency on the 'dig' command; replace it with the native 
#				 Ruby 'resolv', and 'dnsruby' modules instead 
#	11/27/2012	Re-factor 'get_domain_root' method, fix a bug there
#	11/21/2012	Implement the 'whois' wrapper for the domain research
#	11/16/2012	Implement @know_cidr_blks class hash for discovered app labelling
#	11/15/2012	Optimize the algorithm used by the method 'ip_known?'
#	11/14/2012	Fix small bug in method 'host_2_ips'
#	11/13/2012	Fix small bugs handling url case-insensitivity
#	11/08/2012	Add methods for host discovery via open zone transfer
#	11/07/2012	Add the dns_brute_force method
#	11/06/2012	Re-factor the crawler code
#	11/05/2012	Bug fix on the class attributes access
#	10/28/2012	Bug fix on the reverse-dns lookup method
#	10/26/2012	Implement a web crawler for website crawling and link extraction
#	10/24/2012	Re-factor the port discovery method for better performance 
#	10/23/2012	Implement the port discovery method 
#	10/22/2012	Implement a simple HTTP service detection method
#	10/21/2012	Implement a simple TCP port scanner, and SSL socket detection methods
#	10/20/2012	Implement the IP address validation process
#	10/19/2012	Reimplement the URL status check method	
#	10/18/2012	Implement proprietary URI manipulation methods
#	10/17/2012	Refine and reimplement the DNS query methods and process 
#	10/16/2012	Start from the drawing board, prototype BESTwebDiscovery class.
#	10/15/2012	Exam the simple domain foot-printing Ruby script from the GDS pen tester

## Alpha Release 0.1.0

* First release with everything in one file for fast prototype purpose
