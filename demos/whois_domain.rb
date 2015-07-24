# Automated whois lookup for a list of valid domains
# Usage: ruby whois_domain.rb [file_hosts] 
# Input file format: one line for each host (FQDN)
# Output file format: good old CSV format, with whois response parsed and sorted into structured fields.
require	"wmap"

puts Wmap.banner
dis=Wmap::DomainTracker.instance
dis.verbose=false
puts "Domain Whois Lookup Summary Report"
puts "Host | Domain | Primary Domain Name Server | Registrant Name | Registrant Oraganization | Registrant Address | Registrant Zip | Registrant City | Registrant State | Registration Country | Registration Contact Phone | Registration Contact Email | Technical Contact Name | Technical Contact Organization | Technical Contact Country | Technical Contract Phone | Technical Contact Email | Admin Contact Name | Admin Contact Organization | Domain Availability"
f_hosts = File.open(ARGV[0], 'r')
f_hosts.each do |line|
	#next if line.chomp =~ /\d+\.\d+\.\d+\.\d+/
	begin
		host=line.chomp.split(',')[0]
		#url=line.chomp.split(',')[0]
		#host=dis.url_2_host(url)
		domain=dis.domain_root(host)
		record=Hash.new
		if domain.nil?
			puts "#{line.chomp} | Domain Unknown"
#		elsif dis.domain_known?(domain)
#			next	
		else
			result=Wmap.whois(domain)
			puts result if dis.verbose
			record['ns'] = result.nameservers.first unless result.nameservers.nil?
			unless result.registrant_contacts.nil?
				result.registrant_contacts.each do |contact_r|
					 record['r_name']=contact_r['name']
					 record['r_org']=contact_r['organization']
					 record['r_addr']=contact_r['address'].gsub(/\n/,',').gsub(/\r/,' ') unless contact_r['address'].nil?
					 record['r_zip']=contact_r['zip']					 
					 record['r_city']=contact_r['city']
					 record['r_state']=contact_r['state']
					 record['r_country']=contact_r['country_code']
					 record['r_phone']=contact_r['phone']
					 record['r_email']=contact_r['email']
				end
			end
			unless result.technical_contacts.nil?
				result.technical_contacts.each do |contact_t|
					 record['t_name']=contact_t['name']
					 record['t_org']=contact_t['organization']
					 record['t_country']=contact_t['country_code']
					 record['t_phone']=contact_t['phone']
					 record['t_email']=contact_t['email']					
				end
			end
			unless result.admin_contacts.nil?
				result.admin_contacts.each do |contact_a|
					 record['a_name']=contact_a['name']
					 record['a_org']=contact_a['organization']				 
				end
			end
			if result.available? 
				record['availability']="true"
			else
				record['availability']="false"
			end
		end
		print "#{line.chomp} | #{domain} | "
		if record.nil?
			print " | Failure to parse the whois response. Please add it manually. "
		else
			print record['ns'], '|'
			print record['r_name'], ' | ', record['r_org'],' | ', record['r_addr'],' | ', record['r_zip'],' | ', record['r_city'],' | ', record['r_state'],' | ', record['r_country'],' | ', record['r_phone'],' | ', record['r_email']
			print ' | ', record['t_name'], ' | ', record['t_org'],' | ', record['t_country'],' | ', record['t_phone'],' | ', record['t_email']
			print ' | ', record['a_name'], ' | ', record['a_org'],' | ', record['availability']
		end
		print "\n"				
	rescue => ee
		puts "#{line.chomp} | #{domain} | #{ee}"
	end	
end
f_hosts.close
