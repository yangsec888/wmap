# Sample Script to Map The Known Business Info to the Veracode DMP scan Data
# Usage: ruby map.rb [old.txt] [new sites list] 
require	"wmap"




# Extract known business info from the old report
def parse_old 
	tracker = Wmap::CidrTracker.new
	f_old=File.open(ARGV[0],'r')
	f_old.each do |line|
		entry=line.split('	')
		if entry.size > 10
			ip=entry[11].strip #
		else
			next
		end
		#puts ip
		if tracker.is_ip?(ip)
			@bmap[ip]=Hash.new if not @bmap.key?(ip)
			@bmap[ip]['b_ln']=entry[8].strip  if @bmap[ip]['b_ln'].nil?
			@bmap[ip]['sv_name']=entry[16].strip if @bmap[ip]['sv_name'].nil?
			@bmap[ip]['sv_code']=entry[15].strip  if @bmap[ip]['sv_code'].nil?
			@bmap[ip]['a_name']=entry[20]  if @bmap[ip]['a_name'].nil?
			@bmap[ip]['a_id']=entry[21]  if @bmap[ip]['a_id'].nil?
			@bmap[ip]['sc_l']=entry[7].strip  if @bmap[ip]['sc_l'].nil?
			@bmap[ip]['sc']=entry[19] if  @bmap[ip]['sc'].nil?
			#puts ip
		end
	end
	f_old.close
	
end

def print_map
	@bmap.keys.map do |ip|
		next if ip.nil?
		b_ln=@bmap[ip]['b_ln']
		sv_name=@bmap[ip]['sv_name']
		sv_code=@bmap[ip]['sv_code']
		a_name=@bmap[ip]['a_name']
		a_id=@bmap[ip]['a_id']
		sc_l=@bmap[ip]['sc_l']
		sc=@bmap[ip]['sc']
		puts "#{ip},#{b_ln},#{sv_name},#{sv_code},#{a_name},#{a_id},#{sc_l},#{sc}"
		
	end
end

@bmap=Hash.new
parse_old
cidr_tracker = Wmap::CidrTracker.new
site_tracker = Wmap::SiteTracker.instance
prime_tracker = Wmap::HostTracker::PrimaryHost.instance
#print_map
f_new=File.open(ARGV[1],'r')
f_new.each do |line|
	site=line.chomp.strip
	site=cidr_tracker.url_2_site(site)
	prime_site=String.new
	host=cidr_tracker.url_2_host(site)
	ip=Wmap::HostTracker.instance.local_host_2_ip(host)
	ip=Wmap::HostTracker.instance.host_2_ip(host) if ip.nil?
	# add logic to identify primary site (based on redirection and cert cn
	redirection=site_tracker.get_redirection_url(site)
	if site_tracker.is_url?(redirection)
		prime_site=site_tracker.url_2_site(redirection)
	elsif prime_tracker.host_known?(host)
		prime_site=site
	elsif prime_tracker.ip_known?(ip)
		prime_host=prime_tracker.local_ip_2_host(ip)
		prime_site=site.sub(host,prime_host)
	else
		prime_site=site
	end
	tracker=cidr_tracker.cidr_worker(ip)
	if @bmap.key?(ip)
		puts "#{site},#{prime_site},#{ip},#{tracker['cidr']},#{tracker['netname']},#{tracker['ref']},#{@bmap[ip]['b_ln']},#{@bmap[ip]['sv_name']},#{@bmap[ip]['sv_code']},#{@bmap[ip]['a_name']},#{@bmap[ip]['a_id']},#{@bmap[ip]['sc_l']},#{@bmap[ip]['sc']}"
	else
		puts "#{site},#{prime_site},#{ip},#{tracker['cidr']},#{tracker['netname']},#{tracker['ref']}"
	end

end
f_new.close
