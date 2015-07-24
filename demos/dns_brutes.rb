# Brute-forcing multiple domains at the same time, the purpose is to extract a valid host list
# Usage: ruby dns_brute.rb [file with list of domains]
require "wmap"

f_rpt=".rpt.txt"
# Step 1 - obtain list of domains to be brute-forced on
tracker=Wmap::HostTracker.new
root_domains=tracker.dump_root_domains
sub_domains=tracker.dump_sub_domains
# Step 2 - multi-thread brute forcer works on known domains and sub-domains 
k=Wmap::DnsBruter.new(:verbose=>false, :max_parallel=>50)
#hosts=k.dns_brute_file(ARGV[0])
#hosts = k.dns_brute_domains(root_domains)
hosts=k.dns_brute_domains(sub_domains)
k=nil
#hosts=hosts1+hosts2
# Step 3 - save results to a local file for debugging
f=File.open(f_rpt,"w")
hosts.map do |x|
  f.write("#{x}\n")
end
f.close
puts "Brute force results are saved successfully: #{f_rpt}"

# Step 4 - now update the local hosts table accordingly
tracker.bulk_add(hosts)
tracker.save!
tracker=nil
