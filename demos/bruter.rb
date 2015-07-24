# Brute-forcing multiple domains at the same time, the purpose is to extract a valid host list
# Usage: ruby dns_brute.rb [file with list of domains]
require "wmap"

f_rpt=".rpt.txt"
# Step 1 - obtain list of domains to be brute-forced on
root_domains=Wmap::HostTracker.instance.dump_root_domains
sub_domains=Wmap::HostTracker.instance.dump_sub_domains
# Step 2 - multi-thread brute forcer works on known domains and sub-domains 
k=Wmap::DnsBruter.new(:verbose=>true, :max_parallel=>50)
#hosts=k.dns_brute_file(ARGV[0])
results=k.dns_brute_workers(sub_domains+root_domains)
k=nil
#hosts=hosts1+hosts2
# Step 3 - save results to a local file for debugging
f=File.open(f_rpt,"w")
results.each_pair do |key,value|
  f.write("#{value}\n")
end
f.close
puts "Brute force results are saved successfully: #{f_rpt}"

# Step 4 - now update the local hosts table accordingly
Wmap::HostTracker.instance.bulk_add(results.values.flatten)
Wmap::HostTracker.instance.save!
