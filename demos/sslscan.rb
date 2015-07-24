# This Ruby driver script depends on the sslscan http://sourceforge.net/projects/sslscan/ 
# Enter command "sslscan" to check if it's already installed in your system
# I need this driver, because native sslscan only support one thread (too slow), and it
#    hanged during a large job.
#
# Usage: ruby sslscan.rb [list of ssl enabled webserver in host:port format]
# version 0.1, date 12/10/2014, by Yang Li

require "parallel"
require "wmap"

@verbose=true	# debugging bit
max_parallel=30

def ssl_scan (target)
	# Worker to wrap around sslscan executable
	f_out=target+".xml"
	shell_cmd = "sslscan --xml=" + f_out + " " +  target
	result=system(shell_cmd)
end

#####################Program Main######################

myDis=Wmap::UrlChecker.new
targets=myDis.file_2_list(ARGV[0])


Parallel.map(targets, :in_processes => max_parallel) { |target|
	ssl_scan(target)
}.each do |process| 				
	if process.nil?
		next
	else
		
	end				
end
				

puts "\nAll Done!\nPlease check out all the .xml reports under your current directory."
#########################################################

