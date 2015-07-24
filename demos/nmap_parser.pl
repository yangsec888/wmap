#!/usr/bin/perl
########################################################################
# Functional Description: 
#                                                                  
# nmap.pl is designed to be a quick nmap port discovery parser for web_discovery
#         the program input is NMAP discovery result XML file, the program output
#         is a list of websites that ready for wmap modules
#
#      For usage information, type in the following command:
# 	$ nmap_parser.pl -h
# 
########################################################################
# Designed and developed by:		Yang Li
#
# Change History: 
# Last modification: 	08/21/2013
#	Version		0.1
use Getopt::Long qw/:config bundling_override no_ignore_case/;
use Nmap::Parser;

my $ver="0.1", $author="Yang Li";				# Program Version and Author
my $verbose;							# Verbose mode for Maverick
my %opts;
GetOptions(
	\%opts,
	'help|h|?' => sub { &print_help and exit 0; },		# Print help
	'version|v:s' => sub { &print_banner; exit 0;},		# Print program version information
	'file|f:s',                  	 			# Program input file (.xml, .nmap)
	'output|o:s',               				# Optional, program output result file 
	'verbose+' => \$verbose,				# Optional, program verbose mode for debugging
	'vv+' => \$verbose,					# Same as "-verbose", abbreviation "-vv"
);		

sub parse_nmap_terse () {
  #
  ## Parse nmap result in xml format. Only open ports are kept. Web services are further filtered out
  #	
	# Check if the optional command switch "-output" is defined, and get ready for it if so.
	if (defined $opts{output}) { open (OUT, ">", $opts{output}) || die " Can't open the file 8: $opts{output} : $!\n"; }
	my $np=new Nmap::Parser;
	$np->parsefile($opts{file});
	my @HOST=$np->all_hosts("up");						# List of 'up' hosts
	if (defined $opts{output}) {
		print OUT "\nTable of Found Open Ports\n";
		print OUT"IP	Port	Status	Service	OS	Hostname\n";
		for my $up_host (@HOST){
			$os = $up_host->os_sig; $osname=$os->name;
			my $ip=$up_host->addr; my $hostname=$up_host->hostname();
			print  OUT "$ip\t\t\t\t$osname\t$hostname,\n"; 		# Addr: $up_host->addr, OS: $up_host->os_sig\n";	
			my @p_tcp=$up_host->tcp_open_ports;
			my @p_udp=$up_host->udp_open_ports;
			foreach(@p_tcp) {					# Print list of open tcp ports
				my $state=$up_host->tcp_port_state($_);
				my $svc = $up_host->tcp_service($_);
				my $svc_name = $svc->name;
				print OUT "\t$_\/tcp\t$state\t$svc_name\n";
			}
			foreach(@p_udp) {					# Print list of open udp ports
				my $state=$up_host->udp_port_state($_);
				my $svc = $up_host->udp_service($_);
				my $svc_name = $svc->name;
				print OUT "\t$_\/udp\t$state\t$svc_name\n";
			}
		}
	} else {		# Redirect to stdout if '-output' command switch is not defined
		print "List of found web services:\n";
		#print "IP	Port	Status	Service	OS	Hostname\n";
		for my $up_host (@HOST){
			$os = $up_host->os_sig; $osname=$os->name;
			my $ip=$up_host->addr; my $hostname=$up_host->hostname();
			#print "$ip\t\t\t\t$osname\t$hostname,\n"; # addr: $up_host->addr, OS: $up_host->os_sig\n";	
			my @p_tcp=$up_host->tcp_open_ports;
			my @p_udp=$up_host->udp_open_ports;
			foreach(@p_tcp) {					# Print list of open tcp ports
				my $port=$_;
				my $state=$up_host->tcp_port_state($_);
				my $svc = $up_host->tcp_service($_);
				my $svc_name = $svc->name;
				if ($svc_name =~ /https/i) {
					if ($hostname) {
						print "https://$hostname:$port/\n";
					} else {
						print "https://$ip:$port/\n";
					}
				} elsif ($svc_name =~ /http/i) {
					if ($hostname) {
						print "http://$hostname:$port/\n";
					} else {
						print "http://$ip:$port/\n"
					}
				}
				#print "\t$_\/tcp\t$state\t$svc_name\n";
			}
			foreach(@p_udp) {					# Print list of open udp ports
				my $port=$_;
				my $state=$up_host->udp_port_state($_);
				my $svc = $up_host->udp_service($_);
				my $svc_name = $svc->name;
				if ($svc_name =~ /https/i) {
					if ($hostname) {
						print "https://$hostname:$port/\n";
					} else { 
						print "https://$ip:$port/\n";
					}
				} elsif ($svc_name =~ /http/i) {
					if ($hostname) {
						print "http://$hostname:$port/\n";
					} else {
						print "http://$ip:$port/\n";
					}
				}
				#print "\t$_\/udp\t$state\t$svc_name\n";
			}	
		}
	}
	if (defined $opts{output}) {
		close (OUT);  				
		print "Done dumping out open ports table from $opts{file} to: $opts{output}.\n";
	}
	undef $np;
}

sub print_help {
		my $header= "#" x 80;
		print "$header\n nmap result quick parser.\n$header\n";
		print "Usage: perl nmap.pl -f [nmap xml file] > [result file with found web services]\n";
		print "Version: $ver, Developed by: $author\n"

}


############################################################
#	Main Program start here
############################################################

&print_help;
unless ($opts{file}) { print "Error: unknown program input. Please check your file again. \n"; exit 1; }
parse_nmap_terse ();
