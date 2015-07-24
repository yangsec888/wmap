require "wmap"
k=Wmap::NetworkProfiler.new(:verbose=>true)
k.profile(ARGV[0])
