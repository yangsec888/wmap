require "wmap"

myDis = Wmap::CidrTracker.new(:verbose=>false)
@tbl=myDis.file_2_hash(ARGV[1])

def find(x)
	return @tbl.key?(x)
end

myDis.file_2_list(ARGV[0]).map do |x|
	puts x unless find(x)
end
