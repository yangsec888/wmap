######################################################
# Extract findings information from the DMP raw XML report
# So that we can manipulate the data into the Barclays Excel report formats
# Usage: ruby rpt.rb [file with paths of xml reports] [DMP Excel Keys File]
#          $ ruby rpt.rb xml_rpts2 excelkeys.csv
#
# Developed by Yang Li, 07/25/2013
#
######################################################

require "nokogiri"
require "csv"

@verbose=false
@findings=Hash.new

def	parse_dmp_rpt (xml_file)
	puts "Extract the site name from the xml report file: #{xml_file}" if @verbose
	begin
		doc = Nokogiri::XML(File.open(xml_file))
		#site = doc.css("detailedreport").attr("app_name").to_s
		site = doc.css("detailedreport dynamic-analysis modules module").attr("target_url").value.to_s
		categories=doc.css("detailedreport category")
		categories.map do |cat|
			cat_name = cat.attr("categoryname")
			cat_rec = cat.css("recommendations para").attr("text")
			cat.css("cwe").map do |cwe|
				cwe_id = cwe.attr("cweid")
				cwe.css("dynamicflaws flaw").map do |flaw|
					flaw_name=flaw.attr("categoryname")
					flaw_url=flaw.attr("url")
					flaw_id=flaw.attr("issueid")
					flaw_desc=flaw.attr("description")
					flaw_cnt=flaw.attr("count").to_i
					flaw_parameter=flaw.attr("vuln_parameter")
					puts "Break point -1" if @verbose
					entry = site + "," + cwe_id + "," + flaw_url + ","
					
					if flaw_parameter.nil?
						entry+="N/A"
					else
						entry+=flaw_parameter
					end
					puts "Entry: #{entry}" if @verbose
					# Save the information into our instance variable
					puts "Break point 0" if @verbose
					@findings[entry]=Hash.new unless @findings.key?(entry)
					@findings[entry]['name']=flaw_name if @findings[entry]['name'].nil?
					@findings[entry]=Hash.new unless @findings.key?(entry)
					puts "Break point 1" if @verbose
					@findings[entry]['desc']=String.new if  @findings[entry]['desc'].nil? 
					@findings[entry]['desc']=@findings[entry]['desc']+flaw_desc+" CHAR(10) "
					puts "Break point 2" if @verbose
					@findings[entry]['rec']=cat_rec if @findings[entry]['rec'].nil?
					puts "Break point 3" if @verbose
					@findings[entry]['ids']=String.new if @findings[entry]['ids'].nil?				
					@findings[entry]['ids']=@findings[entry]['ids']+flaw_id+","
					puts "Break point 4" if @verbose
					@findings[entry]['cnt']=0 if @findings[entry]['cnt'].nil?
					@findings[entry]['cnt']=@findings[entry]['cnt']+flaw_cnt
				end
			end
		end
		return site
	rescue => ee
		puts "Error on method #{__method__}: #{ee}" if @verbose
		return nil
	end
end

def print_findings
	puts "\n\nPrint out all findings summary report" if @verbose
	begin
		@findings.keys.map do |entry|
			puts "Findings for entry: #{entry}" if @verbose
			puts "Flaw Name, Issue IDs, Flaw Count"

			puts "#{@findings[entry]['name']}, #{@findings[entry]['ids']}, #{@findings[entry]['cnt']}"
		end	
	rescue => ee
		puts "Error on method #{__method__}: #{ee}" if @verbose
		return nil
	end
end

# Parse all xml reports in one shot, save the findings data into our data structure @findings
puts "Start on parsing all the DMP XML reports in file: #{ARGV[0]}" if @verbose
f_xmls=File.open(ARGV[0], 'r')
f_xmls.each_line do |line|
	site_name=parse_dmp_rpt(line.chomp)
	puts "Done processing site: #{site_name}" if @verbose
end
f_xmls.close

# print_findings

# Look up for the missing information from our data structure
# And write it into a report
CSV.open("./result.csv", "wb") do |csv|
	csv << ["IssueIDs", "Description", "Remediation"]
	f_keys=File.open(ARGV[1], 'r') # open Excel key file to read
	# Sample key string: http://157.83.142.100/,297,https://157.83.142.100/,N/A
	f_keys.each_line do |line|
		entry=line.chomp.strip
		if entry =~  /141.228.146.173/i
			puts "Entry: #{entry}" if @verbose
		end
		if @findings.key?(entry)
			csv << [@findings[entry]['ids'], @findings[entry]['desc'], @findings[entry]['rec'] ]
		else
			csv << [" "]  # empty string in case of no match found
		end
	end
	f_keys.close

end
