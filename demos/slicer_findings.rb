#!/usr/bin/ruby
# Simple script to slice and dice DMP 'Flaw Details' findings
# Usage: ./rpt_index.rb [list of report paths] 
################################################################################################
# Developed by: Yang Li, Version: 0.8, Last Modification: 09/28/2013
################################################################################################
require "wmap"
require "rubyXL"

@verbose=false			# set debugging bit
file_rpt="2015 Q1 Batch 02-3 Report.xlsx"
sites="non_absa_bcus_sites"
	
def parse_flaw_details (file)
	workbook = RubyXL::Parser.parse(file)
	worksheet = workbook[0].extract_data
	new_sheet = workbook.add_worksheet('Flaw Map')
	worksheet.size.times do |row|
		# Column B field 'Application', or index '1' of the spreadsheet 'Flaw Details', as the table joining key
		url=worksheet[row][1].to_s
		new_sheet.add_cell(row,0,url)
		if Wmap::HostTracker.instance.is_url?(url)
			if @my_sites.key?(url)
				puts "Match found: #{url}" if @verbose
				for col in 1..worksheet[row].size
					new_sheet.add_cell(row,col,worksheet[row][col-1])
				end
			else
				new_sheet.add_cell(row,1,"NA")
				next
			end
		else
			new_sheet.add_cell(row,1,"NA")
			next
		end
	end
	k=nil
	workbook.save
	workbook=nil
end

################################################################################################
# Main 
################################################################################################

puts "Loading mapping sites from file: #{sites}"
@my_sites=Wmap::HostTracker.instance.file_2_hash(sites)
puts "Working on mapping out the flaw details ..."
parse_flaw_details(file_rpt)
puts "Done. The mapping details should be available in the new sheet of file: #{file_rpt}"

