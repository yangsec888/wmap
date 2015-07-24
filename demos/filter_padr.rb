#!/usr/bin/ruby
# Simple script to create an index.html page for the Dynamic MP report repository
# Usage: ruby filter_padr.rb [Appsec Quarterly xlsx report file]
################################################################################################
# Developed by: Yang Li, Version: 0.3, Last Modification: 01/05/2015
################################################################################################# filter to map known relationship in the PADR spreadsheet back to the perimeter scan data set
# Input is the perimeter datafile
# Output is modified datafile with known relationship

require "wmap"
require "rubyXL"

# Change The Update Mapping key file Here:
file_map = "PADR-Formatted-02052015.xlsx"
# File to be processed: 
file_rpt = "2015 Q1 Batch 02-3 Report.xlsx"

@verbose=true
@map_pa=Hash.new
@flaw_details=Hash.new

def parse_padr (file)
	# default mapping relationship
	workbook = RubyXL::Parser.parse(file)
	worksheet = workbook[0].extract_data

	worksheet.size.times do |row|
		# Column K of 'PADR-xxx' file field'URL' as the mapping key
		url=worksheet[row][10].to_s
		urls=Array.new
		case url
			when /\,|\;/; urls=url.split(%r{\,|\;\s+})
			else; urls.push(url)
		end
		match="No"  # If the PADR entry's IP match to local known host list
		urls.map do |entry|
			entry.strip!
			next if entry.nil?
			host=Wmap::HostTracker.instance.url_2_host(entry)
			ip=String.new
			if Wmap::HostTracker.instance.is_ip?(host)
				ip = host
			else
				ip = Wmap::HostTracker.instance.local_host_2_ip(host)
				ip = Wmap::HostTracker.instance.host_2_ip(host) unless ip.nil?
			end
			unless ip.nil? or ip.empty?
				@map_pa[ip]=worksheet[row] unless @map_pa.has_key?(ip)
				if Wmap::HostTracker.instance.ip_known?(ip)
					match="Yes"
				end
			end
		end
		puts match if @verbose
	end
	puts "Parsing done. Number of entries found: #{@map_pa.keys.size}"
	workbook=nil
end

def parse_flaw_details (file)
	workbook = RubyXL::Parser.parse(file)
	# Load the 'Flaw Details' worksheet as the base
	worksheet = workbook[1].extract_data
	new_sheet = workbook.add_worksheet('Flaw Map')
	worksheet.size.times do |row|
		# Column A field 'Application', or index '0' of the spreadsheet 'Flaw Details', as the table joining key
		url=worksheet[row][1].to_s.strip
		new_sheet.add_cell(row,0,url)
		if Wmap::HostTracker.instance.is_url?(url)
			host=Wmap::HostTracker.instance.url_2_host(url)
			if Wmap::HostTracker.instance.is_ip?(host)
				ip = host
			else
				ip = Wmap::HostTracker.instance.local_host_2_ip(host)
			end
			if ip.nil? or ip.empty?
				new_sheet.add_cell(row,1,"NA")
				next
			elsif @map_pa.key?(ip)
				puts "Match found: #{ip}" if @verbose
				for col in 1..@map_pa[ip].size
					new_sheet.add_cell(row,col,@map_pa[ip][col-1])
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

parse_padr(file_map)
puts "Debugging: dumping out relation map: #{@map_pa}" if @verbose # for trouble-shooting
parse_flaw_details(file_rpt)
puts "Done. The mapping information should be available in the new sheet of xlsx file: #{file_rpt}"

