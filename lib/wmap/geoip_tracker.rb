#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
require "geoip"


# Wrapper class of the 'GeoIP' library - http://geoip.rubyforge.org/
# For detail explanation of Geographic information of an IP address (GeoIP) and its data repository, please refer to the vendor MaxMind (http://www.maxmind.com)
class Wmap::GeoIPTracker
	include Wmap::Utils
	
	attr_accessor :db, :verbose
	
	# This product includes GeoLite data created by MaxMind, available from
	# <a href="http://www.maxmind.com">http://www.maxmind.com</a>.
	Db_city=File.dirname(__FILE__)+"/../../dicts/GeoLiteCity.dat"
	Db_asn=File.dirname(__FILE__)+"/../../dicts/GeoIPASNum.dat"
	Db_country=File.dirname(__FILE__)+"/../../dicts/GeoIP.dat"
	
	# Set default instance variables
	def initialize (params = {})		
		@verbose=params.fetch(:verbose, false)
		@db=params.fetch(:db, Db_city)
	end

	# Wrapper for the Ruby GeoIP City class - return data structure below on successful lookup 
	# Struct.new(:request, :ip, :country_code2, :country_code3, :country_name, :continent_code, :region_name, :city_name, :postal_code, :latitude, :longitude, :dma_code, :area_code, :timezone)
	def city(object)	
		puts "Perform GeoIP city lookup on: #{object}" if @verbose
		begin
			object=object.strip
			raise "Unknown object format - only valid hostname or IP is accepted: #{object}" unless is_ip?(object) or is_fqdn?(object)
			GeoIP.new(Db_city).city(object)
		rescue Exception => ee
			puts "Exception on method city: #{object}" if @verbose
			return nil
		end
	end	
	alias_method :query, :city

	# Wrapper for the Ruby GeoIP Country class - return data structure below on successful lookup 
	# Struct.new(:request, :ip, :country_code, :country_code2, :country_code3, :country_name, :continent_code)
	def country(object)	
		puts "Perform GeoIP country lookup on: #{object}" if @verbose
		begin
			object=object.strip
			raise "Unknown object format - only valid hostname or IP is accepted: #{object}" unless is_ip?(object) or is_fqdn?(object)
			GeoIP.new(Db_country).country(object)
		rescue Exception => ee
			puts "Exception on method country: #{object}" if @verbose
			return nil
		end
	end	

	# Wrapper for the Ruby GeoIP ASN class - return data structure below on successful lookup 
	# Struct.new(:number, :asn)
	def asn(object)	
		puts "Perform GeoIP ASN lookup on: #{object}" if @verbose
		begin
			object=object.strip
			raise "Unknown object format - only valid hostname or IP is accepted: #{object}" unless is_ip?(object) or is_fqdn?(object)
			GeoIP.new(Db_asn).asn(object)
		rescue Exception => ee
			puts "Exception on method asn: #{object}" if @verbose
			return nil
		end
	end	
end
