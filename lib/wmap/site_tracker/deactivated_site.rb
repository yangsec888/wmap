#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
#require "singleton"


# Class to trace de-activated site. This is need for basic state tracking for our sites.

module Wmap
class SiteTracker

class DeactivatedSite < Wmap::SiteTracker
	include Wmap::Utils
	#include Singleton

	attr_accessor :sites_file, :known_sites, :verbose

	# Set default instance variables
	def initialize (params = {})
		# Initialize the instance variables
		@f_sites=File.dirname(__FILE__)+'/../../../data/deactivated_sites'
		@file_stores=params.fetch(:sites_file, @f_sites)
		@verbose=params.fetch(:verbose, false)
		# Hash table to hold the site store
		File.write(@file_stores, "") unless File.exist?(@file_stores)
		@known_sites=load_site_stores_from_file(@file_stores)
	end

	# Deactivate obsolete entrance from the live site store. Note this method is used by the parent class only
	def add (site,entry)
		begin
			puts "Deactivate site: #{site}" if @verbose
			@known_sites[site]=Hash.new unless @known_sites.key?(site)
			@known_sites[site]['ip']=entry['ip']
			@known_sites[site]['port']=entry['port']
			@known_sites[site]['status']=entry['status']
			@known_sites[site]['server']=entry['server']
			@known_sites[site]['md5']=entry['md5']
			@known_sites[site]['redirection']=entry['redirection']
			@known_sites[site]['timestamp']=entry['timestamp']
			@known_sites[site]['code']=entry['code']
			puts "Deactivate site entry loaded: #{entry}"
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end

	end

	# Refresh re-activated entrance in the store. Note this method is used by the parent class only
	def delete (site)
		begin
			puts "Reactivate site: #{site}" if @verbose
			site=site.strip.downcase unless site.nil?
			@known_sites.delete(site)
			puts "Site removed from the de-activated list."
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end

	end

	# Procedures to discover deactivated sites from the live site store to here in one shot (TBD).
	def update_from_site_store!
		puts "Invoke internal procedures to update the site store."
		begin
		# To be further developed
		rescue Exception => ee
			puts "Exception on method #{__method__}: #{ee}" if @verbose
			return nil
		end
	end
	alias_method :update!, :update_from_site_store!


end

end
end
