#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++


module Wmap
 module Utils
  # Module to log debugging and other messages
  module Logger
	extend self
	# Append information into the log file for the trouble-shooting purpose
	def wlog (obj, agent, file)
		puts "Writing #{obj} into log file: #{file}" if @verbose
		return false if obj.nil?
		@@f=File.open(file,'a')
		timestamp=Time.now
		case obj
		when Array
			if obj.size >= 0
				@@f.write "#{timestamp}: #{agent}: \n"
				obj.map { |x| @@f.write "  #{x}\n" }
				puts "The list is successfully saved into the log file: #{file} " if @verbose
			end
		when Hash
			if obj.length >= 0
				@@f.write "#{timestamp}: #{agent}: \n"
				obj.each_value { |value| @@f.write "  #{value}\n" }
				puts "The hash is successfully saved into the log file: #{file} " if @verbose
			end
		when String
			@@f.write "#{timestamp}: #{agent}: #{obj}\n"
			puts "The string is successfully saved into the log file: #{file} " if @verbose
		else
			#do nothing
			puts "Un-handled exception on: #{obj}" if @verbose
		end
		@@f.close
		return true
	rescue => ee
		puts "Exception on method #{__method__}: #{ee}" if @verbose
		return false
	end

  end
 end
end
