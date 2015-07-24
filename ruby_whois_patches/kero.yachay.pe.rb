#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      # Parser for the kero.yachay.pe server.
      #
      # @note This parser is just a stub and provides only a few basic methods
      #   to check for domain availability and get domain status.
      #   Please consider to contribute implementing missing methods.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class KeroYachayPe < Base

        property_supported :status do
          if content_for_scanner =~ /Status:\s+(.+?)\n/
            case $1.downcase
            when "active"
              :registered
            when "not registered"
              :available
            when "inactive"
              :inactive
            else
              Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            Whois.bug!(ParserError, "Unable to parse status.")
          end
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        property_not_supported :updated_on

        property_not_supported :expires_on

        property_supported :nameservers do
          if content_for_scanner =~ /\nName Servers:\n((.+\n)+)\n/
            $1.split(%r{\n}).map do |name|
              Record::Nameserver.new(:name => name.strip)
            end
          end
        end

        # Checks whether the response has been throttled.
        #
        # @return [Boolean]
        #
        # @example
        #   Looup quota exceeded.
        #
        def response_throttled?
          !content_for_scanner.match(/Looup quota exceeded./).nil?
        end

		# The following methods are implemented by Yang Li on 2/12/2013
		# ----------------------------------------------------------------------------

        property_supported :registrar do
          reg=Record::Registrar.new
		  reg["name"] = $1 if content_for_scanner =~ /^Registrar:\s+(.+)\n/
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Administrative Contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_not_supported :technical_contacts 

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /#{element}:\n((.+\n)+)\n/
			line_num=1
			$1.split(%r{\n}).each do |entry|
              entry=entry.strip
			  reg["name"]=entry if line_num==1
			  reg["organization"]=entry if line_num==1
			  reg["email"]=entry if entry =~ /.+\@.+\.\w+/
			  line_num=line_num+1
			end
		  end
		  return reg
        end	
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
