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

      #
      # = whois.je parser
      #
      # Parser for the whois.je server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisJe < Base

        property_supported :status do
          if content_for_scanner =~ /Status:\s+(.+?)\n/
            case $1.downcase
              when "active"
                :registered
              when "not registered"
                :available
              else
                Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            Whois.bug!(ParserError, "Unable to parse status.")
          end
        end

        property_supported :available? do
          (status == :available)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Created:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Modified:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_not_supported :expires_on

        property_supported :nameservers do
          if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
            $1.split("\n").map do |name|
              Record::Nameserver.new(:name => name.strip)
            end
          end
        end

		# The following methods are implemented by Yang Li on 02/27/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /^Query:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
			reg["name"] = $1 if content_for_scanner =~ /^Registrar Name:(.+)\n/i
			reg["organization"] = $1 if content_for_scanner =~ /^Registrar Name:(.+)\n/i
			reg["url"] = $1 if content_for_scanner =~ /^Registration URL:(.+)\n/i		
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :admin_contacts 

        property_not_supported :technical_contacts 

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /#{element}:\n((.+\n)+)\n/
			  $1.scan(/(.+):\s+(.+)\n/).map do |entry|
				  reg["name"]=entry[1] if entry[0] =~ /Name/i
				  reg["organization"]=entry[1] if entry[0]=~ /Organisation/i
			  end
		  end
		  return reg
        end	
		# ----------------------------------------------------------------------------
      end

    end
  end
end
