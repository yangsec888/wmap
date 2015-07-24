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

      # = whois.nic.lv parser
      #
      # Parser for the whois.nic.lv server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicLv < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
           !!(content_for_scanner =~ /Status: free/)
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        property_supported :updated_on do
          if content_for_scanner =~ /Changed:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_not_supported :expires_on        

        property_supported :nameservers do
          content_for_scanner.scan(/Nserver:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  if content_for_scanner =~ /^\[Registrar\]\n((.+\n)+)\n/
			contacts=$1
			contacts.scan(/(.+):(.+)\n/).map do |entry|
				reg["name"] = entry[1] if entry[0] =~ /Name/i
				reg["organization"] = entry[1] if entry[0] =~ /Name/i
				reg["url"] = entry[1] if entry[0] =~ /email/i		
			end
          end
		  return reg
        end 
		
		property_not_supported :admin_contacts

        property_supported :registrant_contacts do
          build_contact("Holder", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Tech", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner.gsub(/\//,'') =~ /^\[#{element}\]\n((.+\n)+)\n/i
			  contacts=$1
			  contacts.scan(/^(.+):\s+(.+)\n/).map do |entry|
				  reg["name"]=entry[1] if entry[0] =~ /Name/i
				  reg["organization"]=entry[1] if entry[0]=~ /Name/i
				  reg["address"]=entry[1] if entry[0]=~ /Address/i
				  reg["phone"]=entry[1] if entry[0]=~ /Phone/i
				  reg["fax"]=entry[1] if entry[0]=~ /Fax/i
				  reg["email"]=entry[1] if entry[0]=~ /Email/i
			  end			  
          end
		  return reg
        end	
		# ----------------------------------------------------------------------------

      end
    end
  end
end
