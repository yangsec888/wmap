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
      # = whois.norid.no parser
      #
      # Parser for the whois.norid.no server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNoridNo < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /% no matches/)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Created:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last updated:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :expires_on

		# The following methods are implemented by Yang Li on 02/12/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain Name\.+:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  reg["id"] = node("Registrar Handle")	
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Domain Holder Handle", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Legal\-c Handle", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Tech\-c Handle", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          content_for_scanner.scan(/Name Server Handle\.+:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name +  " - handle reference online at http://www.norid.no/domenenavnbaser/whois/kopirett.html")
          end
        end
		
        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  reg["id"]=node(element)
		  content_for_scanner.scan(/((.+\n)+)\n/).each do |x|
			str=x.flatten.join
			if str.include?(node(element))
			  str.scan(/^(.+?)\.+:\s+(.+)\n/).map do |entry|              
				  reg["name"]=entry[1] if entry[0] =~ /Name$/
				  reg["address"]=entry[1] if entry[0]=~ /Post Address/i
				  reg["city"]= entry[1] if entry[0]=~ /Postal Area/i
				  reg["zip"]=entry[1] if entry[0]=~ /Postal Code/i
				  reg["state"]=entry[1] if entry[0]=~ /#{element}\sState\/Province/i
				  reg["country_code"]=entry[1] if entry[0]=~ /Country/i
				  reg["phone"]=entry[1] if entry[0]=~ /Phone Number/i
				  reg["fax"]=entry[1] if entry[0]=~ /Fax Number/i
				  reg["email"]=entry[1] if entry[0]=~ /Email/i
			  end
            end
		  end
		  return reg
        end	
		
		def node(element)
			return $1 if content_for_scanner =~ /^#{element}\.+:\s*(.+)\n/
		end
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
