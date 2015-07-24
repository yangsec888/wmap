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
      # = whois.adamsnames.tc
      #
      # Parser for the whois.adamsnames.tc server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisAdamsnamesTc < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /is not registered/)
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        property_not_supported :updated_on

        property_not_supported :expires_on

        property_supported :nameservers do
          content_for_scanner.scan(/\s+ns\s+(.+?)\s+\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

		# The following methods are implemented by Yang Li on 02/26/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /domain name:\s+(.+)\n/i
        end
		
        property_not_supported :domain_id
		 
		property_supported :admin_contacts do
          build_contact("admin", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("owner", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("tech", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact("billing", Whois::Record::Contact::TYPE_BILLING)
        end
	
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /^#{element}\-contact:.+\n((.+\n)+)\n/i
			  $1.scan(/^#{element}\-(.+):\s+(.+)\n/).map do |entry|
				  reg["id"]=entry[1] if entry[0] =~ /contact/i
				  reg["name"]=entry[1] if entry[0] =~ /name/i
				  reg["organization"]=entry[1] if entry[0]=~ /organization/i
				  reg["address"]=entry[1] if entry[0]=~ /street/i
				  reg["city"]= entry[1] if entry[0]=~ /city/i
				  reg["zip"]=entry[1] if entry[0]=~ /zip/i
				  reg["country_code"]=entry[1] if entry[0]=~ /country/i
				  reg["phone"]=entry[1] if entry[0]=~ /phone/i
				  reg["fax"]=entry[1] if entry[0]=~ /fax/i
				  reg["email"]=entry[1] if entry[0]=~ /email/i
			  end		  
          end
		  return reg
        end	
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
