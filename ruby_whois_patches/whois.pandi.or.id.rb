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
      # = whois.pandi.or.id parser
      #
      # Parser for the whois.pandi.or.id server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisPandiOrId < Base

        property_supported :status do
          if content_for_scanner =~ /domain-status:\s+(.+)\n/
            case $1.downcase
            when "object is active"
              :registered
            else
              Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            :available
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /^Not found/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /Creation Date:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last Updated On:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expiration Date:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/^Name Server:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end
		
        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain Name:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/^(.*Registrar.*):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] =~ /Sponsoring/i
			reg["organization"] = entry[1] if entry[0] =~ /Sponsoring/i
		  end
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Admin Contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Tech Contact", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact("Billing Contact", Whois::Record::Contact::TYPE_BILLING)
        end
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/^(#{element}.*):\s+(.+)\n/).map do |entry|
              reg["id"]=entry[1] if entry[0] =~ /ID/
          end
		  return reg
        end	
		
      end

    end
  end
end
