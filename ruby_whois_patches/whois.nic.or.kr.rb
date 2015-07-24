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

      # Parser for the whois.nic.or.kr server, on the english section only; added by Yang Li 02/10/2013.
      class WhoisNicOrKr < Base

        property_supported :status do
          content_for_scanner.scan(/Publishes\s+:\s*(.+)\n/).flatten
        end

        property_supported :available? do
          !!(content_for_scanner =~ /is not registered:/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /Registered Date\s+:\s*(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Last updated Date\s+:\s*(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Expiration Date\s+:\s*(.+?)\n/
            Time.parse($1)
          end
        end
		
        property_supported :nameservers do
          content_for_scanner.scan(/Host Name\s+:\s*(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name.downcase)
          end
        end

        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/^(Authorized.*):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1].split('(')[0] if entry[0] =~ /Agency/i
			reg["organization"] = entry[1].split('(')[0] if entry[0] =~ /Agency/i
			reg["url"] = entry[1].split('(')[1].split(')')[0] if entry[0] =~ /Agency/i		
          end
		  return reg
        end
		
		property_supported :admin_contacts do
          build_contact_ac("AC", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :technical_contacts 

        property_not_supported :billing_contacts 
	
      private

        def build_contact_ac(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/^(.*#{element}.*):\s*(.+)\n/).map do |entry|
              reg["name"]=entry[1] if entry[0] =~ /Administrative\sContact/i		  
			  reg["phone"]=entry[1] if entry[0]=~ /phone/i
			  reg["email"]=entry[1] if entry[0]=~ /E\-Mail/i
          end
		  return reg
        end	

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/(#{element}.*):\s*(.+)\n/).map do |entry|
              reg["name"]=entry[1] if entry[0].strip == "Registrant"		  
			  reg["address"]=entry[1] if entry[0]=~ /Address/i
			  reg["zip"]=entry[1] if entry[0]=~ /Zip\sCode/i
          end
		  return reg
        end	
		
      end
    end
  end
end
