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

      # Parser for the whois.rrpproxy.net server, added by Yang Li 02/10/2013.
      class WhoisRrpproxyNet < Base

		property_supported :admin_contacts do
          build_contact("admin-", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("owner-", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("tech-", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
	
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/^(#{element}.*):\s*(.+)\n/).map do |entry|
              reg["id"]=entry[1] if entry[0] =~ /contact/i
              if entry[0] =~ /(fname|lname)/i
				if reg["name"].nil?
					reg["name"]=entry[1]
				else 
					reg["name"]=reg["name"]+" "+entry[1]
				end
			  end			  
              reg["organization"]=entry[1] if entry[0]=~ /organization/i
              reg["address"]=entry[1] if entry[0]=~ /street/i
              reg["city"]= entry[1] if entry[0]=~ /city/i
              reg["zip"]=entry[1] if entry[0]=~ /zip/i
              reg["state"]=entry[1] if entry[0]=~ /state/i
			  reg["country_code"]=entry[1] if entry[0]=~ /country/i
			  reg["phone"]=entry[1] if entry[0]=~ /phone/i
			  reg["fax"]=entry[1] if entry[0]=~ /fax/i
			  reg["email"]=entry[1] if entry[0]=~ /email/i
          end
		  return reg
        end	
		
      end
    end
  end
end
