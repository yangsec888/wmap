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

      # Parser for the whois.above.com server, added by Yang Li 02/11/2013.
      class WhoisAboveCom < Base

		property_supported :admin_contacts do
          build_contact("Administrative Contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Technical Contact", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact("Billing Contact", Whois::Record::Contact::TYPE_BILLING)
        end
	
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /^\s+#{element}:\n((.+\n)+)\n/
			line_num=1
			$1.split(%r{\n}).each do |line|
			  line=line.strip unless line.nil?
              reg["name"]=line if line_num==1	  
              reg["organization"]=line if line_num==1
              reg["address"]=line if line_num==2
              reg["city"]= line if line_num==3
              reg["state"]=line if line_num==4
              reg["zip"]=line if line_num==5
			  reg["country_code"]=line if line_num==6
			  reg["phone"]=line.split('Tel.')[1] if line=~ /Tel/i
			  reg["fax"]=line.split('Fax.')[1] if line=~ /Fax/i
			  reg["email"]=line if line =~ /\w+\@.+\.\w+/
			  line_num=line_num+1
			end
          end
		  return reg
        end	
		
      end
    end
  end
end
