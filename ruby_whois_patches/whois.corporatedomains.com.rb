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

      # Parser for the whois.corporatedomains.com server, added by Yang Li 02/05/2013.
      class WhoisCorporatedomainsCom < Base
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/Registrar(.+):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] =~ /Name/i
			reg["organization"] = entry[1] if entry[0] =~ /Name/i
			reg["url"] = entry[1] if entry[0] =~ /Homepage/i			
          end
		  return reg
        end
		
		property_supported :admin_contacts do
          build_contact("Administrative contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Technical contact", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 

		# The following methods are implemented by Yang Li on 02/05/2013		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /#{element}:\s*\n((.+\n)+)\n/i
			  line_num=1
			  $1.split(%r{\n}).each do |line|
				reg["organization"]=line.strip if line_num==1
				reg["name"]=line.strip if line_num==2
				reg["address"]=line.strip if line_num==3
				reg["city"]=line.strip if line_num==4
				reg["country_code"]=line.strip if line_num==5
				reg["email"]=line.split(':')[1].strip if line=~ /\w+\@\w+\.\w/
				reg["phone"]=line.split(':')[1].strip if line=~ /Phone/
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
