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

      # Parser for the whois.ascio.com server, added by Yang Li 02/05/2013.
      class WhoisAscioCom < Base
	  
        property_supported :created_on do
          if content_for_scanner =~ /^Record created:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /^Record last updated:\s+(.+)\n/
            Time.parse($1)
          end
        end		

        property_supported :expires_on do
          if content_for_scanner =~ /Record expires:\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :nameservers do
          if content_for_scanner =~ /^Domain servers in listed order:\n((.+\n)+)/
			$1.split(%r{\n}).map do |line|
				Record::Nameserver.new(:name => line.strip.split(%r{\s+})[0])
			end
          end
        end
		
        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain name:\s+(.+)\n/i
        end
		
        property_not_supported :domain_id
		 
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
	
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /^#{element}:\n((.+\n)+)\n/i
			  line_num=1
			  $1.split(%r{\n}).each do |line|
				line=line.strip unless line.nil?
				reg["id"]=line.split('(')[1].split(')')[0] if line_num==1
				reg["name"]=line.split('(')[0] if line_num==1
				reg["organization"]=line.strip if line_num==2
				reg["address"]=line if line_num==3
				reg["city"]=line if line_num==5
				reg["country_code"]=line if line_num==6
				reg["email"]=line if line=~ /.+\@.+\.\w/
				reg["phone"]=line.split('Fax:')[0] if line=~ /Fax/
				reg["fax"]=line.split('Fax:')[1] if line=~ /Fax/
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
