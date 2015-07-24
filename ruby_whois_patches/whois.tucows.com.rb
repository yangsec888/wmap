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

      # Parser for the whois.tucows.com server, added by Yang Li 02/10/2013.
      class WhoisTucowsCom < Base

        property_supported :registrar do
          reg=Record::Registrar.new
		  if content_for_scanner =~ /Registration Service Provider:\n((.+\n)+)\n/
			line_num=1
			$1.split(%r{\n}).each do |entry|
				reg["name"] = entry.strip.split(',')[0] if line_num==1
				reg["organization"] = entry.strip.split(',')[0] if line_num==1
				reg["url"] = entry.strip.split(',')[1] if line_num==1		
				line_num=line_num+1
			end
          end
		  return reg
        end
		
		property_supported :admin_contacts do
          build_contact("Administrative Contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Technical Contact", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
	
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /#{element}:\n((.+\n)+)\n/i
			  line_num=1
			  addrs=''
			  $1.split(%r{\n}).each do |entry|
				  reg["name"]=entry.strip if line_num==1
				  reg["organization"]=entry.strip if line_num==1
				  reg["address"]=entry.strip if line_num==2
				  reg["phone"]=$1 if entry =~ /(\d{7,})/i
				  reg["fax"]=entry.strip.split('Fax:').last.strip if entry =~ /Fax/i
				  reg["email"]=$1 if entry =~ /(\w+\@.+\.\w+)/i
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
