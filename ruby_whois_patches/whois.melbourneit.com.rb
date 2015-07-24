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
      class WhoisMelbourneitCom < Base
		
	property_supported :admin_contacts do
          build_contact("Admin Name", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :registrant_contacts do
          build_contact("Domain Name", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Tech Name", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 

      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /^#{element}\.+((.+\n)+)\n/i
			  line_num=1
			  addrs=''
			  $1.split(%r{\n}).each do |entry|
				  reg["name"]=entry if line_num==1
				  reg["organization"]=entry.strip.split(%r{\.\s}).last if entry =~ /Organisation Name/i
				  reg["phone"]=entry.strip.split(%r{\.\s}).last.strip if entry =~ /Phone/i
				  reg["fax"]=entry.strip.split(%r{\.\s}).last.strip if entry =~ /Fax/i
				  reg["email"]=entry.strip.split(%r{\.\s}).last.strip if entry =~ /Email/i
				  if entry =~ /Address\./i && !entry.strip.split(%r{\.\s})[1].nil?
					addrs = addrs + entry.strip.split(%r{\.\s})[1] + ", " 
				  end
				  reg["address"]=addrs
				  line_num=line_num+1
			  end
		end
	  return reg
        end	
		
      end
    end
  end
end
