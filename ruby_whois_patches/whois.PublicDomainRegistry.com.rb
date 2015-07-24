#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++

# The parser was implemented by Yang Li on 02/27/2013

require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      #
      # = whois.PublicDomainRegistry.com parser
      #
      # Parser for the whois.PublicDomainRegistry.com server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisPublicdomainregistryCom < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !(content_for_scanner =~ /Status:LOCKED/)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Registration Date:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on 

        property_supported :expires_on do
          if content_for_scanner =~ /Expiration Date:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain Name:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  reg["name"] = node("Registrar")	
		  reg["url"] = node("Referral URL")	
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Registrant Contact Details", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Administrative Contact Details", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Technical Contact Details", Whois::Record::Contact::TYPE_TECHNICAL)
        end
	
        property_supported :billing_contacts do
          build_contact("Billing Contact Details", Whois::Record::Contact::TYPE_BILLING)
        end
		
      private

        def build_contact(element, type)
            reg=Record::Contact.new(:type => type)
		    if content_for_scanner =~ /^\s*#{element}:\s*\n((.+\n)+)\n/
				line_num=1
				$1.split(%r{\n}).each do |line|   
					  line=line.strip
					  reg["id"]=$1 if line =~ /(ID#\d+)/
					  reg["name"]=line if line_num==1
					  reg["organization"]=line if line_num==4
					  reg["address"]=line if line_num==5
					  reg["city"]= line.split(',')[0] if line_num==6
					  reg["zip"]= line.split(',')[1].split(%r{\s+})[1] if line_num==6
					  reg["state"]=line.split(',')[1].split(%r{\s+})[0] if line_num==6
					  reg["country_code"]=line if line_num==7
					  reg["phone"]=line.split('Tel.')[1] if line =~ /Tel\./i
					  reg["fax"]=line.split('Fax.')[1] if line =~ /Fax\./i
					  reg["email"]=$1 if line =~ /(\(.+\@\.+\.\w+\))/
					  line_num=line_num+1					
				end
			end
		    return reg
        end	
		
		def node(element)
			return $1 if content_for_scanner =~ /^\s*#{element}\.+:\s*(.+)\n/
		end
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
