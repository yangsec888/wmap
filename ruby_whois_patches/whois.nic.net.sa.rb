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
      # = whois.nic.net.sa parser
      #
      # Parser for the whois.nic.net.sa server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicNetSa < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /^No match\.$/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /reg-date:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on

        property_not_supported :expires_on
		
		# The following methods are implemented by Yang Li on 2/7/2013
		# ----------------------------------------------------------------------------
        property_supported :nameservers do
          if content_for_scanner =~ /Name\sServers:\n((.+\n)+)\n/
            $1.split("\n").map do |name|
              Record::Nameserver.new(:name => name.strip.downcase)
            end
          end
        end

        property_supported :domain do
          #return $1.strip if content_for_scanner =~ /^Domain\sName:(.*)\n/i
		  return $1.strip if content_for_scanner =~ /Registrant:\n((.+\n)+)\n/i
        end
		
		property_not_supported :domain_id
		
        property_not_supported :registrar 
		
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
				$1.split(%r{\n}).each do |line|
					reg["name"]=line.strip if line_num==1
					reg["organization"]=line.strip if line_num==1
					reg["address"]=line.split(':')[1].strip if line_num==2
					reg["city"]=line.strip if line_num==3
					reg["country"]=line.strip if line_num==4
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
