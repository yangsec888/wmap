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
      # = whois.nic.im parser
      #
      # Parser for the whois.nic.im server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicIm < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /was not found/)
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        property_not_supported :updated_on

        property_supported :expires_on do
          if content_for_scanner =~ /Expiry Date:\s+(.*?)\n/
            Time.parse($1.gsub("/", "-"))
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name.chomp("."))
          end
        end

		# The following methods are implemented by Yang Li on 02/04/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /Domain Name:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  if content_for_scanner =~ /^Domain Managers\n((.+\n)+)^Administrative\sContact\n/
			$1.scan(/(.+):(.+)\n/).map do |entry|
				reg["name"] = entry[1] if entry[0] =~ /Name/i
				reg["organization"] = entry[1] if entry[0] =~ /Name/i
			end	
          end
		  return reg
        end
		
		property_not_supported :admin_contacts do
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
		  if content_for_scanner =~ /#{element}\n((.+\n)+)/i
			  line_num=1
			  $1.split(%r{\n}).each do |line|
				reg["name"]=line.split(':')[1].strip if line_num==1
				reg["organization"]=line.split(':')[1].strip if line_num==1
				reg["address"]=line.strip if line_num==3
				reg["city"]=line.strip if line_num==4
				reg["zip"]=line.strip if line_num==5
				reg["country"]=line.strip if line_num==6
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
