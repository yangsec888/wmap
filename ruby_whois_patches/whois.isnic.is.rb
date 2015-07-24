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
      # = whois.isnic.is parser
      #
      # Parser for the whois.isnic.is server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisIsnicIs < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /No entries found for query/)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /created:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on

        property_supported :expires_on do
          if content_for_scanner =~ /expires:\s+(.*)\n/
            Time.parse($1)
          end
        end


        property_supported :nameservers do
          content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end
		
		# The following methods are implemented by Yang Li on 02/11/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /^domain:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/((.+\n)+)\n/)[5].flatten.join('').scan(/^(.+):\s+(.+)\n/).map do |entry|
			reg["id"] = entry[1] if entry[0] =~ /nic\-hdl/i
			reg["name"] = entry[1] if entry[0] =~ /role/i
			reg["organization"] = entry[1] if entry[0] =~ /role/i
			reg["email"] = entry[1] if entry[0] =~ /e\-mail/i			
          end
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact(1, Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact(3, Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact(4, Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact(2, Whois::Record::Contact::TYPE_BILLING)
        end
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/((.+\n)+)\n/)[element].flatten.join('').scan(/^(.+):\s+(.+)\n/).map do |entry|
              reg["id"]=entry[1] if entry[0] =~ /nic\-hdl/i
              reg["name"]=entry[1] if entry[0] =~ /(person|role)/i
              reg["organization"]=entry[1] if entry[0]=~ /(person|role)/i
              if entry[0]=~ /(address|descr)/i
				if reg["address"].nil?
					reg["address"]=entry[1]
				else
					reg["address"]=reg["address"]+", "+entry[1]
				end
			  end
			  reg["phone"]=entry[1] if entry[0]=~ /phone/i
			  reg["fax"]=entry[1] if entry[0]=~ /fax/i
			  reg["email"]=entry[1] if entry[0]=~ /e\-mail/i
          end
		  return reg
        end	
		# ----------------------------------------------------------------------------
		
      end

    end
  end
end
