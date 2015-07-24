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
      # = whois.domreg.lt parser
      #
      # Parser for the whois.domreg.lt server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisDomregLt < Base

        property_supported :status do
          if content_for_scanner =~ /Status:\s+(.*)\n/
            $1.to_sym
          end
        end

        property_supported :available? do
          (status == :available)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Registered:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on

        property_not_supported :expires_on


        property_supported :nameservers do
          content_for_scanner.scan(/Nameserver:\s+(.+)\n/).flatten.map do |line|
            if line =~ /(.+)\t\[(.+)\]/
              Record::Nameserver.new(:name => $1, :ipv4 => $2)
            else
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /^Domain:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/^(Registrar.*):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] == "Registrar"
			reg["organization"] = entry[1] if entry[0] == "registrar"
			reg["url"] = entry[1] if entry[0] =~ /website/i			
          end
		  return reg
        end
		
		property_not_supported :admin_contacts

        property_supported :registrant_contacts do
          build_contact("Contact", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :technical_contacts 

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/^#{element}(.+):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] =~ /organization/i
			reg["organization"] = entry[1] if entry[0] =~ /organization/i
			reg["email"] = entry[1] if entry[0] =~ /email/i			
          end
		  return reg
        end	
		# ---------------------------------------------------------------------------
		
      end
    end
  end
end
