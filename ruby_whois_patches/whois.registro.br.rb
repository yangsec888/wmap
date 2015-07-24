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
      # = whois.registro.br parser
      #
      # Parser for the whois.registro.br server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisRegistroBr < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /No match for domain/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /created:\s+(.+?)(\s+#.+)?\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /changed:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /expires:\s+(.+?)\n/
            Time.parse($1)
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
            name, ipv4 = line.strip.split(" ")
            Record::Nameserver.new(:name => name, :ipv4 => ipv4)
          end
        end
		
		# The following methods are implemented by Yang Li on 03/04/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return build_node("domain",content_for_scanner)
        end
		
		property_not_supported :domain_id 
		
        property_not_supported :registrar 
		
        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :admin_contacts 
		
        property_not_supported :technical_contacts 

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
          reg["name"]=build_node("owner", content_for_scanner)
          reg["organization"]=build_node("owner", content_for_scanner)
		  return reg
        end	
		
		def build_node(element,context)
			return $1.strip if context =~ /^#{element}:(.+)\n/i
		end
		# ----------------------------------------------------------------------------
		
      end

    end
  end
end
