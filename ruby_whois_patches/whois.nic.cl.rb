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
      # = whois.nic.cl parser
      #
      # Parser for the whois.nic.cl server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicCl < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
           !!(content_for_scanner =~ /^(.+?): no existe$/)
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        # TODO: custom date format with foreign month names
        # property_supported :updated_on do
        #   if content_for_scanner =~ /changed:\s+(.*)\n/
        #     Time.parse($1.split(" ", 2).last)
        #   end
        # end

        property_not_supported :expires_on
		
        property_supported :updated_on do
		if content_for_scanner =~ /\(data repository last updated on\):\s*(.+)\n/
            Time.utc(*$1.split("/").reverse)
          end
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Servidores de nombre \(Domain servers\):\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              line.strip!
              line =~ /(.+) \((.+)\)/
              Record::Nameserver.new(:name => $1, :ipv4 => $2)
            end
          end
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /ACE:\s+(.+)\s*.+\n/i
        end

        property_supported :registrant_contacts do
          build_contact_rc(Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Administrative Contact", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Technical Contact", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner.scan =~ /#{element}\):\n((.+\n)+)\n/
              $1.scan(/^(.+):(.+)\n/).map do |entry|
				  reg["name"]=entry[1] if entry[0] =~ /Nombre/i
				  reg["organization"]=entry[1] if entry[0]=~ /Organiz/i
			  end
          end
		  return reg
        end	
		
        def build_contact_rc(type)
          reg=Record::Contact.new(:type => type)
		  reg["name"]=content_for_scanner.split(%r{\n})[4].strip
		  reg["organization"]=content_for_scanner.split(%r{\n})[4].strip
		  return reg
        end	
		# ----------------------------------------------------------------------------

      end
    end
  end
end
