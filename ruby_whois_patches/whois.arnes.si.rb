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
      # = whois.arnes.si parser
      #
      # Parser for the whois.arnes.si server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisArnesSi < Base

        property_supported :status do
          if content_for_scanner =~ /status:\s+(.+)\n/
            case $1.downcase
              when "ok"   then :registered
              else
                Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            :available
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /% No entries found/)
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
          if content_for_scanner =~ /expire:\s+(.*)\n/
            Time.parse($1)
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/nameserver:\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /domain:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/^(registrar.*):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] == "registrar"
			reg["organization"] = entry[1] if entry[0] == "registrar"
			reg["url"] = entry[1] if entry[0] =~ /url/i			
          end
		  return reg
        end
		
		property_not_supported :admin_contacts

        property_supported :registrant_contacts do
          build_contact("Domain holder", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :technical_contacts do
          build_contact("Tech", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /^#{element}:\n((.+\n)+)\n/i
			  line_num=1
			  $1.split(%r{\n}).each do |line|
				line=line.strip unless line.nil?
				reg["name"]=line if line_num==1
				reg["organization"]=line if line_num==1
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
