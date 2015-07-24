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

      # Base parser for CoCCA servers.
      #
      # @abstract
      class BaseCocca2 < Base

        property_supported :domain do
          content_for_scanner =~ /Domain Name: (.+)\n/
          $1 || Whois.bug!(ParserError, "Unable to parse domain.")
        end

        property_not_supported :domain_id

        # TODO: /pending delete/ => :redemption
        # TODO: /pending purge/  => :redemption
        property_supported :status do
          list = statuses
          case
            when list.empty?
              Whois.bug!(ParserError, "Unable to parse status.")
            when list.include?("available")
              :available
            when list.include?("ok")
              :registered
            else
              Whois.bug!(ParserError, "Unknown status `#{list.join(", ")}'.")
          end
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Creation Date: (.+?)\n/
            parse_time($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /Updated Date: (.+?)\n/
            parse_time($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /Registry Expiry Date: (.+?)\n/
            parse_time($1)
          end
        end

        property_supported :registrar do
          if content_for_scanner =~ /Sponsoring Registrar: (.+?)\n/
            Record::Registrar.new(
                :name         => $1,
                :organization => nil,
                :url          => content_for_scanner.slice(/Sponsoring Registrar URL: (.+)\n/, 1)
            )
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/Name Server: (.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

        def statuses
          content_for_scanner.scan(/Domain Status: (.+)\n/).flatten.map(&:downcase)
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------

		property_supported :domain_id do
          return $1 if content_for_scanner =~ /Domain ID:\s+(.*)\n/i
        end
		
        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Admin", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Tech", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact("Billing", Whois::Record::Contact::TYPE_BILLING)
        end
		
      private

        def parse_time(value)
          # Hack to remove usec. Do you know a better way?
          Time.utc(*Time.parse(value).to_a)
        end

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  strs=''
		  content_cleanup=content_for_scanner.split(%r{/n}).delete_if { |x| x !~ /(.+):(.+)/ }
		  content_cleanup.join('\n').scan(/^#{element}(.+):(.+)\n/).map do |entry|
              reg["id"]=entry[1].strip if entry[0] =~ /ID/i
              reg["name"]=entry[1].strip if entry[0] =~ /Name/i
              reg["organization"]=entry[1].strip if entry[0]=~ /Organization/i
              if (entry[0]=~ /Street/i) 
				strs=strs+entry[1].strip+", "
			  end
			  reg["address"]=strs
              reg["city"]= entry[1].strip if entry[0]=~ /City/i
              reg["zip"]=entry[1].strip if entry[0]=~ /Postal\sCode/i
              reg["state"]=entry[1].strip if entry[0]=~ /State\/Province/i
              reg["country_code"]=entry[1].strip if entry[0]=~ /Country/i
			  reg["email"]=entry[1].strip if entry[0]=~ /Email/i
			  reg["phone"]=entry[1].strip if entry[0] =~ /Phone$/i 
			  reg["fax"]=entry[1].strip if (entry[0] =~ /Fax$/i) 
          end
		  return reg
        end	
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
