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

      # Parser for the whois.srs.net.nz server.
      #
      # @note This parser is just a stub and provides only a few basic methods
      #   to check for domain availability and get domain status.
      #   Please consider to contribute implementing missing methods.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class WhoisSrsNetNz < Base

        # @see http://dnc.org.nz/content/srs-whois-spec-1.0.html
        property_supported :status do
          if content_for_scanner =~ /query_status:\s(.+)\n/
            case (s = $1.downcase)
            when "200 active"
              :registered
            # The domain is no longer active but is in the period prior
            # to being released for general registrations
            when "210 pendingrelease"
              :redemption
            when "220 available"
              :available
            when "404 request denied"
              :error
            when /invalid characters/
              :invalid
            else
              Whois.bug!(ParserError, "Unknown status `#{s}'.")
            end
          else
            Whois.bug!(ParserError, "Unable to parse status.")
          end
        end

        property_supported :available? do
          status == :available
        end

        property_supported :registered? do
          status == :registered || status == :redemption
        end


        property_supported :created_on do
          if content_for_scanner =~ /domain_dateregistered:\s(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :updated_on do
          if content_for_scanner =~ /domain_datelastmodified:\s(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /domain_datebilleduntil:\s(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :nameservers do
          content_for_scanner.scan(/ns_name_[\d]+:\s(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(:name => name)
          end
        end

        # Checks whether the response has been throttled.
        #
        # @return [Boolean]
        #
        # @example
        #   query_status: 440 Request Denied
        #
        def response_throttled?
          cached_properties_fetch(:response_throttled?) do
            !!(content_for_scanner =~ /^query_status: 440 Request Denied/)
          end
        end

        # NEWPROPERTY
        def valid?
          cached_properties_fetch(:valid?) do
            !invalid?
          end
        end

        # NEWPROPERTY
        def invalid?
          cached_properties_fetch(:invalid?) do
            status == :invalid
          end
        end

		# The following methods are implemented by Yang Li on 01/24/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return $1 if content_for_scanner =~ /domain_name:\s+(.*)\n/i
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  content_for_scanner.scan(/^registrar_(.+):\s+(.+)\n/).map do |entry|
			reg["name"] = entry[1] if entry[0] =~ /name/i
			reg["organization"] = entry[1] if entry[0] =~ /name/i
			reg["id"] = entry[1] if entry[0] =~ /phone/i
			reg["url"] = entry[1] if entry[0] =~ /email/i			
          end
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("registrant_", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("admin_", Whois::Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("technical_", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  content_for_scanner.scan(/^#{element}(.+):\s+(.+)\n/).map do |entry|
              reg["name"]=entry[1] if entry[0] =~ /name/i
              reg["organization"]=entry[1] if entry[0]=~ /name/i
              reg["address"]=entry[1] if entry[0]=~ /address1/i
              reg["city"]= entry[1] if entry[0]=~ /city/i
			  reg["country"]=entry[1] if entry[0]=~ /country/i
			  reg["phone"]=entry[1] if entry[0]=~ /phone/i
			  reg["fax"]=entry[1] if entry[0]=~ /fax/i
			  reg["email"]=entry[1] if entry[0]=~ /email/i
          end
		  return reg
        end	
		# ----------------------------------------------------------------------------
		
      end
    end
  end
end
