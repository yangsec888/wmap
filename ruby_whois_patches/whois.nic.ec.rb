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
      # = whois.nic.ec parser
      #
      # Parser for the whois.nic.ec server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisNicEc < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /Domain not registered/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          t=build_node("Created",content_for_scanner)
          Time.parse(t)
        end

        property_supported :updated_on do
          t=build_node("Modified",content_for_scanner)
          Time.parse(t)
        end

        property_supported :expires_on do
          t=build_node("Expires",content_for_scanner)
          Time.parse(t)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Servidores de dominio \(Name Servers\)\n((.+\n)+)\n/
            $1.split("\n").map do |name|
              Record::Nameserver.new(:name => name)
            end
          end
        end

		# The following methods are implemented by Yang Li on 03/04/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          return build_node("Query",content_for_scanner)
        end
		
		property_not_supported :domain_id 
		
        property_supported :registrar do
          reg=Record::Registrar.new
		  if content_for_scanner =~ /^Registrar Information\n((.+\n)+)\n/
			registrar=$1
			reg["name"] = build_node("Registrar Name", registrar)
			reg["organization"] = build_node("Registrar Name", registrar)
			reg["url"] = build_node("Registration URL", registrar)
			reg["country"] = build_node("Country", registrar)
          end
		  return reg
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Admin Contact", Whois::Record::Contact::TYPE_ADMIN)
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
		  if content_for_scanner =~ /^#{element}:\n((.+\n)+)\n\n/
			  contact=$1
              reg["name"]=build_node("Name", contact)
              reg["organization"]=build_node("Organisation", contact)
              if contact =~ /^(Address:\n(.+\n)+)/
				  addrs=$1
				  myaddr=build_address(addrs)
				  reg["address"]=myaddr["address"]
				  reg["city"]=myaddr["city"]
				  reg["zip"]=myaddr["zip"]
				  reg["state"]=myaddr["state"]
				  reg["country_code"]=myaddr["country_code"]			
			  end			  
			  reg["phone"]=build_node("Phone Number",contact)
			  reg["fax"]=build_node("Fax Number",contact)
			  reg["email"]=build_node("Email Address",contact)
          end
		  return reg
        end	
		
		def build_node(element,context)
			return $1.strip if context =~ /^#{element}:(.+)\n/i
		end
		
		def build_address(context)
			addr=Hash.new
			line_num=1
			context.split(%r{\n}).each do |line|
				line=line.chomp.strip
				addr["address"]=line if line_num==2
				addr["country_code"]=line if line_num==4
				if line_num==3
					addr["city"]=line.split(',')[0]
					zips=line.split(',')[1].split(' ')
					unless zips.nil?
						addr["state"]=zips.shift
						addr["zip"]=zips.join(' ')
					end
				end
				line_num=line_num+1
			end
			return addr
		end
		# ----------------------------------------------------------------------------
      end

    end
  end
end
