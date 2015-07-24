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
      # = whois.dot.tk parser
      #
      # Parser for the whois.dot.tk server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisDotTk < Base

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /domain name not known/)
        end

        property_supported :registered? do
          !available?
        end


        property_supported :created_on do
          if content_for_scanner =~ /Domain registered:\s+(.*)\n/
            DateTime.strptime($1, "%m/%d/%Y").to_time
          end
        end

        property_not_supported :updated_on

        property_supported :expires_on do
          if content_for_scanner =~ /Record will expire on:\s+(.*)\n/
            DateTime.strptime($1, "%m/%d/%Y").to_time
          end
        end


        property_supported :nameservers do
          if content_for_scanner =~ /Domain Nameservers:\n((.+\n)+)\s+\n/
            $1.split("\n").map do |name|
              Record::Nameserver.new(:name => name.strip.downcase)
            end
          end
        end

		# The following methods are implemented by Yang Li on 03/05/2013
		# ----------------------------------------------------------------------------
        property_supported :domain do
          if content_for_scanner =~ /Domain name:\n(.+)\n\n/
			return $1.strip
		  end
        end
		
		property_not_supported :domain_id 
		
        property_not_supported :registrar 

        property_supported :registrant_contacts do
          build_contact("Organisation", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :admin_contacts 
		
        property_not_supported :technical_contacts

        property_not_supported :billing_contacts 
		
      private

        def build_contact(element, type)
          reg=Record::Contact.new(:type => type)
		  if content_for_scanner =~ /#{element}:\n((.+\n)+)\n/
			  con=$1
			  contact=con.split(%r{\n})
              reg["organization"]=contact.shift.strip
              reg["name"]=contact.shift.strip
			  reg["phone"]=build_node("Phone",con)
			  reg["fax"]=build_node("Fax",con)
			  reg["email"]=build_node("E-mail",con)		  
			  myaddr=build_address(contact)
			  reg["address"]=myaddr["address"]
			  reg["city"]=myaddr["city"]
			  reg["zip"]=myaddr["zip"]
			  reg["state"]=myaddr["state"]
			  reg["country"]=myaddr["country"]			  
          end
		  return reg
        end	
		
		def build_node(element,context)
			return $1.strip if context =~ /#{element}:(.+)\n/i
		end
		
		def build_address(context)
			addr=Hash.new
			line_num=2
			context.each do |line|
				line=line.chomp.strip
				addr["address"]=line if line_num==2
				addr["state"]=line if line_num==4
				addr["country"]=line if line_num==5
				if line_num==3 && !line.nil?
					zips=line.split(' ')
					addr["city"]=zips.pop
					addr["zip"]=zips.join(' ')
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
