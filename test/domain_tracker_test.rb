#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
# Unit Test File for Wmap::DomainTracker class

require "minitest/autorun"
require "Wmap"

class DomainTrackerTest < MiniTest::Unit::TestCase
	include Wmap::Utils
	
	def test_domain_known_case_1?
		assert_equal false, Wmap::DomainTracker.instance.domain_known?("yahoo.com")
	end

	def test_domain_known_case_2?
		assert_equal true, Wmap::DomainTracker.instance.domain_known?("YourDomain.co.uk")
	end

	def test_domain_known_case_3?
		assert_equal false, Wmap::DomainTracker::SubDomain.instance.domain_known?("mail.yahoo.com")
	end
	
	def test_domain_known_case_4?
		assert_equal true, Wmap::DomainTracker::SubDomain.instance.domain_known?("YourHost.YourDomain.co.uk")
	end
end
