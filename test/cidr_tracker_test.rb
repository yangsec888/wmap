#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
# Unit Test File for Wmap::DomainTracker.instance class

require "minitest/autorun"
require "Wmap"

class CidrTrackerTest < MiniTest::Unit::TestCase
	include Wmap::Utils

	def test_cidr_add
		w = Wmap::CidrTracker.new
		w.add("192.168.1.0/24")
		assert_equal true, w.known_cidr_blks.key?("192.168.1.0/24")
	end

	def test_cidr_delete
		w = Wmap::CidrTracker.new
		w.add("10.0.0.0/8")
		w.delete("10.0.0.0/8")
		assert_equal false, w.known_cidr_blks.key?("10.0.0.0/8")
	end

	def test_ip_trusted?
		w = Wmap::CidrTracker.new
		w.add("192.168.1.0/24")
		assert_equal true, w.ip_trusted?("192.168.1.1")
		assert_equal true, w.ip_trusted?("192.168.1.255")
	end

end
