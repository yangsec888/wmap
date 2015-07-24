#--
# Wmap
#
# A pure Ruby library for the Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++
# Unit Test File for Wmap::Utils module

require "minitest/autorun"
require "Wmap"

class UtilsTest < MiniTest::Unit::TestCase
	include Wmap::Utils
	
	def test_sld_domain_conversion
		assert_equal "yahoo.com", get_domain_root("yahoo.com")
	end

	def test_host_2_sld_domain_coversion
		assert_equal "yahoo.com", get_domain_root("www.yahoo.com")
	end

	def test_host_2_cclld_domain_coversion
		assert_equal "yahoo.co.uk", get_domain_root("www.yahoo.co.uk")
	end

	def test_is_domain_root_case_1?
		assert_equal false, is_domain_root?("www.yahoo.co.uk")
	end
	
	def test_is_domain_root_case_2?
		assert_equal true, is_domain_root?("yahoo.co.uk")
	end
	
	def test_get_sub_domain
		assert_equal "mail.yahoo.co.uk", get_sub_domain("www.mail.yahoo.co.uk")
	end

	def test_is_url_case_1?
		assert_equal true, is_url?("http://www.mail.yahoo.co.uk/")
	end	

	def test_is_url_case_2?
		assert_equal true, is_url?("https://www.mail.yahoo.co.uk/")
	end		

	def test_is_url_case_3?
		assert_equal false, is_url?("http://www.mail.yahoo.uii/")
	end	

	def test_is_url_case_4?
		assert_equal false, is_url?("http:\\www.mail.yahoo.co.uk")
	end	
	
	def test_is_ssl?
		assert_equal false, is_ssl?("http://www.mail.yahoo.co.uk/")
	end	
	
	def test_is_site?
		assert_equal false, is_site?("https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	
	
	def test_url_2_host
		assert_equal "login.yahoo.com", url_2_host("https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	
	
	def test_url_2_site_case_1
		assert_equal "https://login.yahoo.com/", url_2_site("https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	

	def test_url_2_site_case_2
		assert_equal "https://login.yahoo.com/", url_2_site("https://login.yahoo.com?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	

	def test_url_2_site_case_3
		assert_equal "https://login.yahoo.com/", url_2_site("https://login.yahoo.com#.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	
	
	def test_url_2_path
		assert_equal "/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com", url_2_path("https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com")
	end	

	def test_urls_on_same_domain?
		assert_equal true, urls_on_same_domain?("https://login.yahoo.com/?.src=ym&.intl=us&.lang=en-US&.done=https%3a//mail.yahoo.com", "https://us-mg4.mail.yahoo.com/neo/launch?.rand=8hjd08hc6t1lq")
	end	

	def test_host_2_url_case_1
		assert_equal "https://mail.yahoo.com/", host_2_url("mail.yahoo.com",443)
	end	

	def test_host_2_url_case_2
		assert_equal "http://mail.yahoo.com/", host_2_url("mail.yahoo.com")
	end	
	
	def test_make_absolute
		assert_equal "http://games.yahoo.com/game/the-magic-snowman-flash.html", make_absolute("http://games.yahoo.com/","game/the-magic-snowman-flash.html")
	end
	
	def test_create_absolute_url_from_base
		assert_equal "http://images.search.yahoo.com/search/images?p=raiders", create_absolute_url_from_base("http://images.search.yahoo.com/images","/search/images?p=raiders")
	end

	def test_create_absolute_url_from_context
		assert_equal "http://images.search.yahoo.com/images/search/images?p=raiders", create_absolute_url_from_context("http://images.search.yahoo.com/images/logo.png","/search/images?p=raiders")
	end

	def test_normalize_url_case_1
		assert_equal "http://images.search.yahoo.com/images/search/images?p=raiders", normalize_url("http://images.search.yahoo.com/./images/search/images?p=raiders")
	end
	
	def test_normalize_url_case_2
		assert_equal "http://images.search.yahoo.com/images/search/images?p=raiders", normalize_url("http://images.search.yahoo.com/../images/../search/images?p=raiders")
	end

	def test_normalize_url_case_3
		assert_equal "http://images.search.yahoo.com/images/search/images?p=raiders", normalize_url("http://images.search.yahoo.com./../images/../search/images?p=raiders")
	end
	
	def test_is_ip_case_1?
		assert_equal false, is_ip?("256.2.3.1")
	end	

	def test_is_ip_case_2?
		assert_equal false, is_ip?("25.2.3.1.22")
	end	

	def test_is_ip_case_3?
		assert_equal true, is_ip?("196.168.230.1")
	end	

	def test_is_fqdn_case_1?
		assert_equal true, is_fqdn?("images.search.yahoo.com")
	end	

	def test_is_fqdn_case_2?
		assert_equal true, is_fqdn?("yahoo.com")
	end		
	
	def test_is_fqdn_case_3?
		assert_equal false, is_fqdn?("images.search.yahoo")
	end	
	
	def test_is_fqdn_case_4?
		assert_equal false, is_fqdn?("images")
	end	
	
	def test_is_cidr_case_1?
		assert_equal false, is_cidr?("196.168.230.1")
	end	

	def test_is_cidr_case_2?
		assert_equal false, is_cidr?("196.168.2.257/12")
	end	
	
	def test_is_cidr_case_3?
		assert_equal true, is_cidr?("196.168.2.25/12")
	end	
	
	def test_cidr_2_ips
		assert_equal ["192.168.1.1"], cidr_2_ips("192.168.1.1/32")
	end	
	
	def test_sort_ips
		assert_equal ["192.168.1.1", "192.168.1.2", "192.168.2.1"], sort_ips(["192.168.1.2", "192.168.2.1","192.168.1.1"])
	end		
	
end
