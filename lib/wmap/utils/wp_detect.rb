#--
# Wmap
#
# A pure Ruby library for Internet web application discovery and tracking.
#
# Copyright (c) 2012-2015 Yang Li <yang.li@owasp.org>
#++

# Utilities for wp_tracker class only; must use with other Utils modules.
module Wmap
 module Utils
    module WpDetect
	  extend self

    # Main method to detect if it's a wordpress site
    def is_wp?(url)
  		site=url_2_site(url)
  		if wp_readme?(site)
  			return true
  		elsif wp_css?(site)
  			return true
  		elsif wp_meta?(site)
  			return true
  		elsif wp_login?(site)
  			return true
  		elsif wp_rpc?(site)
  			return true
  		elsif wp_gen?(site)
  			return true
      elsif wp_load_styles?(site)
  			return true
  		else
  			return false
  		end
  	rescue => ee
  		puts "Exception on method #{__method__}: #{ee}: #{url}" if @verbose
  	end

    # Main method to extract the WordPress version
  	def wp_ver(url)
  		if !wp_ver_readme(url).nil?
  			puts "WordPress version found by wp_ver_readme method. " if @verbose
  			return wp_ver_readme(url)
  		elsif !wp_ver_login(url,"login.min.css").nil?
  			puts "WordPress version found by login.min.css file. " if @verbose
  			return wp_ver_login(url,"login.min.css")
  		elsif !wp_ver_login(url,"buttons.min.css").nil?
  			puts "WordPress version found by buttons.min.css file. " if @verbose
  			return wp_ver_login(url,"buttons.min.css")
  		elsif !wp_ver_login(url,"wp-admin.min.css").nil?
  			puts "WordPress version found by wp-admin.min.css file. " if @verbose
  			return wp_ver_login(url,"wp-admin.min.css")
  		elsif !wp_ver_meta(url).nil?
  			puts "WordPress version found by wp_ver_meta method. " if @verbose
  			return wp_ver_meta(url)
  		elsif !wp_ver_generator(url).nil?
  			puts "WordPress version found by wp_ver_generator method. " if @verbose
  			return wp_ver_generator(url)
      elsif !wp_ver_load_styles(url).nil?
  			puts "WordPress version found by wp_ver_load_styles method. " if @verbose
  			return wp_ver_load_styles(url)
      else
  			return nil
  		end
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
  	end

    # Wordpress detection checkpoint - readme.html
    def wp_readme?(url)
  		site = url_2_site(url)
      readme_url=site + "readme.html"
      k=Wmap::UrlChecker.new
      if k.response_code(readme_url) == 200
        k=nil
        doc=open_page(readme_url)
        title=doc.css('title')
        if title.to_s =~ /wordpress/i
          return true
        else
          return false
        end
      else
        k=nil
        return false
      end
  	rescue => ee
  		puts "Exception on method #{__method__} for site #{url}: #{ee}" if @verbose
  		return false
    end

    # Wordpress detection checkpoint - install.css
    def wp_css?(url)
  		site = url_2_site(url)
      css_url = site + "wp-admin/css/install.css"
      k=Wmap::UrlChecker.new
      if k.response_code(css_url) == 200
        k=nil
        parser = CssParser::Parser.new
        parser.load_uri!(css_url)
        rule = parser.find_by_selector('#logo a')
        if rule.length >0
          if rule[0] =~ /wordpress/i
            return true
          end
        end
      else
        k=nil
        return false
      end
      return false
  	rescue => ee
  		puts "Exception on method #{__method__} for site #{url}: #{ee}" if @verbose
  		return false
    end

    # Wordpress detection checkpoint - WP meta tag
    def wp_meta?(url)
  		site=url_2_site(url)
      k=Wmap::UrlChecker.new
      if k.response_code(site) == 200
        k=nil
        doc=open_page(site)
        meta=doc.css('meta')
        if meta.to_s =~ /wordpress/i
          return true
        else
          return false
        end
      end
  		return false
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return false
    end

  	# Wordpress detection checkpoint - WP generator tag
    def wp_gen?(url)
  		puts "#{__method__} check for #{url}" if @verbose
  		site = url_2_site(url)
  		gen_url_1 = site + "feed/"
  		gen_url_2 = site + "comments/feed"
      k=Wmap::UrlChecker.new
      if k.response_code(gen_url_1) == 200
        doc=open_page(gen_url_1)
  		elsif k.response_code(gen_url_2) == 200
  			doc=open_page(gen_url_2)
  		else
  			k=nil
  			return false
  		end
  		#puts doc.inspect
      gens=doc.css('generator')
  		if gens.nil?
  			k=nil
  			return false
  		end
  		gens.each do |gen|
  			if gen.text.to_s =~ /wordpress/i
  				k=doc=nil
          return true
        end
  		end
  		k=doc=nil
  		return false
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return false
    end

  	# Wordpress detection checkpoint - wp-login
    def wp_login?(url)
  		site=url_2_site(url)
  		login_url=site + "wp-login.php"
      k=Wmap::UrlChecker.new
      if k.response_code(login_url) == 200
        k=nil
        doc=open_page(login_url)
        links=doc.css('link')
        if links.to_s =~ /login.min.css/i
          return true
        else
          return false
        end
      end
  		return false
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return false
    end

  	# Wordpress detection checkpoint - xml-rpc
    def wp_rpc?(url)
  		site=url_2_site(url)
  		rpc_url=site + "xmlrpc.php"
      k=Wmap::UrlChecker.new
  		#puts "res code", k.response_code(rpc_url)
      if k.response_code(rpc_url) == 405 # method not allowed
        k=nil
        return true
      end
  		return false
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return false
    end

    # Wordpress detection checkpoint - /wp-admin/load-styles.php
    def wp_load_styles?(url)
  		site = url_2_site(url)
      load_styles_url=site + "wp-admin/load-styles.php"
      k=Wmap::UrlChecker.new
      if k.response_code(load_styles_url) == 200 && k.response_headers(load_styles_url).keys.include?("etag")
        k=nil
        return true
      else
        k=nil
        return false
      end
  	rescue => ee
  		puts "Exception on method #{__method__} for site #{url}: #{ee}" if @verbose
  		return false
    end

  	# Identify wordpress version through the login page
    def wp_ver_login(url,pattern)
  		puts "Check for #{pattern}" if @verbose
  		site=url_2_site(url)
  		login_url=site + "wp-login.php"
      k=Wmap::UrlChecker.new
  		#puts "Res code: #{k.response_code(login_url)}" if @verbose
      if k.response_code(login_url) == 200
        doc=open_page(login_url)
  			#puts doc.inspect
        links=doc.css('link')
  			#puts links.inspect if @verbose
  			links.each do |tag|
  	      if tag.to_s.include?(pattern)
  					puts tag.to_s if @verbose
  					k=nil
  	        return tag.to_s.scan(/[\d+\.]+\d+/).first
  	      end
  			end
      end
      k=nil
      return nil
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
    end

  	# Identify wordpress version through the meta link
    def wp_ver_meta(url)
  		site=url_2_site(url)
      k=Wmap::UrlChecker.new
      if k.response_code(site) == 200
        doc=open_page(site)
  			#puts doc.inspect
        meta=doc.css('meta')
  			#puts meta.inspect
  			meta.each do |tag|
  	      if tag['content'].to_s =~ /wordpress/i
  					#puts tag.to_s
  					k=nil
  	        return tag['content'].to_s.scan(/[\d+\.]+\d+/).first
  	      end
  			end
      end
      k=nil
      return nil
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
    end

  	# Identify wordpress version through the generator tag: <generator>https://wordpress.org/?v=4.9.8</generator>
    def wp_ver_generator(url)
  		puts "#{__method__} check for #{url}" if @verbose
  		site = url_2_site(url)
  		gen_url_1 = site + "feed/"
  		gen_url_2 = site + "comments/feed"
      k=Wmap::UrlChecker.new
      if k.response_code(gen_url_1) == 200
        doc=open_page(gen_url_1)
  		elsif k.response_code(gen_url_2) == 200
  			doc=open_page(gen_url_2)
  		else
  			k=nil
  			return nil
  		end
  		#puts doc.inspect
      gens=doc.css('generator')
  		if gens.nil?
  			k=nil
  			return nil
  		end
  		gens.each do |gen|
  			if gen.text.to_s =~ /wordpress/i
  				k=nil
          return gen.text.to_s.scan(/[\d+\.]+\d+/).first
        end
  		end
      k=doc=nil
      return nil
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
  	end

  	# Wordpress version detection via - readme.html
    def wp_ver_readme(url)
  		site=url_2_site(url)
      readme_url=site + "readme.html"
      k=Wmap::UrlChecker.new
  		puts "Res code: #{k.response_code(readme_url)}" if @verbose
      if k.response_code(readme_url) == 200
        k=nil
        doc=open_page(readme_url)
  			puts doc if @verbose
        logo=doc.css('h1#logo')[0]
        puts logo.inspect if @verbose
  			return logo.to_s.scan(/[\d+\.]+\d+/).first
      end
      k=nil
      return nil
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
  	end

    # Wordpress version detection via - /wp-admin/load-styles.php
    def wp_ver_load_styles(url)
  		site=url_2_site(url)
      load_styles_url = site + "wp-admin/load-styles.php"
      k=Wmap::UrlChecker.new
      if k.response_code(load_styles_url) == 200
        headers = k.response_headers(load_styles_url)
        if headers.keys.include?("etag")
          k=nil
          return headers["etag"]
        end
      end
      k=nil
      return nil
  	rescue => ee
  		puts "Exception on method #{__method__} for url #{url}: #{ee}" if @verbose
  		return nil
  	end


  end
end
end
