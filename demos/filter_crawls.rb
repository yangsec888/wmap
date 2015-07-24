require "wmap"

k=Wmap::UrlCrawler.new(:verbose=>true)
sites=k.crawls(k.file_2_list(ARGV[0]))
k.wlog(sites,".crawl_sites") 
