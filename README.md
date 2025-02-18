[<img src='/wmap_logo.jpg' width='350' height='350'>](https://github.com/yangsec888/wmap)
=====================

- [What's this program for?](#whats-this-program-for)
- [WMAP in Motion](#wmap-in-motion)
- [Installation](#installation)
- [Before Using This Program](#before-using-this-program)
- [More Document(s)](#more-documents)
- [Program Version](#program-version)
- [Author Contact](#author-contact)
- [Bug Report or Feature Request](#bug-report-or-feature-request)
- [Legal Disclaimer](#legal-disclaimer)

# OWASP Web Mapper README


## What's this program for?
This program is part of the [OWASP Web Mapper Project](https://www.owasp.org/index.php/OWASP_Web_Mapper_Project). It's designed for the web application asset discovery and tracking. It was originally developed to cover the gaps of a similar commercial offering. Over the time it grows to be a more capable and complete replacement (IMHO).

Note that program is mainly operating on Command Line Interface (CLI). For better user experience, you might want to use the [Web Mapper Portal Application](https://github.com/yangsec888/www_wmap) instead.


## WMAP in Motion
You can try out the complete [demo web app](https://www.wmap.cloud/) deployed in the DigitalOcean cloud: https://www.wmap.cloud/


## Installation
To take full power of this program, you would need an *nix flavor machine with direct Internet access. I have installed it successfully on both Mac and Linux machines. You'll also need the Ruby environment being setup properly. The easiest way to install OWASP Web Mapper is by using Ruby Gems. You can install it from command line:
```sh
$ gem install wmap
```

### Specific Installation Problem with Nokogiri
Nokogiri is a native xml/html parser used by the project. It's fast and powerful. However, it comes with pitfall of installation problem around building native extension for your environment. Please refer to this page for trouble-shooting tip (http://www.nokogiri.org/tutorials/installing_nokogiri.html).

### Dependency
You need the Ruby 2.1.0 or above in order to use this program. In my test environment, I was able to set it up with <a href="https://rvm.io/">RVM</a>. Please refer to this page for more installation information: https://www.ruby-lang.org/en/documentation/installation/

In addition, the following Ruby GEM dependency are needed by different features of this software. They should be installed automatically when you install the 'wmap' gem above.
```
      require "dnsruby"
      require "geoip"
      require "minitest/autorun"
      require "net/ping"
      require "netaddr"
      require "nokogiri"
      require "css_parser"
      require "openssl"
      require "open_uri_redirections"
      require "parallel"
      require "whois"
      require 'httpclient'
```

### Before Using This Program
You need to define a scope for the program to run successful. The scope includes both your legitimate Internet domain, and your public
network block in the CIDR format.

To add your Internet domain into the scope, use the build-in shell command below:
```sh
$ trust --target XYZ.COM
```
To add your public network block into the scope (note current support of IPv4 only):
```sh
$ trust --target x.x.x.x/x
```
Use command switch '--help' for more information
```sh
$ trust --help
```

### Automatic Discovery and Tracking
```sh
    wmap -t <seed file | target host | target url | target IP or network cidr>
```
The above utility is intelligent enough to take argument as either a seed file, or a string such as a host, an IP, a network block, or a URL. The new discoveries will be automatically tracked in the data file 'lib/wmap/data/target_sites'.
  Note: seed file - mix of url, cidr and domain seed, one entry per line.
				url seed - known URL(s) for further discovery via the web crawler.
				cidr seed - list of known network blocks, for discovering web service via port scanning; it is also used to validate if the web service has a known IP (internal hosted).
				domain seed - validated internet domain to be used for DNS record brute-forcing; it is also used to validate the ownership of found web service.


### Dump Out Discovery Database
You can dump out the program output by using the build-in utility 'wdump' as shown below:
```sh
$ wdump [output file name from you]
```
The above utility will dump out the discovery database into a single file as program output. Currently, the supported file format is Comma-separated Value (.csv) and Extensible Markup Language (.xml)


### More Usage Cases:
There are more examples under the 'demos' folder of this package. The examples show how to use the 'wmap' API to get your job done easily. Please check out the code - they should be easy and straightforward to be understood.


## More Document(s):
The software comes with the Ruby doc during your installation as shown above. For your convenience, the Ruby doc is also distributed with this software. You can navigate to the 'doc' folder of your local installation, and click the 'index.html' to open the start page in your favorite browser. You can also download the wmap-x.x.x.rdoc.zip documentation package alone from GitHub, unzip and open the doc/index.html in your browser.

If you need additional documentation / information other than this README file and the Ruby document package, please be patient - as I'm still working on it :)


## Program Version
The latest release is version [2.6.5+](version.txt). as of fall 2019. Please refer to the [CHANGELOG.md](CHANGELOG.md) for more history information.


## Author Contact
This program is designed and developed by Sam (Yang) Li. You can reach him by Email: <yang.li@owasp.org>
## Bug Report or Feature Request?
Contact the author Sam (Yang) Li directly at email 'yang.li@owasp.org'.


## Legal Disclaimer:
This software is provided strictly 'as-if' without any implied warranty. You're free to copy or modify the codes anyway you want - a reference back to this software will be appreciated. Please refer to the 'LICENSE.txt' file for more information.
