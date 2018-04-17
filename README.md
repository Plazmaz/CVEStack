## CVEStack 
This is a quick little utility to filter the [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) for various elements within your stack, then rebroadcasts the reduced feed on the specified port (defaults to 8088) It supports a pip-style format. For instance, this file:
```
linux
wordpress
````

Produces an RSS-style feed for all CVEs returned matching the keywords `linux` or `wordpress`. You could also require a version number. **Please note this might return false negatives. NVD does not provide formal version data.**. 
You can use this feature by doing something like:
```
linux==4.13
```
Which would generate this feed:
```
<?xml version='1.0' encoding='UTF-8'?>
<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0">
  <channel>
    <title>National Vulnerability Database</title>
    <link>https://web.nvd.nist.gov/view/vuln/search</link>
    <description>National Vulnerability Database</description>
    <atom:link href="https://web.nvd.nist.gov/view/vuln/search" rel="self"/>
    <docs>http://www.rssboard.org/rss-specification</docs>
    <generator>python-feedgen</generator>
    <lastBuildDate>Tue, 17 Apr 2018 05:22:27 +0000</lastBuildDate>
    <item>
      <title>CVE-2018-10124</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10124</link>
      <description>The kill_something_info function in kernel/signal.c in the Linux kernel before 4.13, when an unspecified architecture and compiler is used, might allow local users to cause a denial of service via an INT_MIN argument.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10124</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2018-10087</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10087</link>
      <description>The kernel_wait4 function in kernel/exit.c in the Linux kernel before 4.13, when an unspecified architecture and compiler is used, might allow local users to cause a denial of service by triggering an attempted use of the -INT_MIN value.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10087</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
  </channel>
</rss>
```
Versus just `linux`, which would generate a much larger feed.  
*Note the pattern matched is displayed in the <comments> tag*

Usage:
```
  -h, --help            show the help message and exists
  --pattern-file PATTERN_FILE, -f PATTERN_FILE
                        Sets the file to pull patterns from (defaults to
                        ".dependencies.txt")
  --strip-spaces, -s    Sets if spaces should be stripped from patterns
                        (Defaults to false)
  --left-pad, -lp       Sets if patterns should be prefixed with a left space
                        (Defaults to true)
  --right-pad, -rp      Sets if patterns should be suffixed with a right space
                        (Defaults to false)
  --port PORT, -p PORT  Sets the listening port (defaults to 8088)
```
