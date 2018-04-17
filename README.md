## CVEStack 
This is a quick little utility to filter the [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) for various elements within your stack. It supports a pip-style format. For instance, this file:
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
Versus just `linux`, which generates
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
    <lastBuildDate>Tue, 17 Apr 2018 05:23:01 +0000</lastBuildDate>
    <item>
      <title>CVE-2018-10124</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10124</link>
      <description>The kill_something_info function in kernel/signal.c in the Linux kernel before 4.13, when an unspecified architecture and compiler is used, might allow local users to cause a denial of service via an INT_MIN argument.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10124</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
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
    <item>
      <title>CVE-2018-10087</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10087</link>
      <description>The kernel_wait4 function in kernel/exit.c in the Linux kernel before 4.13, when an unspecified architecture and compiler is used, might allow local users to cause a denial of service by triggering an attempted use of the -INT_MIN value.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10087</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2018-10074</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10074</link>
      <description>The hi3660_stub_clk_probe function in drivers/clk/hisilicon/clk-hi3660-stub.c in the Linux kernel before 4.16 allows local users to cause a denial of service (NULL pointer dereference) by triggering a failure of resource retrieval.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-10074</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2017-2628 (curl)</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-2628</link>
      <description>curl, as shipped in Red Hat Enterprise Linux 6 before version 7.19.7-53, did not correctly backport the fix for CVE-2015-3148 because it did not reflect the fact that the HAVE_GSSAPI define was meanwhile substituted by USE_HTTP_NEGOTIATE. This issue was introduced in RHEL 6.7 and affects RHEL 6 curl only.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-2628</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2017-18224 (linux_kernel)</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-18224</link>
      <description>In the Linux kernel before 4.15, fs/ocfs2/aops.c omits use of a semaphore and consequently has a race condition for access to the extent tree during read operations in DIRECT mode, which allows local users to cause a denial of service (BUG) by modifying a certain e_cpos field.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-18224</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2017-1677 (db2)</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-1677</link>
      <description>IBM Data Server Driver for JDBC and SQLJ (IBM DB2 for Linux, UNIX and Windows 9.7, 10.1, 10.5, and 11.1) deserializes the contents of /tmp/connlicj.bin which leads to object injection and potentially arbitrary code execution depending on the classpath. IBM X-Force ID: 133999.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-1677</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
    <item>
      <title>CVE-2015-1777</title>
      <link>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1777</link>
      <description>rhnreg_ks in Red Hat Network Client Tools (aka rhn-client-tools) on Red Hat Gluster Storage 2.1 and Enterprise Linux (RHEL) 5, 6, and 7 does not properly validate hostnames in X.509 certificates from SSL servers, which allows remote attackers to prevent system registration via a man-in-the-middle attack.</description>
      <guid isPermaLink="false">https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1777</guid>
      <comments>CVEStack: Matches 'linux'</comments>
    </item>
  </channel>
</rss>
```
