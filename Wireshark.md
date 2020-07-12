# Useful Wireshark filter expressions

## Some general tips and tricks

1. Look for connections to high number ports.
2. DNS to strange randomly looking domains.
3. HTTP requests to IP numbers (no domains specified) with strange GET parameters.
4. Look for HTTP Referer to see how the user got redirected there; find link between compromised and infected site.
5. Sometimes it may be easier to find the final infection (ie. exploit-kit or malware download) *Statistics -> Conversations -> Sort by bytes*
6. Sort by largest byte stream, look at the IP address, domain name and follow HTTP stream if you can see anything special
7. Lab 5 Suricata: Note that `<meta HTTP-Equiv="refresh" content...` and `loc = "http://www.montearts.com/wp-includes/adobecloud/index.php"`
self.location.replace(loc);`, *two* redirection methods are unusual.
8. Can submit URLs in virustotal.com
9. You can export specified packets after filtering to isolate those packets from the stream.
10. Don't rely on Network miner to list all files DL'ed. For some reason files DL over diff port number (not 80,443) doesn't appear.
11. Try both Follow -> TCP stream and HTTP stream. You might see things in one that is not covered by the other.
  1. [Here](http://malware-traffic-analysis.net/2016/08/20/page2.html) if you had just used Follow -> HTTP stream you would have missed the iframe which redirected to http://tilisinga-ismaeliet.starlightsteps.org.uk, see `tcp.stream eq 81`
  2. Whereas in [this](http://malware-traffic-analysis.net/2014/11/16/index.html) - If you had Follow -> TCP stream you wouldn't be able to read the gzip-encoded body in frame 981 which redirected to http://stand.trustandprobaterealty.com, see `tcp.stream eq 18`
  14. Useful link for de-obfuscating JS code - [JS deobfuscator](https://lelinhtinh.github.io/de4js/)

### Tips

1. Establish the IP, MAC, hostname of the interesting hosts.
2. Determine which protocol has the main traffic ie HTTP, SMTP, SSH, Telnet etc.
3. Filter for `dhcp`, `nbns` to determine MAC, Windows hostnames.
3. Check for IPV6 traffic.
4. The course covers TLS certificate, DNS, ICMP exfiltration. Learn to detect these. Most likely by looking at the length of the payloads.

## TLS/SSL

1. Filters out all the TLS/SSL handshakes `ssl.record.content_type == 22`
2. Filters out heartbeats specifically `ssl.record.content_type == 24`
  1. Detect heartbleed by looking at Heartbeat Request, very long invalid payload length requested and subsequent response. Note that server may not be vulnerable to heartbleed.

## DNS

1. Flags out all DNS requests `dns` or even better by source `ip.addr == 192.168.204.146 && dns`
2. Find IP of given domain `dns.resp.name == "epzqy.iphaeba.eu"` or right-click -> Apply as Filter

Filter all traffic to/from this IP
```ip.addr == 118.123.6.95```

Filter by CIDR
`ip.src == 172.16.165.165 && ip.dst == 172.16.165.0/24`

## Identifying host client computers

To find hostname, two ways:
1. Filter `dhcp`, look for *DHCP Request -> Option -> Host Name* sent by host to be identified.
2. Filter `nbns`, look for *NetBIOS Name Service -> Additional records -> Name* sent by host
3. Note you can sometimes identify source OS by looking at User-Agent strings

Searching throught packet contents in WS
https://www.cellstream.com/reference-reading/tipsandtricks/431-finding-text-strings-in-wireshark-captures

Apply not
```!(udp.dstport == 16464)```

`tcp.port==4000` sets a filter for any TCP packet with 4000 as a source or dest port

## MAC filter

1. `eth.addr`, `eth.src`

## Export -> HTTP

1. Note that the frame no. stated shows the frame HTTP 200 OK received.

## NTLM filtering

```ntlmssp.ntlmserverchallenge```

## Kerberos / SMB2 filtering

`kerberos` and `smb2`

## HTTP notes

1. To filter HTTP response codes > 200, do `http.response.code > 200`

`http.request` to filter all the HTTP methods

#### Filter by HTTP host (case-sensitive) [Reference](https://osqa-ask.wireshark.org/questions/33938/how-can-i-filter-by-website-names)

```
http.host contains "website.com"
```
or 
```
http.host=="exact.name.here"
```

#### Filter by HTTP User-Agent (case-insensitive)

`http.user_agent matches "(?i)java"` - Matches all user-agent with "java" inside

### Other HTTP notes

There is a difference between 
1. *Follow -> TCP Stream* and 
2. *Follow -> HTTP Stream*
    Explanation [here](https://blog.didierstevens.com/2017/08/23/wireshark-follow-streams/). Generally gzip HTML data doesn't render, so click on a packet whose protocol is recognised as HTTP by WS and Follow -> HTTP Stream.

3. One way is to apply HTTP filter together with TCP stream to see if there are HTTP streams in that TCP one `http and (tcp.stream eq 18)`

4. Check for unusual connections with high TCP port numbers `ip.src == 172.16.165.132 && ((tcp.dstport > 443) || (udp.dstport > 443))`


# References
1. https://github.com/wireshark/wireshark/blob/master/doc/wireshark-filter.pod
2. https://gist.github.com/githubfoam/08efac0343f98bd727caa32e6c81f655
3. https://www.wireshark.org/docs/dfref/h/http.html
4. [Good reference](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)