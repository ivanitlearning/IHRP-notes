# IHRP notes
Collection of notes taken for the eLS IHRP course. I took these notes while going through the course. They are not meant to be comprehensive or complete and are meant largely for reference.

## Contents

* [Useful Wireshark filter expressions](./Wireshark.md)
* [Threathunting with Windows logging](./Threathunt-signs.md)
* [Suricata cheatsheet](./Suricata.md)
* [Splunk cheatsheet](./Splunk.md)
* [ELK cheatsheet](./ELK.md)
* [Bro/Zeek cheatsheet](./Zeek.md)

## Misc notes

### Analyse pcap with Security Onion

```
ivan@SO:~/IHRP/2015-02-24-traffic-analysis-exercise$ sudo so-import-pcap 2015-02-24-traffic-analysis-exercise.pcap
```

#### Kibana SO

Visit https://192.168.92.142/app/kibana, restrict time range to pcap's.

#### Squert

Visit https://192.168.92.142/squert/, restrict time range.
[How to restrict time range (time interval)](https://securityonion.readthedocs.io/en/latest/squert.html)

#### OSINT and other tools

1. https://www.threatminer.org/ - Can analyse file hashes of malware tells you what IP it communicates with. Check out virusshare as well it gives the port number and process it masquerades as.
2. https://threatcrowd.org/ - Alternative, searches IP, domain but not file hashes
3. https://htmledit.squarefree.com/ - For rendering HTML content (more readable emails)
4. https://hybrid-analysis.com/
5. Or search Google for URL/hash, hopefully links you to something useful