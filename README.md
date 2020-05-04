# IHRP notes
Collection of notes taken for eLS IHRP course

## Network traffic analysis

### IPv6 unique multicast addresses
Table generated [here](https://www.tablesgenerator.com/markdown_tables), taken from Odom's ICND1 guide.
| Short Name             | Multicast Address | Meaning                                                        | IPv4 Equivalent            |
|------------------------|-------------------|----------------------------------------------------------------|----------------------------|
| All-nodes              | FF02::1           | All-nodes (all interfaces that use IPv6 that are on the link)  | A subnet broadcast address |
| All-routers            | FF02::2           | All-routers (all IPv6 router interfaces on the link)           | None                       |
| All-OSPF,  All-OSPF-DR | FF02::5, FF02::6  | All OSPF routers and all OSPF-designated routers, respectively | 224.0.0.5, 224.0.0.6       |
| RIPng Routers          | FF02::9           | All RIPng routers                                              | 224.0.0.9                  |
| EIGRPv6 Routers        | FF02::A           | All routers using EIGRP for IPv6 (EIGRPv6)                     | 224.0.0.10                 |
| DHCP Relay Agent       | FF02::1:2         | All routers acting as a DHCPv6 relay agent                     | None                       |




### Suricata

Rules in **/etc/suricata/rules/**

Logs in **/var/log/suricata/**:
1. eve.json <- Suricata’s recommended output

   Pipe to **less** with colours
   
   ```elsanalyst@training ~ $ jq -C 'select(.event_type == "alert")' /var/log/suricata/eve_archived.json.1 | less -R```
2. fast.log
3. stats.log <- Human-readable statistics log

Run **evebox** to analyse suricata logs via HTTP from outside.
```
elsanalyst@training ~ $ sudo evebox oneshot --host "0.0.0.0" /var/log/suricata/eve_archived.json.1
```
Then visit the suricata server at port 5636.

#### Suricata commands
Run suricata on interface with specified rules
```
elsanalyst@training ~ $ sudo suricata -c /etc/suricata/suricata.yaml -s customsig.rules -i ens33
3/5/2020 -- 05:34:49 - <Notice> - This is Suricata version 4.1.2 RELEASE
3/5/2020 -- 05:34:49 - <Notice> - all 1 packet processing threads, 4 management threads initialized, engine started.
```

Run suricata passive mode on `.pcap` files
```
elsanalyst@training ~ $ sudo suricata -c /etc/suricata/suricata.yaml -s customsig.rules -r /home/elsanalyst/PCAPs/eicar-com.pcap
```

Run suricata passively on .pcap, skip checksum
```
sudo suricata -r PCAPs/eicar-com.pcap -k none -l <path to log>
```


Read [this](https://suricata.readthedocs.io/en/suricata-5.0.3/rules/intro.html) for guide to rules
