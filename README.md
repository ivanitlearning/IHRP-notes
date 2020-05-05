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



