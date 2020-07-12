# Bro cheat sheet

## Command line passive mode pcap

```bro -Cr <pcap> local```

https://old.zeek.org/manual/2.5.5/quickstart/index.html#bro-as-a-command-line-utility

[Quick Bro reference](http://gauss.ececs.uc.edu/Courses/c6055/pdf/bro_log_vars.pdf)

## Method

1. Analyze **pcap** with local script (above)
2. Check **weird.log** to see mislabelled traffic (ie. SSL traffic hiding as plain over TCP 80)
3. Check if self-signed cert
4. Check the certs-remote.pem file, if found. 
  1. Use `openssl` to inspect
  2. `openssl x509 -in 1.pem -text -noout`

### Inspecting http.log
```
cat  http.log  |  bro-cut id.orig_h id.orig_p id.resp_h id.resp_p host uri referrer
```

### conn.log

1. See important fields

```
cat  conn.log  |  bro-cut id.orig_h id.orig_p id.resp_h id.resp_p proto conn_state
```
2. Also remember to check if there is suspicious traffic such as SSL over port 80

### dns.log
```
cat dns.log | bro-cut id.orig_h id.resp_h id.resp_p query
```

### Reverse xxd a long hex string to see if it's a binary

```cat 1.txt | xxd -r -p | strings```

##### Example on using Bro logs to detect Java RMI Registry exploitation

Inspect Bro's **conn.log** for hosts that run Java RMI Registry on TCP 1099, check that it communicates with remote machine over default port 8080, then check **http.log** that it gets jar file from the remote server.

### RITA

Security Onion installation instructions [here](https://securityonion.readthedocs.io/en/latest/rita.html).

Supports detection of 

1. Beaconing Detection: Search for signs of beaconing behavior in and out of your network
2. DNS Tunneling Detection Search for signs of DNS based covert channels
3. Blacklist Checking: Query blacklists to search for suspicious domains and hosts

Configure config file at `/etc/rita/config.yaml` to specify internal subnet so RITA knows which is client/server.

1. Import Zeek logs with `rita import /nsm/bro/logs/2019-09-04 dataset1` then view with `rita html-report`
2. Run python http server to view report.