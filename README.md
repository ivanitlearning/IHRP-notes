# IHRP notes
Collection of notes taken for eLS IHRP course

## Network traffic analysis


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
