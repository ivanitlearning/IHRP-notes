# Suricata

Rules in **/etc/suricata/rules/**

Logs in **/var/log/suricata/**:
1. eve.json <- Suricata's recommended output

   Pipe to **less** with colours
   
   ```elsanalyst@training ~ $ jq -C 'select(.event_type == "alert")' /var/log/suricata/eve_archived.json.1 | less -R```
2. fast.log
3. stats.log <- Human-readable statistics log

Run **evebox** to analyse suricata logs via HTTP from outside.
```
elsanalyst@training ~ $ sudo evebox oneshot --host "0.0.0.0" /var/log/suricata/eve_archived.json.1
```
Then visit the suricata server at port 5636.

## Suricata commands
Run suricata on interface with specified rules
```
elsanalyst@training ~ $ sudo suricata -c /etc/suricata/suricata.yaml -s customsig.rules -i ens33
3/5/2020 -- 05:34:49 - <Notice> - This is Suricata version 4.1.2 RELEASE
3/5/2020 -- 05:34:49 - <Notice> - all 1 packet processing threads, 4 management threads initialized, engine started.
```

Run suricata passively on **.pcap** files
```
elsanalyst@training ~ $ sudo suricata -c /etc/suricata/suricata.yaml -s customsig.rules -r /home/elsanalyst/PCAPs/eicar-com.pcap
```

Run suricata passively on .pcap, skip checksum
```
sudo suricata -r PCAPs/eicar-com.pcap -k none -l <path to log dir>
```

Read [this](https://suricata.readthedocs.io/en/suricata-5.0.3/rules/intro.html) for guide to rules

## Bash script for testing Suricata rules
```bash
#!/usr/bin/env bash
#Basic suricata sigdev script
#jwilliams@oisf.net

#cleanup logs from previous run
if [ -d "/tmp/suricata" ]; then
    rm -rf /tmp/suricata && mkdir /tmp/suricata
else
    mkdir /tmp/suricata
fi

#run suricata on the pcap given as the argument
sudo suricata -c /etc/suricata/suricata.yaml -S /home/elsanalyst/customsig.rules -k none -r $1 -l /tmp/suricata

#print out sig hits
echo -e "\nSignature Hits:\n"
cat /tmp/suricata/fast.log
```

Invoke this way
```
elsanalyst@training:/tmp/suricata$ sudo /home/elsanalyst/Desktop/automate_suricata.sh /home/elsanalyst/PCAPs/Sofacy.pcap
```

#### Writing suricata rules

Basically the idea is to match text, before, after certain content, taking into account whether it's content modifier or sticky buffer.

#### Suricata content modifiers vs sticky buffers

See [this](https://suricata.readthedocs.io/en/suricata-4.1.4/rules/intro.html#rules-modifiers). Basically modifier means it looks at what precedes the http_thing to match, while sticky buffer precedes the content to match.

#### Prefiltering keywords

What is **fast_pattern**? Explanation with [eg here.](https://suricata.readthedocs.io/en/suricata-4.1.4/rules/prefilter-keywords.html?highlight=fast_pattern). Basically **fast_pattern** is a content modifier which prioritises the Content just preceding it.