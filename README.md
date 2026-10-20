# Network Intrusion Detection System

## What it does
This project uses Suricata to watch network traffic and raise an alert whenever something matches a rule. A small Python script then blocks the attacker automatically.

## Lab setup
I used two virtual machines on the same network. Ubuntu (10.0.2.3) is the target and runs Suricata 8.0.3 as a service on enp0s3, while Kali (10.0.2.15) acts as the attacker.

## Detection rules
I wrote three custom rules in local.rules. They alert on ping (ICMP echo requests), on a port scan (20 SYN packets from one source within 5 seconds), and on SSH attempts (5 connections to port 22 within 60 seconds).

## Response script
block_attacker.py reads Suricata’s alert log, picks out the attacker IP from the port scan alerts, and blocks it with iptables. It skips a safe list (the Ubuntu VM, the gateway, localhost), won’t add the same rule twice, and logs every block in blocked.log.

## Results
An Nmap scan from Kali over 1000 ports gave 50 alerts, one for every 20 SYNs, and the ping, port scan and SSH rules all fired. After I ran the script, Kali got 100% packet loss when pinging Ubuntu.
![Rules](CodeAlpha_NetworkIDS%20Screenshots/1-rules.png)
![Suricata running](CodeAlpha_NetworkIDS%20Screenshots/2-suricata-running.png)
![Ping alert](CodeAlpha_NetworkIDS%20Screenshots/3-ping-alert.png)
![Port scan alert](CodeAlpha_NetworkIDS%20Screenshots/4-portscan-alert.png)
![SSH alert](CodeAlpha_NetworkIDS%20Screenshots/5-ssh-alert.png)
![Block script](CodeAlpha_NetworkIDS%20Screenshots/6a-block-script.png)
![Kali blocked](CodeAlpha_NetworkIDS%20Screenshots/6b-kali-blocked.png)

## Limitations
The script reads the whole log, so an old alert can still trigger a block. I also have to run it by hand, and Suricata only detects, so the script is the only thing that actually blocks.

## What I learned
I learned how a Suricata rule is built from an action, a header and options. The threshold setting stops a single packet from setting off an alert, which is why the Nmap scan gave 50 alerts instead of 1000. I also saw how readable the alert log is once you know where the source IP sits in each line.

## How to run it
Install Suricata, put local.rules in /var/lib/suricata/rules/, and list it under rule-files in suricata.yaml, where you also set the interface to the one your machine uses. Load the rules with sudo suricatasc -c reload-rules, then start the script with sudo python3 block_attacker.py. To undo a block, run sudo iptables -D INPUT -s ATTACKER_IP -j DROP.
