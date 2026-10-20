import subprocess
from datetime import datetime

# addresses that must never be blocked (this machine, the gateway, localhost)
safe = {"10.0.2.3", "10.0.2.2", "127.0.0.1"}
attackers = set()

# reads the Suricata log and collects the source IP of every port scan alert
for line in open("/var/log/suricata/fast.log"):
    if "port scan" in line:
        left = line.split(" -> ")[0]
        ip = left.split()[-1].split(":")[0]
        attackers.add(ip)

for ip in attackers:
    if ip in safe:
        print("skipping safe address", ip)
        continue
    # checks first so the same IP doesn't get blocked twice
    already = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    if already.returncode == 0:
        print(ip, "is already blocked")
        continue
    # adds a rule at the top of the firewall that drops all traffic from this IP
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    message = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " blocked " + ip + " (port scan)"
    print(message)
    with open("blocked.log", "a") as f:
        f.write(message + "\n")
