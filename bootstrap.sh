#! /bin/bash
# Allow password authentication for debugging purposes

sed -i "s|PasswordAuthentication no|PasswordAuthentication yes|" /etc/ssh/sshd_config
sudo systemctl daemon-reload
sudo systemctl restart sshd


# Install auditd to prevent profile error
sudo apt update
sudo apt install -y auditd
sudo systemctl restart auditd
