# Linux Authentication Log Analysis

## 1. Introduction

Linux systems maintain authentication logs that record security-related activities, including login attempts, authentication failures, and administrative actions.

On Ubuntu, authentication events are commonly recorded in:

`/var/log/auth.log`

These logs help cybersecurity analysts investigate system access and identify potentially suspicious behavior.

## 2. What SSH Authentication Means

SSH stands for Secure Shell. It is a network protocol that allows users to securely access and manage remote computers.

SSH authentication verifies the identity of a user attempting to connect to a remote Linux system.

Examples of SSH authentication events include:

- Successful password authentication.
- Failed password attempts.
- Attempts using invalid usernames.

## 3. Commands Used for Log Investigation

The following Linux commands were used to examine authentication activity:

**View authentication logs:**
```bash
sudo less /var/log/auth.log
```

**Search for failed login attempts:**
```bash
sudo grep "Failed password" /var/log/auth.log
```

**Search for successful SSH logins:**
```bash
sudo grep "Accepted password" /var/log/auth.log
```

**Count failed login attempts:**
```bash
sudo grep -c "Failed password" /var/log/auth.log
```

**Search for SSH authentication activity:**
```bash
sudo grep "sshd" /var/log/auth.log
```

## 4. Identifying Source IP Addresses

Authentication logs can contain the IP address from which an SSH connection originated.

For example:

`Failed password for employee1 from 203.0.113.10 port 52341 ssh2`

The source IP address is `203.0.113.10`.

Source IP addresses help analysts investigate where authentication requests originated.

## 5. Why Authentication Logs Matter

Authentication logs are important for cybersecurity because they provide evidence of system access and authentication activity.

Analysts can use these records to:

- Identify repeated failed login attempts.
- Investigate potential brute-force attacks.
- Identify successful authentication events.
- Review administrative activity.
- Investigate suspicious login sources.

## 6. Connection to the Python Project

This project uses a synthetic CSV dataset to simulate authentication events.

The Python analyzer processes the dataset and identifies suspicious login patterns using custom detection rules.

The Ubuntu exercise demonstrates how authentication events are recorded and investigated on a Linux system.

The current Python implementation does not automatically collect or analyze live Linux authentication logs.