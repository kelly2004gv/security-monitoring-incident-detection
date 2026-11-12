# Security Incident Investigation

## Incident 001 — Possible Brute-Force Attack

### 1. Incident Summary

The security monitoring tool identified five failed login attempts against the account `employee1`, followed by a successful login from the same source IP address.

### 2. Evidence

| Field | Finding |
|---|---|
| Username | employee1 |
| Source IP | 192.168.1.10 |
| Failed attempts | 5 |
| Time period | 7 minutes |
| Successful login | Yes |
| Detection rule | RULE-003 |

### 3. Analysis

The authentication pattern is consistent with possible brute-force behavior.

The successful login following repeated authentication failures increases the need for investigation.

However, the available evidence does not confirm that the account was compromised.

### 4. Risk

Potential unauthorized access to an employee account.

### 5. Recommended Actions

1. Verify the employee's identity.
2. Review the successful login session.
3. Investigate related authentication events.
4. Check whether the source IP belongs to an authorized device.
5. Consider revoking suspicious sessions if unauthorized access is confirmed.
6. Review MFA and password policies.

### 6. Conclusion

The activity was flagged as suspicious. Additional investigation is required before confirming account compromise.

---

## Incident 002 — Repeated Failed Admin Logins

### 1. Incident Summary

The security monitoring tool identified five failed login attempts against the `admin` account within eight minutes.

### 2. Evidence

| Field | Finding |
|---|---|
| Username | admin |
| Source IP | 203.0.113.10 |
| Failed attempts | 5 |
| Time period | 8 minutes |
| Successful login | No |
| Detection rules | RULE-001 and RULE-002 |

### 3. Analysis

The activity indicates repeated authentication failures targeting an administrative account.

Administrative accounts may have elevated permissions, making unauthorized access particularly concerning.

The source IP belongs to a documentation-only range used for this simulated dataset.

### 4. Risk

Potential unauthorized attempts to access a privileged account.

### 5. Recommended Actions

1. Review administrative account authentication history.
2. Verify whether the login attempts were expected.
3. Check approved network and VPN records in a real environment.
4. Review privileged account access policies.
5. Ensure multifactor authentication is enabled.
6. Escalate confirmed suspicious activity to the security team.

### 6. Conclusion

The activity represents a suspicious authentication pattern. The dataset does not show a successful login or prove that the account was compromised.

---

## Investigation Limitations

This project uses synthetic authentication records.

The IP addresses and usernames are examples created for educational and portfolio purposes.

The findings demonstrate how automated security alerts can support an investigation. They do not establish that an actual security incident occurred.