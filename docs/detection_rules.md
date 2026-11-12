# Authentication Threat Detection Rules

## RULE-001: Repeated Failed Logins from One IP

**Severity:** Medium

**Description:** Detects five or more failed login attempts from the same source IP within ten minutes.

**Potential threat:** Brute-force or password-guessing activity.

**Recommended investigation:**
- Identify the source IP.
- Identify targeted accounts.
- Review timestamps and frequency.
- Determine whether the source is expected or authorized.

## RULE-002: Repeated Failed Logins Against One Account

**Severity:** Medium

**Description:** Detects five or more failed login attempts against the same username within ten minutes.

**Potential threat:** Account-targeted password guessing.

**Recommended investigation:**
- Identify the targeted account.
- Review source IP addresses.
- Check whether multiple systems are involved.
- Review account activity after the failed attempts.

## RULE-003: Successful Login After Repeated Failures

**Severity:** High

**Description:** Detects a successful login after at least five failed attempts for the same username and source IP within 30 minutes.

**Potential threat:** Possible account compromise.

**Recommended investigation:**
- Confirm whether the successful login was expected.
- Review the source IP and timestamps.
- Examine subsequent account activity.
- Consider additional authentication safeguards if compromise is suspected.

**Note:** These are educational detection rules. Alerts indicate potentially suspicious behavior and require investigation before confirming an incident.