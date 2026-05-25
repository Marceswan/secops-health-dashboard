# Triage Playbook

Per-rule guidance for triaging findings produced by the SecOps Health
Dashboard. For each rule: severity, what it means, how to triage, and
the recommended remediation. Rules are grouped by category.

Severity scale: `Critical` -> `High` -> `Medium` -> `Low`.

Shield-only rules are marked with `[Shield]` and only fire if the
capability probe detected Real-Time Event Monitoring.

---

## Category: OAuth Risk

### 1. New_ConnectedApp_Broad_Scope
- Severity: **High**
- Meaning: A Connected App was created (or modified) in the last 24
  hours and granted broad OAuth scopes such as `full`, `api`, or
  `refresh_token` combined with `web`.
- Triage:
  1. Open the Connected App in Setup.
  2. Identify the creator and the scopes requested.
  3. Confirm with the security team whether the integration was
     pre-approved.
- Remediation: Revoke or scope-down the app. If unauthorised, block
  the OAuth Policy and rotate the consumer secret.

### 6. Unknown_ConnectedApp_Granted
- Severity: **Medium**
- Meaning: A user granted a token to a Connected App that is not on
  the known-good list.
- Triage: Check the OAuthToken record for app name, user, and IP.
  Cross-reference with the customer's allowed integrations.
- Remediation: Revoke the token from Setup -> OAuth Connected Apps
  Usage if the app is not approved. Educate the user.

### 7. Admin_With_Third_Party_Token
- Severity: **High**
- Meaning: A user with `ModifyAllData` or `Manage Users` granted a
  refresh token to a third-party Connected App.
- Triage: Identify the admin, the app, and when the token was issued.
  Determine whether the admin needed third-party access.
- Remediation: Revoke the token immediately. Move the integration to
  a least-privileged service account.

### 10. Stale_OAuth_Token
- Severity: **Low**
- Meaning: An OAuth token has not been used in 90 days but is still
  active.
- Triage: List the token, user, and Connected App. Confirm with the
  owner whether the integration is still required.
- Remediation: Revoke the token. If the integration is still needed,
  re-issue with a shorter refresh window.

### 12. New_App_Surge
- Severity: **High**
- Meaning: More than 3 new Connected Apps were created in the last
  24 hours.
- Triage: List all new apps. Check whether a deploy job or a managed
  package created them in bulk; if not, treat as suspicious.
- Remediation: Disable any unauthorised apps. Audit deployment
  history for unexpected metadata pushes.

### 20. Mass_Report_Export `[Shield]`
- Severity: **High**
- Meaning: A single user exported more than 10 reports in 1 hour
  (sourced from `ReportEventStream`).
- Triage: Identify the user, the reports, and the destination
  (download vs scheduled email).
- Remediation: Suspend the user pending review. Lock the affected
  reports. Check for credential compromise.

### 22. Api_Volume_Spike `[Shield]`
- Severity: **Medium**
- Meaning: API call volume for a single user or Connected App is
  3x the 7-day baseline.
- Triage: Pull the `ApiEvent` rows. Confirm whether a new
  integration deployed legitimately.
- Remediation: If unexpected, revoke the token and engage the
  integration owner.

### 23. Bulk_Api_From_New_Client
- Severity: **High** `[Shield]`
- Meaning: Bulk API job submitted from a client ID never seen in the
  baseline.
- Triage: Capture the client IP, client ID, and job size. Validate
  with the integration owner.
- Remediation: Kill the bulk job if unauthorised. Add the client to
  the deny list or require Login IP ranges.

---

## Category: Login Anomaly

### 2. Impossible_Travel
- Severity: **Critical**
- Meaning: Two successful logins for the same user from countries
  too far apart to travel between in the elapsed time.
- Triage: Pull both `LoginHistory` rows. Confirm with the user and
  with VPN logs whether one of the sessions was them.
- Remediation: If not the user, force-logout all sessions, reset the
  password, rotate any active tokens, and require MFA re-enrolment.

### 3. Failed_Login_Burst
- Severity: **Medium**
- Meaning: More than 10 failed logins for one user in 15 minutes.
- Triage: Check whether the user is locked out. Look at source IPs.
  A spread of IPs is more concerning than a single misconfigured
  client.
- Remediation: If credential-stuffing pattern, force a password
  reset and notify the user. Consider adding the source IP block to
  Login IP Ranges.

### 13. Failed_MFA_Burst
- Severity: **Medium**
- Meaning: More than 5 failed MFA challenges for one user in 1 hour.
- Triage: Check whether the user has a new device or a lost token.
  Talk to the user before assuming attack.
- Remediation: Re-enrol the user's MFA factor. If the user denies
  the attempts, treat as account compromise.

### 15. Inactive_User_Login_Success
- Severity: **Critical**
- Meaning: A user marked `IsActive = false` produced a successful
  login event.
- Triage: This should be impossible in steady state. Pull the
  `LoginHistory` row and confirm the user's status timeline.
- Remediation: Deactivate again immediately, reset password, revoke
  all tokens, and open an incident ticket.

### 21. LoginAs_Outside_Hours `[Shield]`
- Severity: **Medium**
- Meaning: An admin used Login As during off-business hours
  (configurable; defaults to 19:00-07:00 local).
- Triage: Confirm whether the admin had a ticket or change record
  authorising the access.
- Remediation: If unauthorised, revoke admin privilege and audit the
  affected user's record changes.

---

## Category: Privilege Escalation

### 4. ModifyAllData_Granted
- Severity: **High**
- Meaning: A permission set or profile change granted the
  `ModifyAllData` permission in the last 24 hours.
- Triage: Identify the change actor, the affected user, and the
  business justification.
- Remediation: If unauthorised, revoke the permission and audit any
  data changes the user made since the grant.

### 14. Privileged_PermSet_Granted
- Severity: **High**
- Meaning: A user was added to a perm set that contains any of:
  `ModifyAllData`, `ViewAllData`, `Manage Users`, `Author Apex`.
- Triage: Validate the assignment against the customer's change
  management process.
- Remediation: Remove if unauthorised. Tighten perm set assignment
  rules.

---

## Category: Setup Change

### 5. MFA_Disabled_For_User
- Severity: **High**
- Meaning: MFA was disabled for a user via permission set or profile
  change.
- Triage: Identify who made the change and why.
- Remediation: Re-enable MFA. Document the exception if legitimate.

### 8. IP_Restriction_Removed
- Severity: **High**
- Meaning: Login IP Ranges were narrowed or deleted on a profile.
- Triage: Confirm with the security team. IP range loosening is a
  common precursor to lateral movement.
- Remediation: Restore the original IP ranges from version control
  or change history if not approved.

### 9. Session_Timeout_Extended
- Severity: **Medium**
- Meaning: Session timeout on a profile was extended beyond the
  customer's policy (default 2 hours).
- Triage: Verify the change ticket. Long sessions widen the window
  for stolen-session attacks.
- Remediation: Revert to policy if no approval. Document any
  exception.

---

## Category: ConnectedApp Drift

### 11. Orphan_ConnectedApp
- Severity: **Medium**
- Meaning: A Connected App exists but has zero active tokens and zero
  usage in the last 30 days.
- Triage: Confirm the integration is no longer in use.
- Remediation: Disable the app. Delete after a 30-day soak.

---

## Category: Baseline Deviation

These rules fire only after the baseline profile has been built (the
first weekly refresh).

### 16. Baseline_New_Country
- Severity: **Medium**
- Meaning: A user logged in from a country not in their 90-day
  baseline.
- Triage: Confirm whether the user travelled. Travel calendars and
  HR systems are the fastest source of truth.
- Remediation: If unexpected, force re-authentication with MFA.

### 17. Baseline_New_Ip24
- Severity: **Medium**
- Meaning: A user logged in from a /24 subnet they have never used.
- Triage: Check whether the user changed ISP or office. VPN
  endpoints often rotate within a /24, so confirm before escalating.
- Remediation: If suspicious, force MFA challenge and review session
  activity.

### 18. Baseline_Off_Hours
- Severity: **Low**
- Meaning: A user logged in outside their typical hours-of-day
  window.
- Triage: Low-signal on its own. Correlate with other findings for
  the same user.
- Remediation: No direct action; escalate only if combined with
  other anomalies.

### 19. Baseline_New_App
- Severity: **Medium**
- Meaning: A user granted a token to a Connected App they have
  never used before.
- Triage: Verify the app is on the approved list and the user had a
  business reason to connect it.
- Remediation: Revoke the token if not approved. Educate the user.

---

## General triage workflow

1. Open the finding from the Posture tab.
2. Read the description and capability gate.
3. Pull the linked records (LoginHistory, OAuthToken, PermissionSet,
   etc.) for full context.
4. Decide: legitimate, unknown, or malicious.
5. Apply the remediation above.
6. Mark the finding `Resolved` with notes explaining the outcome.
7. If malicious, open an incident in the customer's IR tool.

Document every triage decision in the finding's `Notes__c` field so
the next consultant has the history.
