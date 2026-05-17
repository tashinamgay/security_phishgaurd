# Incident Response Simulation

## Scenario

An attacker attempts repeated login guesses against a PhishGuard account.

## Detection

PhishGuard records login attempts in the login logs collection. Failed attempts are displayed in the admin security panel.

Security control:

- A username is blocked after 5 failed login attempts.
- The admin security page shows recent login attempts and failed-attempt counts.

## Response steps

1. Admin reviews the security panel.
2. Admin identifies the username with repeated failed attempts.
3. Admin suspends the affected account if the activity looks suspicious.
4. Admin asks the user to reset credentials and enable 2FA.
5. Admin reviews whether the source IP or pattern should be blocked at infrastructure level.

## Evidence to include in report

- Screenshot of the admin security panel showing failed login attempts.
- Screenshot or log showing the "Too many failed attempts" message.
- Explanation that the response stayed within the authorised test environment.
