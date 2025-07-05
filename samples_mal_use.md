# Samples malicious user's stories based for common vulnerabilities (OWASP)
## SQL Injection in Login

    Attacker Story:
    As an attacker, I want to inject SQL in the login form so that I can bypass authentication and access user data.

    STRIDE Category: Tampering, Elevation of Privilege


## Cross-Site Scripting (XSS)

    Attacker Story:
    As an attacker, I want to inject JavaScript into a comment field so that I can steal user sessions.

    STRIDE Category: Tampering, Information Disclosure


## Privilege Escalation via API

    Attacker Story:
    As an attacker, I want to exploit insufficient role checks in the API so that I can gain admin access.

    STRIDE Category: Elevation of Privilege, Spoofing

## IDOR (Insecure Direct Object Reference)

    Attacker Story:
    As an attacker, I want to change resource IDs in the URL so that I can view another user’s data.

    STRIDE Category: Information Disclosure, Tampering


## Brute Force Login

    Attacker Story:
    As an attacker, I want to try many passwords so that I can guess valid credentials.

    STRIDE Category: Spoofing, Denial of Service (via lockout abuse)


## CSRF (Cross-Site Request Forgery)

    Attacker Story:
    As an attacker, I want to trick a logged-in user into clicking a malicious link so that I can change their email address.

    STRIDE Category: Tampering, Repudiation


## Software and Data Integrity Failures (A08:2021)

    Attacker Story:
    As an attacker, I want to tamper with software updates so that I can execute malicious code in the application.

    STRIDE Category: Tampering, Elevation of Privilege


## Security Logging and Monitoring Failures (A09:2021)

    Attacker Story:
    As an attacker, I want to exfiltrate data without triggering alerts so that I can stay undetected.

    STRIDE Category: Repudiation, Information Disclosure

## Server-Side Request Forgery (SSRF) (A10:2021)

    Attacker Story:
    As an attacker, I want to make the server send requests on my behalf so that I can access internal systems.

    STRIDE Category: Spoofing, Information Disclosure
