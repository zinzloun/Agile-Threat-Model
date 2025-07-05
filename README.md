# Simple framework to integrate threat modeling into Agile
AKA a ethnographic approach to security development
## Note
The framework has been generated with the help of ChatGPT

## Why
Bringing threat modeling into Agile using attacker-based user stories can make security risks more visible and manageable during development
## How
You're essentially flipping traditional user stories to write abuser stories or threat stories, which describe how an attacker might exploit weaknesses. These stories can then be addressed like any other backlog item.

## Follows a framework we can use
#### 🧠 Structure of an Attacker Story

    As an attacker, I want to [action/technique] so that I can [impact].

Example:

    As an attacker, I want to inject SQL code in the login form so that I can bypass authentication and access user accounts.

#### 🔄 How to Integrate into Agile

- Add to the Product Backlog -> Include threat stories alongside user stories.
- Link to User Stories\Features -> Every user story (e.g., "As a user, I want to log in") should be evaluated for potential threat stories.
- Define Acceptance Criteria for Threat Mitigation: Add security controls as criteria
  - Input validation is enforced
  - Parameterized queries are used.
- Use STRIDE or CAPEC to Guide Threat Discovery. Generally we use STRIDE to help identify what type of threats to consider.
- Sprint Planning & Refinement -> Discuss threat stories during refinement.
- Prioritize critical threats using a qualitative risk management approach

### 🔧 Sample Attacker Story Template

    Title: SQL Injection in Login
    
    **As** a malicious user  
    **I want to** inject SQL code in the login form  
    **So that I can** bypass authentication and access restricted data
    
    **Related user story**: As a user, I want to log in with my email and password.
    
    **Acceptance criteria**:
    - Input validation is enforced
    - Prepared statements are used
    - Login failures are logged and rate-limited

You can find more user's stories [here](samples_mal_us.md)

## Sample OWASP 10 (2021) Malicious User Stories
![MUS](mm-us-owasp.png)

## Create a threat catalog
Follows an example of a catalog used to prioritize threats 

| **ID** | **Threat Title**                      | **Attacker Story**                                                                 | **STRIDE**                 | **Severity** | **Mitigations / Controls**                                                     | **Detection Methods**                                | **Owner / Champion**      | **Sprint Priority** |
|--------|----------------------------------------|-------------------------------------------------------------------------------------|----------------------------|--------------|----------------------------------------------------------------------------------|------------------------------------------------------|---------------------------|----------------------|
| T001   | SQL Injection                          | As an attacker, I want to inject SQL into a form so I can bypass login              | Tampering, EoP             | High         | Input validation, parameterized queries, WAF                                     | WAF alerts, query logs, SIEM                          | Security Champion Dev Team | High                 |
| T002   | Privilege Escalation                   | As an attacker, I want to escalate my role to admin through insecure API calls      | EoP, Spoofing              | High         | RBAC enforcement, privilege boundaries                                           | Audit logs, API gateway monitoring                    | Lead Developer             | High                 |
| T003   | Session Hijacking (XSS)                | As an attacker, I want to inject JS to steal cookies and impersonate users          | Tampering, Info Disclosure | High         | CSP, output encoding, HTTPOnly cookies                                           | CSP violation reports, user-agent anomaly detection   | Frontend Dev               | High                 |
| T004   | Insecure File Upload                   | As an attacker, I want to upload malicious scripts to execute server-side code      | Tampering, EoP             | Medium       | File validation, sandboxed upload directory, antivirus scanning                 | File scanning logs, app error reports                 | DevOps                     | Medium               |
| T005   | Brute Force Login                      | As an attacker, I want to try many passwords to break into accounts                 | Spoofing, DoS              | Medium       | Rate limiting, CAPTCHA, MFA                                                     | Auth logs, failed login alerts                        | Backend Dev                | Medium               |
| T006   | Outdated Dependencies (RCE)            | As an attacker, I want to exploit a known vuln in a 3rd-party library               | Tampering, EoP             | High         | SBOM, dependency scanning, patch management                                     | SCA tools (e.g., Snyk, Dependabot), build pipeline    | Security Team              | High                 |
| T007   | SSRF to Internal Admin Panel           | As an attacker, I want the server to make requests to an internal IP                | Spoofing, Info Disclosure  | High         | URL allow-listing, block internal metadata IP ranges                            | Outbound request monitoring, DNS logging              | Infra Team                 | High                 |
| T008   | Log Poisoning / WAF Bypass             | As an attacker, I want to obfuscate input to evade detection or logging             | Repudiation                | Medium       | Structured logging, encoding, input validation                                  | Log review automation, alerting on parsing failures   | AppSec                     | Medium               |
| T009   | Insecure Design (Missing Rate Limits)  | As an attacker, I want to overload the system by flooding it with requests          | DoS, Tampering             | Medium       | Functional security design, performance testing                                 | App metrics, rate limit metrics                       | Product Owner              | Medium               |
| T010   | Malicious CI/CD Artifact               | As an attacker, I want to inject malware via an automated build                     | Tampering                  | High         | Signed builds, artifact integrity checks, CI/CD isolation                       | CI audit logs, artifact hash verification             | DevOps Lead                | High                 |

## Cons to keep in mind using this framework

1. Requires Threat Knowledge.
Crafting meaningful abuser stories demands a solid understanding of threat modeling, attacker tactics (e.g., from MITRE ATT&CK), and the system architecture. Without that, the stories may be too generic or miss real threats.

1. Risk of Overwhelming the Backlog.
Abuser stories can multiply quickly. If not prioritized well, they may clutter the backlog, dilute focus, or paralyze teams with too many “what if” scenarios.

1. Definition of Done.
It can be tricky to set clear acceptance criteria for security stories. “Secure” is often a moving target, and validating proper mitigation may require more effort than for functional stories.

1. Potential for Team Pushback.
Dev teams unfamiliar with security practices might see abuser stories as a distraction from delivering features, especially under tight deadlines.

1. Security Work May Be Deferred.
In Agile, lower-priority stories are often postponed. If security stories compete with feature stories, they may not be addressed in time, creating risks.

1. Difficult to Automate.
Unlike functional tests, verifying security controls often requires manual testing or specialized tools. This reduces test coverage and slows feedback loops.

1. Lack of Standardization.
There’s no common format or best practice for writing abuser stories, which can lead to inconsistency between teams and sprints.

1. May Not Cover Non-Application Threats.
This approach focuses on application-level threats but may overlook infrastructure, supply chain, or human-factor risks unless expanded carefully.

### How to mitigate
Generally to adopt such framework requires a high level of maturity in the organization, at least in the DevOP team about security and Agile. I'd say a "security culture" is needed, but here come the question what is a security culture?
Greate resource is here: https://www.securityculturebook.com.
Then having a SDLC in place is also of a great help, I'd say is a pre-requirements.

## Other things to keep in mind regarding Agile threat modeling is difficult in capturing Non-User Interaction threats

1. Harder to Express as “Stories”
    Abuser stories typically follow a pattern like: “As an attacker, I want to [do something] so that I can [achieve a goal].”
    For M2M threats (e.g. insecure API access, SSRF, replay attacks), it’s harder to frame these in a relatable narrative unless your team is already security-savvy.

1. Often Overlooked in Backlog Grooming
    Agile teams tend to prioritize what’s visible to users. API authentication issues, improper token scopes, or race conditions in background jobs might be forgotten without deliberate modeling.

1. Security Ownership is Diffuse
    Developers writing backend APIs may assume someone else (e.g., DevOps or SecOps) will handle TLS, certificates, rate limiting, etc. Without user interaction, there's often no clear "owner" of the threat.

1. Harder to Simulate/Test Automatically
    Many non-interactive threats require complex testing setups (e.g., fuzzing APIs, simulating compromised internal services), which don't fit well in normal CI/CD pipelines.

1. Missing Contextual Threats (e.g. Supply Chain, Lateral Movement)
    Systems interacting over APIs may be vulnerable to chained attacks (like lateral movement via exposed internal endpoints) that don’t fit neatly into a per-feature threat story.

### How to Mitigate This Gap
- Include System-Level Abuser Stories: Create threat stories for components, not just user-facing features. For example: “As an attacker with access to internal services, I want to call an unauthenticated API to access user data.”
- Map to STRIDE or Kill Chain: Use a threat modeling methodology (e.g., STRIDE) to systematically uncover threats beyond the user layer.
- Add “Abuse Preconditions”: document assumptions in each threat story, e.g. “API assumes internal trust boundary,” to identify where M2M threats exist.
- Security Reviews for Integrations: Treat every API integration or background process as a potential threat surface, and run separate threat modeling sessions when needed.

## Conclusion
Here I presented a non-structured approach to threat modeling in an Agile context. Every organization should shape this framework based on their specific needs. I can say that the process to implement it could be challenge and that at the moment is really in a beta version for me as well, but for sure it's a great fun! I'd say that the gamification here it's the key point.

<b>Remember: the journey is the destination</b> :)

