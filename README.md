# Simple framework to integrate threat modeling into Agile
AKA a ethnographic approach to security development
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
