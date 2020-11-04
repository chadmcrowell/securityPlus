# Security+ Exam

## The Goal of Security

CIA:

- Confidentiality
- Integrity
- Availability

Additional:

- Auditing
- Accountability
- Non-repudiation

## Risk

- Threats exploit vulnerabilities to harm assets
- Assets can have vulnerabilities
- Use SP 800-30 as a part of risk assessment

## Threats

- Threat agent
- Threat Actor
  - TA can be internal or external
  - depends on the intent
  - do they have open source intelligence?
- Script Kiddies
- Hacktivists
- Organized Crime
- Nation States
- Advanced Persistent Threat (APT)
- Insiders: anyone with access to the assets (customers and employees)

##  Risk Assessment

- Vulnerability Assessment
  - Pen Testing
- Threat Assessment
  - Adversarial
  - Accidental
  - Structureal
  - Environmental
- Risk Response
  - Mitigation
  - Transferrence (using a cloud service instead)
  - Risk Acceptance (fixing could be too expensive)
  - Avoidance

## Risk Management

- Framework: Process for risk mgmt
  - NIST Risk Management Framework Special Publication 800-37
    - [link](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final)
  - ISACA Risk IT Framework
    - [link](https://www.isaca.org/why-isaca/about-us/newsroom/press-releases/2020/isacas-risk-it-framework-offers-a-structured-methodology)
- Benchmark
- Secure Configuration Guides
  - Platform
  - Web Server
  - Operating System
  - Network Infra Device
  - General Purpose Guides (general server security)
- Security Control: how do you secure it?
  - Administrative/mgmt Control
  - Technical Control
  - Physical Control
  - Security Control
    - Deterrant
    - Preventative
    - Detective
    - Corrective
    - Compensation
- Security Control Examples: Manadtory Vacation, Job Rotation, Multi-Person Control, Separation of duties, Principal of least priviledge

## Governance

- Governance: how to conduct IT security
- PCI-DSS
- Laws & Regulations
- Standards
- Best Practices
- Common Sense
- Acceptable Use Policy
- Organizational Standard
- Security Controls are in Place
- Procedure

---
**Security Controls**  

- Policies & Standards
  - Laws & Regulations
  - Common Sense
  - Best Practice

**Procedures**

---

### Security Policies

- Acceptable Use Policy: what you can and can't do on computer and internet
- Data Sensitvity & Classification
- Access Control Policy: what do you have access to?
- Password Policy
- Care & Use of Equipment (abuse prevention)
- Privacy Policy (customer and in house)
- Personnel Policy

### Frameworks

- Regulatory or non-regulatory
- International standards
- [NIST SP800-37](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final)
- ISACA IT Infrastructure
- ISO 27000

**NIST Risk Management Framework**

- Categorize
  - Organize workflows and processes
- Select
  - Ideas for implementing best practices and controls
- Implement
  - Take the ideas and apply them
- Assess
  - Testing and calculating the impact
- Authorize
  - Sign-off
- Monitor
  - Watch and observe good/bad

### Quantitative Risk Calculations

- Asset value (cost to install/maintain and item itself)
- Exposure Factor (% of an asset that's lost as a result of an incident)
  - if datacenter floods with partial damage to equipment, `exposure factor = .75`
  - if all assets are damaged from flood, `exposure factor = 1`
- Single Loss Expentency (Asset value times exposure factor)
  - if router=`$5000`, and `exposure factor=1`, then `SLE=5000`
- ARO (Annualized Rate of Occurence)
  - if chance of flooding = 20 (flood 1 every 20 years), then ARO=.05 (1/20)
- Annualized Loss Expectancy (ALE)
  - SLE times ARO ($250)
- Mean Time to Repair (MTTR)
  - the time between when an asset fails (e.g. router) and when it is repaired
- Mean time to Failure (MTTF)
  - the time between when an asset is working, to when it fails
- Mean time between failure (MTBF)
  - the time between when an asset first fails, to when it's repaired then fails again

### Business Impact Analysis

- What's the impact on your business if failure occurs (e.g. lose internet)
- Determine Mission Processes (determine what's mission critical)
- Identify Critical Systems (servers and other important assets)
- Single Point-of-failure (one item that, if fails, causes catestrophic failure)
- Identify resource requirements (what do I need to get mission critical stuff up and running)
- Identify recovery priorities (if everything goes down, what steps do I need to follow to get back up)

**IMPACT**

- Property
- People (Safety & Life)
- Finance (Credit, cash flow, accounts receivable)
- Reputation

**Privacy Impact Assessment**

- Determine the impact of our privacy getting out

**Privacy Threshold Assessment**

- What types of privacy info is out there

**Recovery Time Objective (RTO)**

- Minimum time to restore critical systems
- How long can this thing be down before we're in trouble

**Recovery Point Objective (RPO)**

- Maximum amount of data can be lost (in days)

### Organizing Data

- Data Sensitivity/Labeling
  - Public (no restrictions)
  - Confidential (limited access to you only)
    - Private (private to yourself)
  - Personally Identifiable Information (PII)
    - Proprietory (ketchup recipe)
    - Private Health Information (PHI)
  - Health Insurance Portability and Accountability (HIPPA)
- Data Roles
  - Owner (who's reposible for data)
  - Steward/Custodian (maintain the integrity of data)
  - Privacy Officer (who adheres to data privacy and procedures)
- Data Users
  - Standard Users: assigned just enough to perform the task
  - Privileged Users: increased access and control
  - Executive Users: sets policies and incident reponse actions
  - System Admin: sets permissions for others
  - Data/System Owner: all legal responsibility

### Security Training

- Onboarding
  - Background check
  - Non-disclosure agreement
  - Standard operating procedure
  - rules of behavior
  - Specialized issues
  - general procedure policy
- Offboarding
  - disable account
  - return credentials
  - exit interview
  - knowledge transfer
- Personally Identifiable Information (PII)
  - NIST Guide to protecting PII
    - Information Needed:
      - Full name
      - home address
      - email address
      - national identification number
      - passport number
      - vehicle registration plate number
      - driver's license number
      - face, fingerprints, or handwriting
      - credit card numbers
      - digital identity
      - date of birth
- Personnel Management Control
  - Mandatory vacations
  - Job Rotation
  - Separation of duties
- Role-based Data Controls
  - System Owner
  - System Administrator
  - Data Owner
  - User
  - Privileged User
  - Executive User

### Third Party Agreements

- Business Partners Agreement (BPA)
  - Primary Entities
  - Time Frame
  - Financial issues
  - Management
- Service Level Agreement (SLA)
  - Service to be provided
  - Minimum up-time
  - Response Time (contacts)
  - Start and end date
- Interconnection Security Agreement (ISA)
  - Ex. NIST 800-47
  - Statement of requirements
  - System security considerations
  - Topological drawing
  - Signature authority
- Memorandum of Understanding/Agreement (MOA)
  - Purpose of interconnection
  - Relevant authorities
  - Specify the responsibilities
  - Define the terms of agreement
  - Terminating/reauthorizing

## Cryptography

**Obfuscation:** Take something (like a word) that's scrambled so it doesn't make sense (confusion or diffusion)

- Caesar cipher
- Vigenere cipher

### Cryptograhic Methods

- Symmetric Encryption
- Asymmetric Encryption
  - used to send a secure session key
  - public key only used to encrypt
  - private key only used to decrypt
- Session Key (symmetric key)
- Ephemeral Key
  - Temporary 
  - Provides perfect forward secrecy (if cracked today, tomorrow it wouldn't work)
- In-band
- Out-of-band

### Symmetric Cryptosystems

- Symmetric key algorithm
- Symmetric block encryption
  - Data Encryption Standard (DES)
  - Feistel Function
  - DES is a short key
  - Blowfish
  - 3DES
- Blowfish
  - 64 bit block size
  - 16 rounds
  - Key size: 32-448 bits
- 3DES
  - Block cipher
  - 64-bit Block size
  - 16 rounds
  - Key size: 56 bit`x`3
- Advanced Encryption Standard (AES)
  - Block cipher
  - 128-bit block size
  - Key size: 128, 192, or 256 bits
  - Rounds: 10, 12, or 14
- RC4 Streaming Cipher
  - Streaming cipher
  - 1 bit at a time
  - 1 round
  - Key Size: 40-2048 bits

### Symetric Block Modes

- Electronic Code Book (ECB) - nobody uses this anymore
- Block modes
  - Cipher block chaining (CBC)
  - Cipher feedback (CFB)
  - Output feedback
  - Counter (CTR)

### RSA Cryptosystems

- Asymmetric Encryption
- Public/Private Key
- RSA
  - Asymmetric (key pair)
  - at least 2048 bit key
- ECC (Elliptic Curve Cryptography)
  - Elliptic curve formula
  - generate key pair fast
  - Smaller key

### Diffie-Hellman

- Key Exchange Protocol
- Modular arithmetic
- Diffie-hellman groups
- elliptic curve diffie-hellmen
- can have very large keys

### PGP/GPG

- Random key by encryptor
- encrypt data using that random key
- encrypt the key using the receivers public key
- decrypt by using the private key to get the random key
- use the random key to decrypt the data
- PGP certificate
- Web of trust: certificates trust other certificates
- OpenPGP
  - PKI support
  - S/MIME
- Symantec
  - Bitlocker
  - Filevault
  - Enterprise soluton
- ProtonMail (PGP built-in)
- GPG: GNU Privacy Guard (does file and disk encryption)

### Hashing

- add integrity to data
- Hashes are one-way
- will always be the same size
- Deterministic
- Hash Types
  - MD5: 128-bit hash
  - SHA-1: 160-bit hash
  - SHA-256
  - SHA-512
  - RIPEMD: 128, 160, 256, 320 bit digests
- used for password storage

### HMAC

- freeformatter.com
- message integrity
- requires each side to have the same key
- based on the standard hashes (MD5, SHA-1, etc.)

### Steganography

- hiding data within other data