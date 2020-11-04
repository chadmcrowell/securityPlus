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

## Risk Management

- Threats exploit vulnerabilities to harm assets
- Assets can have vulnerabilities
- Use SP 800-30 as a part of risk assessment

### Threats

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

###  Risk Assessment

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

### Risk Management

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

### Governance

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
- Low overhead: two parties need the same session key
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

### Certificates and Trust

- public key with hash and encryption of web page (digital signature)
- digital signature can be spoofed (so, bring in a 3rd party for another signature)
- digital certificate (inside certificate is public key, my signature and 3rd party signature)
- unsigned certificates
- web of trust
  - a lot of people who trust each other
  - requires a lot of maintenance
- public key infrastructure (PKI)
  - top of heiracrchy is the certificate authority
  - intermediate CA
  - root servers

### Public Key Infrastructure (PKI)

- Certificate authority (verisign)
- Root certificate system
  - designated intermediary
  - certificate authorities
- PKCS
  - standard for PKI system
  - with or without private certificate
  - cryptographic message syntax standard: PKCS #7 (.P7B) without private certificate
  - personal information exchange - PKCS #12 (.PFX) with private key
  - **PKCS-7** is a way to store certificates as individiual files
  - **PKCS-12** stores the certificates and the private keys as a package
- CRL Distribution Points
  - Certificate relocation list
  - takes a long time to respond to bad certificate
- Online certificate status protocol (OCSP)
  - real time check for certificate validation
  - Replaces CRL
- X.509
  - how to access database
  - OU, O, C
- Certification Path
  - root certificate, then under it is intermediate certificate (may be many)

### Cryptographic Attacks

- generate a hash and compare
- FreeSSH
- brute force attack: comparing hashes to find a match
- must have long passwords to prevent brute force attacks
- Dictionary attack: start with a word (feeding in a dictionary) and trying capitals, numbers, etc.
- Rainbow-table attack
- Salt: arbitrary value added to the end of password
- Key stretching: attaches other values to your password
  - bcrypt
  - PBKDF2

## Identity and Access Management

- Identifcation
- Authorization
- Authentication

### Identification

- Something you know
  - CAPTCHA
  - password
  - PIN
  - Security questions
- Something you have
  - Smart card
  - RSA key/token
- Something about you
  - finger print (inheritence factor)
  - facial recognition
- Something you do
  - rhythm of your typing
- Somewhere you are
  - entering zip code for gas
- Federated trust
  - windows active directory
  - Don't need username and password
- Multi-factor authentication

### Authorization Concepts

- Permissions
  - What can you do
  - admin assigns permissions
- Rights/Priviledges
  - assign to systems as a whole
- Least priviledge
- Separation of duties

### Access Control List

- Authorization Models
  - Mandatory Access Control (based on data labels)
  - Discretionary Access Control
  - Roles
- Role-based access control
- Implicit deny

### Password Security

- security policy
  - complexity
  - expiration
  - history
- Example: Windows local security policy
- security policy for AD: Group Policy Objects

### Linux File Permissions

- Owner, Group, Everyone (other)
- read, write, execute
- execute for a directory means you can change into it and make it your home
- chmod (4=r, w=2, x=1)
- chown (user, group)
- passwd

### Windows File Permissions

- NTFS permissions
  - Full control
  - modify
  - read/execute
  - list folders contents
  - read
  - write
- Inheritance
- Deny is stronger than allow
- Copying from NTFS drive to different NTFS drive
  - loses NTFS permissions
- Copying from NTFS drive to another folder on same drive
  - keeps NTFS permissions

### User Account Management

- Continuous Access Monitoring
  - track logging in/off
  - track file access
- Shared accounts = bad
- Multiple accounts
  - diff usernames/passwords
  - diff groups
  - use least priviledge
  - log activity
- Default accounts
  - use dedicated service accounts


### AAA

- Authentication, authorization, accounting
- RADIUS
  - dial-in networking
  - RADIUS server
  - RADIUS client
  - RADIUS supplicant (system trying to authenticate)
  - used in wireless auth
  - uses up to 4 different ports (1812, 1813, 1645, 1646)
- TACACS+
  - managing devices
  - takes care of authorization also
  - decouples authorization and authentication
  - uses **TCP port 49**
- both RADIUS and TACACS is used for auditing

### Authentication Methods

- Password Authentication Protocol (PAP)
  - send in the clear
- Challenge-handshake Authentication Protocol (CHAP)
  - server and client have key
  - challenge message
  - creates hash and challenge message over to client
- NT LAN Manager v2
  - Two windows systems logging into eachother
  - challenge messages on each side
  - message hashed
- Kerberos
  - auth to Windows domain controllers
  - Key distribution center (KDC)
  - authentication service provides ticket granting ticket (TGT)
  - TGT also called SID
  - TGT knows what I'm authorized to do and generates a session key (new session key created each time accessing something)
- Security Assertion Markup Language (SAML)
  - used to login to web apps
- Lightweight Directory Access Protocol (LDAP)
  - allows one computer to access another computers directory
  - uses TCP/UDP 389

### Single Sign-On

- LAN uses Windows Active Directory
  - federated systems (trust)
  - admin authorizes users
- SAML
  - logs into a bunch of devices using identity provider
  - service provider
- SSO Circle

## Tools of the Trade

### OS Utilities

- ping -4
- ping -t
- netstat -n
  - Active connections
- netstat -a
  - Listening on ports
- tracert
- arp
- ipconfig
- nslookup
  - `server 8.8.8.8`
- dig
  - query certain records
  - `dig mx google.com`
- netcat
  - open and listen on ports
  - `sudo netcat -l 231`
  - open a port as a client
  - banner grabbing
  - tool for agressive reconnaissance

### Network Scanners

- Nmap
  - `nmap -v -sn 192.168.4.0/24`
  - `nmap -v -A scanme.nmap.org`
- Zenmap
  - GUI for Nmap
- advanced port scanner
- looking for open ports, protocols hardware, and rogue systems
- wiresharek SB network inventory

### Protocol Analyzers

- sniffer (PCAP)
- protocol analyzer (wireshark)
- tcpdump
- broadcast storm

### SNMP

- Simple Network Management Protocol (SNMP)
- Agent (UDP 161/TLS 10161)
- SNMP manager (Network management station)
- Network management station (NMS)
- Management information base (MIB)
- query you're printers MIB
- send a GET
- setup a trap on the device (SNMP trap)
- Walk: SNMPWalk
- version: 1, 2, 3
- SNMP v3 uses TLS encryption
- `snmp server community totalhome RO`
- An SNMP Community is an organization of managed devices (e.g. totalhome)
- Cacti 
- Types of NMS: Nagios, Zaabbix and Spiceworks

### Logs

- 