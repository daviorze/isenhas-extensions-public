# iSenhas Threat Model

This document describes the security assumptions, threat model, and protections implemented in the iSenhas browser extensions.

---

## Security Goals

The primary goals of iSenhas are:

- Protect user credentials against unauthorized access
- Ensure encrypted storage and transmission
- Prevent exposure of master passwords
- Minimize trust requirements in external infrastructure

---

## Assets to Protect

Sensitive assets include:

- Stored credentials
- Encryption keys
- Recovery keys
- Session tokens
- Autofill data

---

## Trust Assumptions

iSenhas assumes:

- The user device operating system is not fully compromised
- The browser enforces extension sandboxing
- HTTPS connections are correctly validated
- Cryptographic primitives provided by Web Crypto API are secure

---

## Threat Actors

Potential attackers include:

### Remote attackers
- Attempt interception of network traffic
- Try to exploit extension permissions
- Inject malicious scripts into webpages

### Malicious websites
- Attempt to access autofill data
- Manipulate DOM to capture credentials

### Supply chain attackers
- Compromise third-party dependencies
- Inject malicious updates

### Insider threats
- Attempt access to user data through backend systems

---

## Mitigations

iSenhas implements:

- AES-256 encryption
- Optional zero-knowledge architecture
- PBKDF2 key derivation
- Secure message passing between extension components
- No transmission of master passwords

---

## Out of Scope

The following are outside the protection scope:

- Fully compromised operating systems
- Malware running with user privileges
- Physical access attacks without device protection

---

## Security Philosophy

Security in iSenhas follows a defense-in-depth strategy:

- Encrypt early
- Trust minimally
- Reduce attack surface
- Assume breach scenarios

---

## Continuous Improvement

The threat model is a living document and will evolve alongside the project.