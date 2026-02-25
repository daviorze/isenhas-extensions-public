# iSenhas Browser Extension (Public)

iSenhas is a privacy-focused password manager designed with security, transparency, and user control as core principles.

This repository contains the **public client implementation** of the iSenhas browser extension.

## 🔐 Security

Security and transparency are core principles of iSenhas.

This repository contains the public client-side code of the browser extensions, allowing independent review and community auditing.

### Security Documentation

- 📄 [Security Policy](SECURITY.md)
- 🛡️ [Threat Model](THREAT_MODEL.md)

### Security Features

- Client-side encryption
- AES-256 encryption
- PBKDF2 key derivation
- Optional Zero-Knowledge architecture
- No transmission of master passwords
- Minimal browser permissions
- Defense-in-depth design

We welcome responsible security research and community feedback.

## 🔐 Security First

iSenhas is built around a security-centric architecture:

- Client-side encryption
- Optional Zero-Knowledge mode
- Local cryptographic operations
- No plaintext secrets transmitted to the server in Zero-Knowledge mode

All sensitive encryption processes happen locally on the user’s device.

---

## 🌐 Repository Scope

This public repository exists to provide **transparency and auditability**.

Included in this repository:

- Browser extension client
- User interface
- Local storage logic
- Cryptographic workflow (client-side)
- Security model implementation

Not included:

- Proprietary automation modules
- Internal heuristics and optimization systems
- Backend infrastructure and operational services

Some components of iSenhas are maintained in private repositories.

---

## 🧠 Security Model

iSenhas supports different operational modes:

### Extreme privacy Mode (Recommended)
- Zero-Knowledge encryption
- Encryption occurs locally
- Master password never leaves the device
- Server stores only encrypted data
- Server cannot access user secrets

### Cloud Convenience Mode
- Enables additional usability features
- May involve server-side processing depending on configuration
- Designed for users prioritizing convenience over extreme privacy

Users can choose the model that best fits their needs.

---

## 🔍 Transparency Commitment

The goal of this repository is to allow:

- Independent security review
- Community auditing
- Architectural transparency
- Trust verification

Security is based on verifiable design, not obscurity.

---

## ⚠️ Important Notice

This repository represents the **public client components** of iSenhas.

The official iSenhas service includes additional proprietary modules that are not part of this repository.

---

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.

See the LICENSE file for details.

---

## 🤝 Contributing

Contributions, issues, and security feedback are welcome.

If you discover a security vulnerability, please report it responsibly instead of opening a public issue.

---

## 🚀 Project Goals

- Privacy by default
- User data ownership
- Transparent security architecture
- Modern password management without hidden data access

---

## 📬 Contact

For questions, suggestions, or responsible disclosure, please open an issue or contact the project maintainers.

---

**iSenhas — Security without compromise.**
