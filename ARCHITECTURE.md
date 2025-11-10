# Architecture Overview

## Deutsch
- **GUI:** PySide6 (Qt)
- **Datenbank:** SQLite (AES-verschlüsselt)
- **Krypto:** AES-256-GCM, PBKDF2, SHA-512
- **Master-Passwort:** Ableitung per PBKDF2-HMAC-SHA256
- **Journal:** Jede Operation (Encrypt/Decrypt) wird verschlüsselt protokolliert

<br>

---

<br>

## English
- **GUI:** PySide6 (Qt)
- **Database:** SQLite (AES encrypted)
- **Crypto:** AES-256-GCM, PBKDF2, SHA-512
- **Master Password:** Derived via PBKDF2-HMAC-SHA256
- **Journal:** Each operation (Encrypt/Decrypt) is encrypted and logged
