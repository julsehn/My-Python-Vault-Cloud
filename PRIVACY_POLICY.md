# Privacy Policy - Password Manager Cloud

**Last Updated:** September 2026

## 1. Introduction

This Privacy Policy explains how the **Password Manager Cloud** service handles your data, focusing on the security and privacy of your encrypted vault.

## 2. What We Store

The official cloud service stores **only**:

### ✅ What IS Stored:
- **Encrypted vault blob** - Your passwords are encrypted with AES-256-GCM before upload
- **Salt** - Used for key derivation (Argon2id)
- **Nonce** - Used for authenticated encryption
- **User authentication data** - Username and SHA256 password hash (for login)

### 🔒 What is NEVER Stored:
- ❌ Your master password
- ❌ Any decrypted password
- ❌ Notes or personal data
- ❌ Session cookies or tokens
- ❌ Your devices or IP addresses

## 3. Encryption Details

### Client-Side Encryption
Your vault is encrypted **on your device** before being sent to our servers:

```
Plain Passwords → AES-256-GCM Encryption → Encrypted Vault Blob → Cloud Storage
```

### Key Derivation

- Algorithm: Argon2id
- Iterations: 3 passes (time_cost=3, memory_cost=64 MiB)
- Salt: Random 16-byte value per vault
- Key Length: 32 bytes (256-bit)

### Encryption Standard

- **AES-256-GCM**: Industry-standard authenticated encryption
- Provides confidentiality AND integrity
- Nonce is 12 bytes (96-bit)
- Associated Data: None (simpler, faster)

## 4. Server Access Control

### Who Can Access Your Data?

**ONLY YOU** can access your vault contents because:

1. The server only stores the **encrypted blob**
2. Decryption requires your **master password**
3. The server never has your master password
4. Server staff **cannot decrypt** your vault
5. Your data is encrypted **at rest** in the database

### Authentication Required
All API endpoints require JWT authentication:

- `/v1/vaults` - Upload/Download vault
- `/v1/auth/*` - Register/Login
- Each user has their own isolated vault

## 5. What Happens on Your Device

### When Uploading:

1. You enter your master password
2. Client derives encryption key from password + salt
3. Vault is encrypted client-side
4. Encrypted blob is sent to cloud
5. **Your device never holds the key and ciphertext together**

### When Downloading:

1. Client downloads encrypted blob
2. You enter master password
3. Client derives key
4. **Client decrypts** locally
5. **Password Manager Cloud never sees decrypted data**

## 6. Data Isolation

Each user's vault is completely isolated:

- Database rows are keyed by `user_id` and `vault_id`
- Token-based authentication ensures only authorized access
- User A cannot access User B's data even if they compromise the server

## 7. What We Don't Do

- ❌ We don't scan your vault contents
- ❌ We don't log vault data
- ❌ We don't access decrypted passwords
- ❌ We don't track user behavior
- ❌ We don't sell data
- ❌ We don't share with third parties

## 8. Security Measures

### On Our End:

- SQLite database with token-based access control
- HTTPS-only communication
- CORS protection for web clients
- Server-side version control prevents conflicts

### On Your End:
- Master password required for all operations
- Local vault file protected by encryption
- Session timeout auto-locks (configurable)

## 9. Your Rights

You own your data completely:

- **Delete vault:** Remove from cloud instantly
- **Export:** Download encrypted blob anytime
- **Backup:** Your encrypted file is portable
- **Forget us:** Delete cloud vault, keep local copy

## 10. Technical Transparency

### Encryption Flow Diagram:

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   YOUR DEVICE   │      │  PASSWORD CLOUD │      │  YOUR DEVICE   │
├─────────────────┤      ├─────────────────┤      ├─────────────────┤
│ 1. Enter vault  │      │                 │      │ 2. Enter vault  │
│    password     │      │                 │      │    password     │
└────────┬────────┘      │                 │      │   (via client)  │
         │               │                 │      │                  │
         │ 3. Derive key │                 │      │ 6. Decrypt blob  │
         │   (Argon2id)  │                 │      │                  │
         │──────────────►│                 │      │                  │
         │               │  4. Encrypt blob │      │                  │
         │               │    (AES-256)     │      │ 7. View passwords│
         │               │────────────────►│      │                  │
         │               │ 5. Store encrypted│     │                  │
         │               │    vault blob    │      │                  │
         │◄──────────────│─────────────────│      │                  │
         │    JWT Auth   │                 │      │                  │
         │◄──────────────│                 │      │                  │
         │ 6. Decrypt    │                 │      │                  │
```

### Why This is Secure:

- **Zero-Knowledge Architecture:** Server cannot decrypt your data
- **End-to-End Encryption:** Encryption happens on client only
- **Cryptographic Standards:** AES-256-GCM with Argon2id key derivation
- **Authentication Required:** JWT tokens prevent unauthorized access

## 11. Legal Disclaimer

**We cannot help you recover your password** if you forget it. We never store your master password - only your encrypted vault.

**Technical Limitations:**
- If you forget your master password, we cannot decrypt your vault
- The salt allows proper key derivation but no backdoor exists
- Your encrypted vault blob is cryptographically secure

## 12. Updates to This Policy

This policy may be updated periodically. We recommend reviewing it regularly.

---

## Summary

| Aspect | Status |
|--------|--------|
| Can we see your passwords? | ❌ **NO** - Encrypted with AES-256-GCM |
| Can we see your master password? | ❌ **NO** - Never transmitted or stored |
| Can we access vault contents? | ❌ **NO** - Server cannot decrypt |
| Who can decrypt your vault? | ✅ **Only YOU** - With your master password |
| Is encryption reversible? | ✅ **Yes** - If you know your password |
| Can staff access your data? | ❌ **NO** - Technically impossible |

**Your passwords are yours alone. We're just the storage space - you hold the key.**
