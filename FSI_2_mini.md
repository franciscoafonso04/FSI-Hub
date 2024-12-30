# Complete and Detailed Study Guide for the Exam: Fundamentals of Security

## **1. Cryptography Fundamentals**

### **1.1 Key Concepts**

- **Encryption**: The process of converting plaintext into ciphertext using a cryptographic key.

  - **Symmetric Encryption**: Uses the same key for both encryption and decryption.
    - Example: AES (Advanced Encryption Standard), DES (Data Encryption Standard).
    - Challenges: Secure key distribution.
  - **Asymmetric Encryption**: Uses a public key for encryption and a private key for decryption.
    - Example: RSA, ECC (Elliptic Curve Cryptography).
    - Benefits: Solves key distribution problem but is computationally expensive.

- **Hash Functions**: Transform input data into a fixed-size string (hash) that is unique to the input.

  - **Properties**:
    - Deterministic: Same input always produces the same hash.
    - Collision-resistant: It is computationally infeasible to find two different inputs with the same hash.
    - Non-reversible: Hashes cannot be converted back to the original input.
  - **Examples**: SHA-256, SHA-3, MD5 (deprecated due to vulnerabilities).
  - **Keyed Hash Functions**:
    - Add a secret key to the hashing process for integrity verification (e.g., HMAC).

### **1.2 Security Principles**

- **Kerckhoffs's Principle**: The security of a cryptographic system should depend only on the secrecy of the key, not the algorithm itself.
- **Avoid DIY Cryptography**:
  - Developing cryptographic algorithms without expert knowledge can lead to vulnerabilities.
  - Example vulnerabilities: Weak random number generators, timing attacks, padding oracle attacks.

### **1.3 Classical Ciphers**

- **Substitution Cipher**:
  - Each letter or symbol in the plaintext is replaced with another.
  - Weakness: Preserves frequency patterns, making it vulnerable to frequency analysis.
- **Caesar Cipher**:
  - Shifts characters by a fixed number of positions.
  - Easily broken through brute force or frequency analysis.
- **Rotor Machines**:
  - Mechanized substitution using rotating disks.
  - Example: Enigma machine, broken during WWII due to predictable key settings.

### **1.4 Modern Encryption**

- **AES**:
  - A symmetric block cipher standardized by NIST.
  - Operates on 128-bit blocks with key sizes of 128, 192, or 256 bits.
  - Consists of multiple rounds of substitution, permutation, mixing, and key addition.
- **Modes of Operation**:
  - **ECB** (Electronic Codebook): Encrypts blocks independently but reveals patterns in data.
  - **CBC** (Cipher Block Chaining): Uses an Initialization Vector (IV) and chains blocks for better security.
  - **CTR** (Counter Mode): Converts a block cipher into a stream cipher by encrypting counters.

### **1.5 One-Time Pad**

- XORs the plaintext with a random key of the same length.
  - Perfect security if the key is random, secret, and used only once.
  - Limitations: Impractical due to the need for large, secure keys.

---

## **2. Message Authentication and Integrity**

### **2.1 Message Authentication Codes (MACs)**

- Provide integrity and authenticity of messages.
  - **HMAC** (Hash-based MAC): Combines a cryptographic hash function with a secret key.
    - Example: HMAC-SHA256.
  - **CMAC** (Cipher-based MAC): Uses block ciphers like AES to compute MACs.

### **2.2 Hash Functions**

- **Collision Resistance**: Essential to prevent two different inputs from producing the same hash.
- **Avalanche Effect**: A small change in input results in a significantly different hash output.
- Examples of usage: Password hashing, digital signatures, data integrity.

### **2.3 Authenticated Encryption (AE)**

- Combines confidentiality (encryption) with integrity (MAC).
  - **Encrypt-then-MAC**: Encrypt the plaintext and then compute the MAC over the ciphertext (preferred).
  - Algorithms: AES-GCM (Galois Counter Mode), ChaCha20-Poly1305.

---

## **3. Public Key Cryptography**

### **3.1 Key Management**

- **Symmetric Key Management**:
  - Challenges: Securely distributing keys among participants.
- **Asymmetric Key Management**:
  - Public keys can be shared openly, solving the distribution problem.
  - Long-term keys are used for identity, while session keys are used for encryption during communication.

### **3.2 Public Key Operations**

- **Encryption**:
  - Sender encrypts with the recipient's public key.
  - Recipient decrypts using their private key.
- **Digital Signatures**:
  - Sender signs with their private key.
  - Recipient verifies the signature using the sender's public key.
  - Provides authenticity, integrity, and non-repudiation.

### **3.3 Diffie-Hellman (DH)**

- Key exchange protocol to derive a shared secret without transmitting the secret directly.
  - Vulnerable to Man-in-the-Middle (MitM) attacks without authentication.

### **3.4 Post-Quantum Cryptography (PQC)**

- **Threats**:
  - Quantum computers can break RSA and ECC using Shor's Algorithm.
  - Grover's Algorithm halves the security of symmetric encryption.
- **NIST Standards**:
  - Lattice-based cryptography, hash-based cryptography.
  - Transition strategies involve hybrid models combining classical and quantum-safe algorithms.

---

## **4. Public Key Infrastructure (PKI)**

### **4.1 Certificates and Validation**

- **X.509 Certificates**:
  - Bind public keys to identities.
  - Fields include Subject, Issuer, Public Key, Validity Period.
- **Certificate Authorities (CAs)**:
  - Issue and sign certificates.
  - Root CAs establish trust for the entire PKI hierarchy.

### **4.2 Certificate Revocation**

- **CRL (Certificate Revocation List)**: Lists certificates no longer trusted.
- **OCSP (Online Certificate Status Protocol)**: Provides real-time validation of certificates.

---

## **5. Network Security Protocols**

### **5.1 Transport Layer Security (TLS)**

- Operates at the **application layer** to ensure secure communication on the web (e.g., HTTPS).
  - **Handshake Protocol**: Authenticates participants and negotiates cryptographic parameters.
  - **Record Protocol**: Encrypts and ensures the integrity of transmitted data.
  - TLS 1.3 improvements:
    - Simplified handshake.
    - Removal of outdated algorithms.

### **5.2 Secure Shell (SSH)**

- Provides secure remote login and data transfer.
  - **Protocols**:
    1. Transport Layer: Secures communication.
    2. User Authentication: Verifies client identity (e.g., public key, password).
    3. Connection Protocol: Allows multiple channels over a secure tunnel.

### **5.3 Internet Protocol Security (IPSec)**

- Operates at the **network layer** to secure IP traffic.
  - **Modes**:
    - Transport: Protects only the payload.
    - Tunnel: Protects the entire packet.
  - **Components**:
    - Authentication Header (AH): Provides integrity and authentication.
    - Encapsulating Security Payload (ESP): Adds encryption for confidentiality.

---

## **6. Common Attacks and Countermeasures**

### **6.1 Man-in-the-Middle (MitM)**

- Intercepting and altering communication between two parties.
  - Countermeasure: Use authenticated key exchange and PKI.

### **6.2 Denial of Service (DoS)**

- Overloading a service to prevent legitimate access.
  - Countermeasure: Rate limiting, traffic filtering.

### **6.3 Phishing**

- Tricking users into revealing sensitive information.
  - Countermeasure: Awareness training, email filtering, two-factor authentication.

### **6.4 SYN Flooding**

- Exhausting server resources by sending numerous TCP SYN requests.
  - Countermeasure: SYN cookies, firewalls.

---

## **7. Intrusion Detection Systems (IDS)**

### **7.1 Types**

- **Host-based IDS (HIDS)**: Monitors activity on a specific host.
- **Network-based IDS (NIDS)**: Monitors network traffic for suspicious patterns.

### **7.2 Techniques**

- Signature-based: Detects known attack patterns.
- Anomaly-based: Detects deviations from normal behavior using machine learning.



