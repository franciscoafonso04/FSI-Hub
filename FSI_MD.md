# Informatics Security Fundamentals

## **Symmetric Encryption**

### **1. Introduction to Cryptography and Security**

#### **Cryptography and Guarantees**
- **Encryption**: The process of transforming readable data (plaintext) into unreadable data (ciphertext) using a secret key.
- **Primary Objective**: Ensure **confidentiality** of the information.
- **Additional Guarantees**:
  - **Authenticity**: Verifies the sender's identity.
  - **Non-repudiation**: Prevents denial of having sent a message.
  - **Unpredictability and anonymity**: Relevant in complex systems.

#### **Types of Encryption**
1. **Symmetric**:
   - The same key is used for encryption and decryption.
   - Example: AES.
2. **Asymmetric**:
   - Uses a pair of keys (private and public).
   - Example: RSA.
3. **Specialized Encryption**:
   - Homomorphic, authenticated, or tailored to specific needs.

---

### **2. Fundamentals of Encryption**

#### **Definitions and Notation**
- **Encryption**: \( c \gets E(k, p) \)
  - Usually a **randomized** process for better security.
- **Decryption**: \( p \gets D(k, c) \)
  - Always **deterministic**.

#### **Security Models**
- **Confidentiality**: Ensures private data cannot be deduced from the ciphertext.
- **Common Issues**:
  - Patterns in plaintext can leak information if visible in ciphertext.

---

### **3. Classical Ciphers**

#### **Caesar Cipher**
- **How it works**:
  - Each letter in the plaintext is shifted by a fixed number.
  - Example: "banana" with \( k = 3 \) → "edqdqd".
- **Limitations**:
  - Small key space.
  - Easily broken by brute force.

#### **Substitution Ciphers**
- Replace each letter with another, based on a fixed permutation.
  - Example: `a → f`, `b → a`.
- **Key space size**:
  - \( 26! \) permutations (~\( 2^{88} \)).
- **Frequency Analysis Attacks**:
  - Exploit common letter frequencies in a given language.
  - Example in Portuguese:
    - `a` (14.63%) is very frequent.
    - `z` (0.47%) is rare.

---

### **4. The One-Time Pad (OTP)**

#### **How It Works**
- XOR each bit of the plaintext (`m`) with a truly random key (`k`) of the same length:
  - Encryption: \( c = m \oplus k \).
  - Decryption: \( m = c \oplus k \).

#### **Properties**
- **Perfect Security**:
  - Unbreakable if the key is random, kept secret, and used only once.
- **Drawbacks**:
  - The key must be as long as the message.
  - Impractical for large-scale use due to key storage and distribution challenges.

---

### **5. Kerckhoffs's Principle**

#### **Definition**
- The security of a cryptographic system should depend only on the secrecy of the **key**, not the algorithm.
- **Advantages of Open Designs**:
  - Facilitates security audits.
  - Algorithms like AES were rigorously tested before being standardized.

---

### **6. Modern Ciphers**

#### **Definition**
- Operate on **fixed-size blocks** of data.
  - Example: 128-bit blocks in AES.
- Consist of two main operations:
  1. **Encryption**: \( c = E(k, p) \).
  2. **Decryption**: \( p = D(k, c) \).

#### **AES (Advanced Encryption Standard)**
- **History**:
  - Standardized in 2000 to replace DES.
  - Developed through a public competition led by NIST.
- **Features**:
  - Block size: 128 bits.
  - Key sizes: 128, 192, or 256 bits.
  - Core operations: SubBytes, ShiftRows, MixColumns, AddRoundKey.

#### **Modes of Operation**
1. **ECB (Electronic Codebook Mode)**:
   - Encrypts each block independently.
   - **Insecure**: Patterns in ciphertext reveal patterns in plaintext.
2. **CBC (Cipher Block Chaining)**:
   - Each block depends on the previous one, using an Initialization Vector (IV).
   - Requires **padding** for non-multiple block sizes.
3. **CTR (Counter Mode)**:
   - Uses a counter to generate a keystream.
   - **Advantages**:
     - Parallelizable.
     - Efficient for read/write operations.

---

### **7. Keys and Randomness**

#### **Key Generation**
- **Symmetric Keys**:
  - Randomly generated or derived using a Key Derivation Function (KDF).
- **Asymmetric Keys**:
  - Generated as key pairs (private and public).
  - Typical sizes:
    - RSA: ~4096 bits for 128-bit security.
    - ECC: ~400 bits for equivalent security.

#### **Key Storage**
- Secure storage in hardware devices:
  - HSMs (Hardware Security Modules).
  - Smartcards.
- **Long-term Key Protection**:
  - Key wrapping techniques encrypt keys for storage.

---

### **8. Randomness and Security**

#### **Importance**
- Randomness is crucial for generating secure cryptographic keys.
- **Randomness is not about the values themselves but the process used to generate them.**

#### **Sources of Randomness**
- Linux Systems:
  - `/dev/urandom`: Non-blocking, sufficient for most applications.
  - `/dev/random`: Blocking, checks for sufficient entropy (less commonly needed).

---

### **9. Quantifying Security**

#### **Security Parameters**
- **Bit security**:
  - A system with n-bit security requires 2^n operations to break.
  - **Example**:
    - A 128-bit key provides 2^128 possible combinations.
- **Practical Recommendations**:
  - Long-term security: 256-bit keys.
  - Short-term security: 80-bit keys might suffice.

---

### **10. Key Takeaways**

- **Classical Ciphers**:
  - Simple but insecure (e.g., frequency analysis vulnerabilities).
- **Modern Ciphers**:
  - AES is the current standard and is used with secure modes like CBC and CTR.
- **Randomness**:
  - Essential for the strength of cryptographic systems.
- **Kerckhoffs's Principle**:
  - The secrecy should lie in the key, not in the algorithm.

Here is the detailed summary for Week 9: MACs and Authenticated Encryption in Markdown format.

---

## **MACs and Authenticated Encryption**

### **1. Hash Functions**

#### **Definition and Applications**
- **Hash Function**: Maps an input of any size to a fixed-size output.
- Common cryptographic applications:
  - Key derivation
  - Authentication digests
  - Randomness extraction
  - Password storage
  - Proofs of work
- Used beyond cryptography:
  - Version control indexing
  - Cloud storage deduplication
  - File integrity in intrusion detection systems.

#### **Properties of Secure Hash Functions**
1. **Efficiency**: Must be computationally efficient.
2. **Pre-image Resistance**: Hard to reverse-engineer the input from the output.
3. **Collision Resistance**: Difficult to find two distinct inputs producing the same hash.

---

### **2. Hash Function Constructions**

#### **Collision Search and the Birthday Paradox**
- **Collision Complexity**:
  - Expected after approximately sqrt(2^n) operations.
  - Computationally easier than (2^n), due to the birthday paradox.

#### **Merkle-Damgård Construction**
- Basis for many older hash functions:
  - MD5, SHA-1, SHA-256, SHA-512.
- Process:
  1. Break message `M` into fixed-size blocks.
  2. Compress blocks iteratively to produce the hash.
- Vulnerabilities:
  - Susceptible to **length extension attacks**.

#### **Sponge Construction**
- Used in SHA-3.
- **Process**:
  - **Absorb phase**: Input blocks are XORed into the state.
  - **Squeeze phase**: Generates output by iterating a fixed permutation.
- Advantages:
  - Arbitrary input and output lengths.
  - Inherent resistance to length extension.

---

### **3. Secure Hash Algorithms (SHA) Family**

#### **SHA-1**
- **Block size**: 512 bits.
- **Output size**: 160 bits.
- Broken in 2017:
  - Collision found after \( 2^{63} \) operations.

#### **SHA-2**
- **Variants**: SHA-224, SHA-256, SHA-384, SHA-512.
- Characteristics:
  - Resistant to known generic attacks.
  - Improved parameters compared to SHA-1.

#### **SHA-3**
- Based on the **sponge construction**.
- Features:
  - Flexible output sizes.
  - Resistant to length extension attacks.
  - **SHAKE Functions**: Extendable Output Functions (XOFs).

---

### **4. Message Authentication Codes (MACs)**

#### **Purpose**
- Provide message authentication and integrity using symmetric keys.
- **Guarantee**: A message `m` with a MAC `t` implies:
  1. It was created by someone who knows the secret key `k`.
  2. The message has not been altered.

#### **Construction**
1. **Keyed Hashing**:
   - MAC(k, m) = H(k || m)
   - Vulnerable to length extension in Merkle-Damgård-based hashes.
2. **HMAC**:
   - Safeguards against length extension.
   - Uses inner and outer key padding.

3. **CMAC**:
   - Based on AES in CBC mode.
   - Fixes vulnerabilities in CBC-MAC by processing the final block with a derived key.

4. **Wegman-Carter MAC**:
   - Combines a universal hash function with a pseudorandom function (PRF).
   - Provides strong security using a nonce.

---

### **5. Authenticated Encryption**

#### **Why Authenticated Encryption (AE)?**
- Combines **confidentiality** (encryption) and **integrity** (authentication).
- Protects against:
  - Message tampering.
  - Replay attacks using nonces.

#### **Approaches**
1. **Encrypt-and-MAC**:
   - Separately encrypt and authenticate.
   - **Weakness**: Potentially decrypts malicious ciphertext before verifying authenticity.

2. **MAC-then-Encrypt**:
   - Authenticate message first, then encrypt both message and MAC.
   - **Weakness**: Vulnerable to padding oracle attacks (e.g., Lucky 13).

3. **Encrypt-then-MAC**:
   - Encrypt the message first, then authenticate the ciphertext.
   - **Advantage**: Ensures ciphertext is verified before decryption.
   - **Preferred method**.

---

### **6. Advanced Authenticated Encryption Designs**

#### **Galois-Counter Mode (GCM)**
- Combines AES in CTR mode with a Wegman-Carter MAC.
- **Features**:
  - Parallelizable encryption and authentication.
  - Highly efficient in hardware implementations.

#### **Offset Codebook Mode (OCB)**
- Combines AES with offsets derived from nonces.
- **Advantages**:
  - Minimal overhead compared to GCM.
  - Prevents block duplication detection under nonce reuse.

#### **Synthetic IV Mode (SIV)**
- Protects against nonce reuse.
- Process:
  1. Generate a deterministic tag as the IV.
  2. Encrypt using the tag.
- **Tradeoff**: Not streamable.

#### **Permutation-Based AEs**
- Derived from sponge construction (e.g., SHA-3).
- Characteristics:
  - Resilient to nonce reuse for unforgeability.
  - Leakage of partial plaintext under nonce reuse.

---

### **7. Key Takeaways**

- **Hash Functions**:
  - Serve as the foundation for many cryptographic protocols.
  - SHA-2 and SHA-3 are the current standards.
- **MACs**:
  - Ensure message integrity and authentication.
  - HMAC and CMAC are widely used constructions.
- **Authenticated Encryption**:
  - Encrypt-then-MAC is the safest design.
  - GCM and OCB are popular AE schemes, balancing security and performance.

---

Here is the detailed summary for Week 10: Public Key Cryptography in Markdown format:

---

## **Public Key Cryptography**

### **1. Introduction to Public Key Cryptography**

#### **Historical Context**
- Developed in the 1970s to address limitations of symmetric cryptography.
- Key contributions:
  - **Public Key Encryption**: Enables secure communication in open systems.
  - **Digital Signatures**: Provides authenticity and non-repudiation.
  - **Key Agreements**: Facilitates secure session key exchange.

#### **Core Ideas**
- Public-key cryptography replaces the need for pre-shared keys in open systems.
- Asymmetric encryption uses a pair of keys:
  - **Public Key (`pk`)**: For encryption/signature verification.
  - **Private Key (`sk`)**: For decryption/signature generation.

---

### **2. Key Management**

#### **Symmetric Key Challenges**
- **Key Proliferation**: \( \frac{N(N-1)}{2} \) keys needed for \( N \) participants.
- **Solutions**:
  - Centralized Key Distribution Centers (e.g., Kerberos).
  - Use of **long-term keys** for storage security (e.g., HSMs, smartcards).
  - **Session Keys**:
    - Ephemeral and data-limited.
    - Reduces risk of long-term key compromise.

---

### **3. Asymmetric Encryption**

#### **How It Works**
1. **Encryption**: \( c \gets E(pk, p) \)
2. **Decryption**: \( p \gets D(sk, c) \)
   - Anyone can encrypt using `pk`.
   - Only the owner of `sk` can decrypt.

#### **Efficiency and Hybrid Systems**
- Asymmetric encryption is computationally expensive (thousands of bits vs. 128 bits for symmetric keys).
- **Key Encapsulation Mechanism (KEM)**:
  1. Generate a symmetric session key (`k`).
  2. Encrypt the payload using `k`.
  3. Encrypt `k` using `pk`.

---

### **4. Building Public Key Encryption**

#### **Mathematical Foundations**
- Based on **trapdoor one-way functions**:
  - Easy to compute but hard to invert without a secret key.
  - Example: RSA (Rivest-Shamir-Adleman) relies on integer factorization.

#### **RSA Overview**
1. **Key Generation**:
   - Choose primes \( p, q \); compute \( n = p \cdot q \) and \( \phi = (p-1)(q-1) \).
   - Select \( e \) (public exponent) and \( d \) (private exponent) such that \( e \cdot d \mod \phi = 1 \).
   - Public key: \( (e, n) \), Private key: \( (d, n) \).
2. **Encryption**: \( c = p^e \mod n \).
3. **Decryption**: \( p = c^d \mod n \).

#### **RSA-OAEP**:
- Addresses lack of randomness in RSA.
- Adds padding and randomness before encryption.

---

### **5. Digital Signatures**

#### **Definition and Properties**
- Provides assurance that:
  1. The message was authored by the signer.
  2. The message has not been altered.
  3. The signer cannot deny signing the message (**non-repudiation**).

#### **Construction**
- Signing: \( \sigma \gets Sign(sk, p) \).
- Verification: \( T/F \gets Verify(pk, p, \sigma) \).

#### **Differences from MACs**
- **Digital Signatures**:
  - Do not require pre-shared keys.
  - Ensure non-repudiation.
- **MACs**:
  - Require shared secrets.
  - Lack non-repudiation.

---

### **6. Key Agreement Protocols**

#### **Purpose**
- Establish a symmetric session key in a public-key setting.
- Goals:
  1. Confidentiality of the session key.
  2. Authenticity of key exchange.
  3. **Perfect Forward Secrecy (PFS)**:
     - Compromise of long-term keys does not compromise past session keys.

#### **Diffie-Hellman (DH) Protocol**
1. Public parameters: \( G, g, p \) (group, generator, prime).
2. Key exchange:
   - Alice computes \( X = g^a \mod p \).
   - Bob computes \( Y = g^b \mod p \).
   - Shared key: \( K = g^{ab} \mod p \).

#### **Limitations**
- Vulnerable to **Man-in-the-Middle (MITM)** attacks without authentication.

---

### **7. Authentication Challenges**

#### **Authenticating Public Keys**
- Problem: Ensuring the public key belongs to the intended recipient.
- Solution: **Public Key Infrastructure (PKI)**:
  - Certificates issued by trusted authorities bind public keys to identities.

---

### **8. Post-Quantum Cryptography**

#### **Quantum Threats**
- Grover’s Algorithm:
  - Quadratic speedup in brute force attacks.
  - **Impact**: Doubling symmetric key sizes.
- Shor’s Algorithm:
  - Efficient factorization of integers.
  - **Impact**: Breaks RSA and other public-key schemes.

#### **Post-Quantum Algorithms**
- Focus on problems resistant to quantum attacks:
  - **Lattice-based Cryptography**:
    - Learning With Errors (LWE), Shortest Vector Problem (SVP).
  - NIST-selected replacements:
    - **CRYSTALS-Kyber** (Key Encapsulation).
    - **CRYSTALS-Dilithium** and **FALCON** (Signatures).

---

### **9. Key Takeaways**

- Symmetric cryptography is efficient but limited in open systems.
- Public-key cryptography addresses authentication and key exchange.
- Digital signatures provide non-repudiation and integrity.
- Diffie-Hellman ensures confidentiality but requires authentication to prevent MITM.
- Post-quantum cryptography is crucial for future-proofing against quantum computers.

---

## **Informatics Security Fundamentals - Public Key Infrastructures and Authentication**

### **1. Public Key Infrastructures (PKIs)**

#### **Why PKIs?**
- Public-key cryptography relies on authentic public keys.
  - Example: Alice receives `pkB` and needs assurance it belongs to Bob, not an attacker.
- **Challenges**:
  - Prevent **Man-in-the-Middle (MITM)** attacks.
  - Ad-hoc solutions (e.g., manually trusting keys) are impractical at scale.

#### **PKI Context**
- Provides **legal and technical frameworks**:
  - Standardizes algorithms, roles, and responsibilities.
  - Offers liability in case of violations.

#### **How PKIs Work**
- Central entity (e.g., Certification Authority, CA) attests to public key ownership.
- **Certificates**:
  - Bind a public key (`pkB`) to an identity (e.g., Bob).
  - Signed by a trusted CA (e.g., Charlie).

---

### **2. Public Key Certificates (PKCs)**

#### **Goal**
- Ensure that a public key belongs to its rightful owner.
- Example:
  - Bob proves ownership of `pkB` to a CA.
  - CA issues a certificate attesting to Bob's ownership.

#### **Structure of Certificates**
- Certificates include:
  1. Public key (`pkB`).
  2. Identity of the owner (e.g., Bob).
  3. CA identity and metadata (e.g., serial numbers, validity).
  4. Digital signature from the CA.

#### **Verification Process**
- Steps for Alice to verify Bob's certificate:
  1. Check if Bob's key matches the certificate.
  2. Ensure the certificate is within its validity period.
  3. Verify the certificate's metadata.
  4. Confirm the CA's trustworthiness.
  5. Use the CA's public key (`pkCA`) to verify the signature.

---

### **3. X.509 Certificates**

#### **Overview**
- Standardized format for digital certificates.
- Fields include:
  - **Subject**: The certificate owner (e.g., Bob).
  - **Issuer**: The signing CA.
  - **Validity Period**: Start and expiration dates.
  - **Public Key Information**: The subject's public key.
  - **Serial Number**: Unique identifier.

#### **Extensions**
- **Critical Extensions**:
  - Marked as mandatory; failure to understand them invalidates the certificate.
- Examples:
  1. **Key Usage**: Defines valid contexts for key use.
  2. **Authority Key Identifier**: Links to the CA's public key.
  3. **Basic Constraints**: Indicates if the certificate belongs to a CA.

---

### **4. Certificate Chains**

#### **Multi-Level Trust Hierarchies**
- **Root CAs**: Trust anchors, often pre-installed in systems (e.g., browsers).
- **Subordinate CAs**:
  - Root CAs delegate to sub-CAs to validate users in different contexts.
  - Trust in sub-CAs is derived from trust in root CAs.

#### **Validation Process**
- Example:
  - To trust Bob’s certificate:
    1. Alice verifies Bob’s certificate (issued by a sub-CA).
    2. Alice verifies the sub-CA’s certificate (issued by the root CA).
    3. Alice verifies the root CA’s self-signed certificate.

---

### **5. Certificate Revocation**

#### **Need for Revocation**
- Scenarios:
  - Private keys are compromised.
  - Metadata (e.g., validity) becomes outdated.
  - CA is no longer trustworthy.

#### **Revocation Mechanisms**
1. **Certificate Revocation Lists (CRLs)**:
   - CAs publish blacklists of revoked certificates.
   - Challenges: Ensuring up-to-date CRL access.
2. **Online Certificate Status Protocol (OCSP)**:
   - Real-time revocation checks via secure servers.
3. **Certificate Pinning**:
   - Specific certificates are manually trusted by systems or applications.

---

### **6. Alternative: Pretty Good Privacy (PGP)**

#### **Features**
- Decentralized trust model (**Web of Trust**).
- Users validate and sign each other's keys.
- **Advantages**:
  - No central authority required.
  - Resilient against single points of failure.
- **Disadvantages**:
  - Complex to manage and scale.
  - Limited adoption outside niche contexts.

---

### **7. Authentication and Access Control**

#### **Authentication**
- **Purpose**: Confirm the identity of a user or system.
- **Factors**:
  1. **Something You Know**: Passwords, PINs.
  2. **Something You Have**: Smart cards, tokens.
  3. **Something You Are**: Biometrics (e.g., fingerprints).

#### **Authorization**
- **Purpose**: Determine user permissions (e.g., read, write, modify).
- Ensures access is restricted based on system-defined roles.

---

### **8. Authentication Protocols**

#### **Challenges**
- **Replay Attacks**:
  - Adversaries intercept and reuse authentication messages.

#### **Solutions**
1. **Challenge-Response**:
   - Bob sends a random challenge (nonce).
   - Alice computes a response using her secret (e.g., hashed password and nonce).
   - Bob verifies the response.

2. **Using Nonces**:
   - Nonces ensure each session is unique.
   - Example:
     - Challenge: Nonce sent by Bob.
     - Response: \( H(\text{password} || \text{nonce}) \).

---

### **9. Password Security**

#### **Threats**
1. **Keylogging**:
   - Hardware or software intercepts keystrokes.
2. **Dictionary Attacks**:
   - Precomputed hash databases to match weak passwords.
3. **Phishing**:
   - Trick users into revealing credentials (e.g., fake websites).

#### **Countermeasures**
1. **Salting**:
   - Add random data (`salt`) to passwords before hashing.
   - Prevents precomputed dictionary attacks.
2. **Strong Passwords**:
   - Use combinations of letters, numbers, and special characters.

---

### **10. Key Takeaways**

- **PKIs**:
  - Central to establishing trust in public-key cryptography.
  - Legal and technical frameworks enhance reliability.
- **Certificates**:
  - X.509 is the standard format.
  - Certificate chains validate trust hierarchies.
- **Revocation**:
  - CRLs and OCSP ensure invalid certificates are flagged.
- **Authentication**:
  - Use robust protocols (e.g., challenge-response) to prevent attacks.
- **Password Security**:
  - Employ salting, strong passwords, and secure storage practices.

---
