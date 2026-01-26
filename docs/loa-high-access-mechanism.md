# Assessment and recommendation for a LoA High access mechanism

Security risk 1: A memory dump during the right time reveals the OPAQUE password and allows it to be used from another device without the server knowing.

Security risk 2: The server has no way of knowing that the user has input two authentication factors. The PIN-hardening is indistinguishable from an HKDF output using only PIN and software salt.

Solution to security risks: use a key attestation to sign all service requests to the server to ensure possession factor, and to mitigate risk of memory dump.


## 0. Executive summary

This evaluation assesses candidate LoA High access mechanisms for EUDIW, building on the "Statligt e-leg" specification and addressing changes introduced by the shift from smart cards to personal smartphones (BYOD).

Candidate suitability is decided by two key factors: 

1. The security guarantees provided under specific threats. 
2. Functional coverage. Candidates should ideally support most of the capabilities required by the EUDIW use cases.

Ultimately, candidate suitability reflects deeper discussions about core security properties, the role of formal security evaluation, and the required functionality. 

Pragmatism also matters. Solutions that facilitate certification offer a clear advantage. As certification schemes are still evolving, the preferred option presented here remains contingent on future certification allowances.

Our assessment considered a wide range of candidates. Signature-based systems alone are insufficient, and while challenge-response protocols (e.g., SCRAM) appear adequate under certain conditions, they have two fundamental limitations:

1. The authentication guarantees of protocols like SCRAM are not cryptographically intrinsic (i.e., derived solely from cryptographic protocol design). Instead, guarantees depend on external components and fragile operational assumptions (correct TLS configuration, uncompromised verifiers, secure devices etc.).
2. They often lack forward secrecy, do not enable subsequent session key derivation, and are not trivially composable with other cryptographic workflows.

The above points can be, and have been, contested as the suitability of solution candidates hinges on whether the evaluation prioritizes composable, intrinsic cryptographic guarantees, or is willing to accept security assumptions that are external and conditional.

The expert group chose not to recommend any "basic" challenge-response protocol. These do not offer formal security guarantees under composability (i.e., resilience when embedded within complex systems), and have insufficient functionality (specifically, the ability to derive additional session key from the exchange alone). 

Instead, the group evaluated two alternatives: threshold signatures and password-authenticated key exchange (PAKE). Of the two, PAKE offers a more favorable balance of security, implementation maturity, and functional coverage.

The recommended solution is OPAQUE, a secure augmented PAKE protocol that has formal proofs of composable, adversarially robust security, thus requiring an HSM only to protect the server's secret key (as opposed to parts of the protocol itself). 

Note that this recommendation will need to be re-evaluated as certification scheme development progresses.

## 1. Preliminaries

### 1.1. Task requirements

**Task**: Identify and recommend a server-side access mechanism for EUDIW that meets LoA High. Existing solutions from the government e-ID project may be reused.

**Scope**: This evaluation aims to:

- Assess changes in requirements resulting from the shift to a wallet-based model.
- Evaluate access mechanisms likely to meet LoA High.
- Recommend a compliant mechanism.

This is a theoretical evaluation; no implementation is required.

**Deliverable**: A justified recommendation supported by assurance-level analysis.

## 2. Results

### 2.1. Requirements evaluation

The technical specification for "Statligt e-leg" defines [User Authentication][1], using a PIV-compliant smart card, client middleware (a smartphone app), and a server equipped with an HSM.

Increased reliance on smartphones introduces several key changes:

* **Key Protection** becomes more complex due to the heterogeneity of bring your own user devices (BYOD). Smartphones are impractical to certify under EUDIW requirements. Mitigation involves using the smartphone within a national eID scheme for server authentication
* **PIN Verification**  is unaffected, as the previous model already used smartphones for knowledge-factor verification.
* **Device Identity Binding** is more challenging in multi-device contexts, as there is no longer a single smartcard-based root of trust. Mitigation requires mechanisms to bind devices to a single HSM-secured user account.
* **Recovery and Revocation** are more complex. Traditional card-based revocation via a CA is no longer viable, requiring self-service workflows. Re-enrollment remains the primary recovery path, with potential enhancements via threshold-based multi-party schemes and granular recovery parameters.
* **Feature-Rich Wallets** enabled by smartphones, support both simplified (e.g., HMAC-based) and advanced (e.g., ZKP-layered) solutions. Feature-rich wallets necessitate stricter composability guarantees and enables secure data storage and usage analytics.
* **Client compatibility** requirements have shifted. In Statligt e-leg, broad app compatibility was needed. The EUDIW model relaxes this constraint and tolerates higher implementation complexity.
* **Certification** can now focus solely on the HSM, without addressing external device boundaries.

In summary, a smartphone-centric architecture necessitate updated approaches to key protection, device binding, and recovery to align with certification requirements. Other areas, such as PIN hardening (see Appendix A), remain unaffected.

### 2.2. Deployment context

To assess candidates, it is helpful to clarify the deployment context.

Authentication factors:

1. The knowledge factor is provided through a trusted UI as a user-controlled PIN, entered on the user device and combined with a device-protected key using PIN hardening. The hardened PIN functions as a client password. Verification occurs server-side to enforce rate-limiting and account locking.  Users are not allowed to set their own PIN.
2.  The possession factor is supplied during PIN hardening via a keyed mapping function (e.g., ECDH or HMAC), with the PIN acting as a public input and the key protected by the device’s secure hardware

User device characteristics:

3. Target platforms are iOS and Android.
4. Trusted component exists and access to secure environment is provided via platform-specific APIs.
5. Devices are BYOD but part of national eID scheme at LoA High where the use of trusted hardware and server request is verified (key attestation, device check etc.).


Protocol parameters:

6. Standard profiles for threshold signatures (e.g., FROST or MuSig2), or
7. OPAQUE with fresh DH keys and server authentication, configured per [test vector 5](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-18.html#name-opaque-3dh-real-test-vector-5) (note that PIN-hardening allows us to rely on the identify function as a KSF).

Lifecycle:

8. Identity proofing is performed per the national eID scheme (out of scope for this document)
9. All attestations are issued with a distinct Proof of Possession key protected by a server-side HSM resource that is gated by the national eID access mechanism described here.
10. Recovery is handled through re-enrollment using the same process as registering the initial user device, associating a new device with the same server-side user account.
11. Validity status is enforced through explicit time periods (e.g., 24-hour validity). No explicit revocation.

Session security:

12. Post-authentication, all service requests are secured using service specific session keys. These require a second protocol layer when using threshold signatures, but can be directly derived with OPAQUE.  
13. All session keys are specific to the service request. Relatedly, lifetimes are limited to the duration of the individual service request.

### 2.3. Selection criteria

When selecting candidates for further assessment, our disqualifying conditions were:

1. The candidate must provide security against active adversaries through intrinsic cryptographic guarantees, not through external configurations or assumptions.
2. The candidate must support intrinsic derivation of additional useful cryptographic material as part of the protocol.
3. The candidate must resist offline guessing attacks, even in the event of server-side storage compromise.
4. The protocol must maintain security when composed with other protocols and application logic.
5. The candidate must be widely deployed and tested in a context that makes it suitable for our analysis.

### 2.4. Candidates for a LoA High access mechanism

Two primary approaches were considered for achieving LoA High compliance: Threshold signatures and password-authenticated key exchange (PAKE). At a glance, the two appear fundamentally different; PAKE gates an HSM-held signing key, while threshold signatures distribute a signing authority. Yet, there are two reasons for the comparison:

1. Growing support for Schnorr signatures in HSMs enables full user control through distribution of the signing authority.
2. In the NL SCAL 3 initiative, threshold signing functions as the knowledge factor.

Because threshold signing serves as a proof-of-knowledge factor in this context, the comparison is justified.

> Security assumptions are listed in Appendix B and security goals in Appendix C

#### 2.4.1. Threshold signatures

Threshold signature schemes split the signing key among multiple parties, ensuring that a valid signature cannot be generated without collaboration. This enforces cryptographic guarantees of exclusive control, surpassing traditional consent-based mechanisms. Protocols such as FROST and MuSig2 are mature, widely supported, and actively deployed, making them strong candidates for Level of Assurance (LoA) High access mechanisms. Ongoing trials in the Netherlands will serve as the basis for our evaluation.

While the cryptographic assurances are compelling, the practical deployment of threshold signature schemes raises several concerns:

* **Limited deployment**. While ECSDSA is listed as a recommended signature scheme in SOG-IS and in ETSI TS 119 312, now expired patent claims have limited its deployment. Threshold signatures are possible also using a variant of Schnorr based on Edwards curves, EdDSA (informational in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) and forthcomming in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final)). But required curves, like edwards25519 and edwards448, are not included in either SOG-IS, ETSI TS 119 312, and [BSI TR 03181](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03181/BSI-TR-03181.pdf?__blob=publicationFile&v=5) optionally supports edwards25519. The curves are both listed in [SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final).
* **Limited HSM support**. Outside of IBM HSMs [(running in EP11 and CCA mode)](https://public.dhe.ibm.com/security/cryptocards/pciecc5/docs/4770_Data_Sheet.pdf), hardware support is limited for ECSDSA. Hardware support for EdDSA is better and EdDSA is included in [PKCS#11v3](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/csprd01/pkcs11-curr-v3.0-csprd01.html#_Toc10560880).
* **Patent concerns**. Using alternatives to Schnorr (and its variants) is not straight forward and can pose significant patent risks.
* **Uncertain compliance implications**. Threshold signatures have not yet undergone formal evaluation for compliance with Level of Assurance (LoA) High requirements.
* **Comparatively more complex**. Theoretical benefits (e.g., recovery) require complex multi-party setups and may offer limited advantages over simpler approaches, which benefit from existing experience and reusable components (e.g., re-onboarding).
* **Extension requirement**. A threshold signature scheme needs to be extended and tailor to the intended application (e.g., access mechanism or PoP). This burdens the security analysis.

Using ECSDSA is challenging and restricts implementation flexibility and increases both vendor dependency and legal risk. Hardware support for EdDSA is much better, but it lags behind in European standardization. 

Even if these barriers are overcome, the unproven compliance status and added complexity diminish the overall value proposition. Without clear and substantial benefits, adopting threshold signatures remains difficult to justify.

Furthermore, the specific application of threshold signatures must be defined. An intuitive assumption is their use to distribute signing authority for the PoP. But upon closer scrutiny, the benefits of such an application today seem unclear. While threshold signatures enforce multi-party control over signing, there is no mechanism to enforce their use. Since group signatures are syntactically indistinguishable from single-party signatures, demonstrating user control over the PoP key requires additional assurances.

> Note that distributing the PoP key via threshold signing is unrelated to the access mechanism itself. We address this application only because it is a common assumption about threshold signing in general. When threshold signing is used for PoP key control, a separate access mechanism is still required to authenticate the user.

These assurances can take various forms. One option is to use transcript proofs to verify threshold participation. While they do not enforce policy, they make violations publicly detectable. The Cleverbase approach leverages FROST’s native support for transcript proofs to provide this assurance. An alternative is to rely on a [trusted key dealer](https://www.rfc-editor.org/rfc/rfc9591.html#appendix-C) who generates and distributes shares and issues a signed statement confirming that the public key is a threshold key. But this undermines the sole control model, as the trusted dealer learns all signing shares. If the dealer is trusted with these shares, it is simpler delegate the signing operation entirely to that trust domain.

Finally, even if all challenges are resolved, there remains a critical gap: no current verifier support for ECSDSA among Relying Parties. EdDSA is a stronger candidate in this regard and once European standardization matures, it is the more obvious candidate.

**In practice, threshold signatures appear ill-suited for distributing the PoP key. Unsurprisingly, this is not the application explored in the Cleverbase proposal.** The Cleverbase proposal employs threshold signatures as part of the second factor in a Level of Assurance (LoA) High authentication. The user functions as a trusted key dealer, generating the threshold key shares. The user's share is encrypted with a hardened PIN, while the server's share is encrypted with an HSM protected key. The server binds the group public key to the user.

During authentication, the server first verifies the possession factor, then uses FROST to compute a threshold signature on a session-specific challenge, thereby verifying the second factor. This effectively gates HSM access behind a LoA High two-factor authentication.

While this is an innovative use of threshold signatures, it raises one key question:

**Threshold cryptography is meaningful only when control over the signing process and the protected resource are independently distributed. If only the signing process is distributed, but not the protected resource (e.g., the server uses threshold signatures to gate an HSM-protected signing key) then what does threshold signing achieve?**

Our analysis could not answer this question when considering a EUDIW Provider context.

> Let Sander have a stab at providing an answer. One argument is accountability increases with the public transcript proof. This clarifies the separation between the Authorization server and the Resource Server.

#### 2.4.2. Password Authenticated Key Exchange

PAKE protocols enable secure mutual authentication over untrusted networks without transmitting passwords in cleartext. They are typically categorized as:

1. Balanced PAKE (bPAKE): Client and server share a password.
2. Augmented PAKE (aPAKE): Server stores a verifier.

Similar to threshold cryptography, aPAKE methods enhance security by mitigating the impact of server compromise, as no plaintext-equivalent credentials are stored. They also prevent offline attacks by requiring active server participation in the authentication process.

Among various aPAKE protocols (compared [here][5]), OPAQUE stands out as the only one with both a mature standard and a formal security proof under the Universal Composability (UC) framework. Its properties have been previously analyzed in the "Statliga e-leg" section on [OPRF-based aPAKE][6]. OPAQUE's UC security model enables safe protocol composition, reducing the need for separate security analyses and minimizing the risk of implementation flaws. This makes it particularly suitable for high-assurance environments where server compromise or insider threats are significant concerns.

In sum, key practical benefits of aPAKE:

1. Enhances server-side credential security by eliminating stored plaintext-equivalent data.
2. Limits attacks by requiring online interaction with the server.
3. Supports secure integration with layered protocols, simplifying overall system security evaluation.
4. Outputs a shared key useful for other applications.

Given our analysis of both threshold signatures and PAKE as candidates for an LoA High access mechanism, we focus the remainder of this text on detailing an aPAKE-based approach.

## 3. An aPAKE-based access mechanism

We outline an enveloping protocol to establish a secure channel between a user's smartphone (a BYOD device) and a protected server (hosting resources such as an HSM, storage, and logging etc).

The primary function of this protocol is to enable secure use of an HSM-protected EUDIW private key from a mobile device. The protocol provides end-to-end confidentiality, forward secrecy, and mutual authentication of exchanged data. It also facilitates server-side management of a secret key used for client-side encryption.

After key exchange, subsequent secure communications between smartphone and server can reuse the derived session keys. This reuse does not compromise security, due to the UC security guarantees provided by OPAQUE.

### 3.1. High-level protocol steps

The protocol details have previously been analyzed in the Statliga e-leg project with an implementation available [here][8] (c.f., also the [IETF datatracker][7]). Below is a high-level overview:

```
+--------+        +-------------+        +--------+        +--------+
|  User  |        |   Device    |        | Server |        |  HSM   |
+--------+        +-------------+        +--------+        +--------+
    |                   |                    |                   |
    | 1. Enters PIN ---->                    |                   |
    |                   |                    |                   |
    |                   | 2. PIN Hardening   |                   |
    |                   |  (keyed function)  |                   |
    |                   |                    |                   |
    |                   | 3. Derive PAKE pwd |                   |
    |                   |                    |                   |
    |                   |<==================>|                   |
    |                   | 4. aPAKE exchange  |                   |
    |                   |  Auth + Secure     |                   |
    |                   |  Session Setup     |                   |
    |                   |  Output: client    |                   |
    |                   |  key pair, session |                   |
    |                   |  key, storage key  |                   |
    |                   |                    |----> Request ---->|
    |                   |                    |  keyed function   |
    |                   |                    |<---- Response ----|
    |                   |<==================>|                   |
    |                   |                    |                   |
    |                   | 5. Service Request |                   |
    |                   |------------------->|                   |
    |                   | 6. Service Response|                   |
    |                   |<-------------------|                   |
```

The exchange comprises three phases:

1. **Activation**: The user activates their device by entering a PIN (knowledge factor), which is combined with a secure element-protected key (possession factor) to meet the LoA High two-factor authentication requirement, as detailed in Appendix A.
2. **Key exchange**: The device derives an aPAKE password (containing both their knowledge and possession factor) and establishes a mutually authenticated, confidential session with the server. This session produces a session key for encrypted communication and an optional storage key for server-side encrypted storage.
3. **Service provisioning**: All subsequent interactions are secured using the aPAKE-derived session keys.

The activation process aligns with the [User Authentication][1] flow detailed in the "Statligt e-leg" report, though simplified due to smartphone capabilities.

Expected service requests during the provisioning phase include:

1. Operations using the HSM-protected private key.
2. Storage or retrieval of data encrypted under the storage key.
3. Reporting usage metrics for aggregation.

The second and third are added with the increased reliance on smartphones.

# Appendices

## Appendix A: PIN-hardening

The knowledge factor builds on the [PIN-hardening][2] approach defined in the technical specifications for the "Statligt e-leg." Hardening serves two primary purposes:

1. It enforces two-factor authentication by combining the possession factor (a device-specific secret) with the knowledge factor (the PIN) to form a composite password.
2. It compensates for the inherently low entropy of random $n$-digit PINs (bit security normally ranges between ~2.3 - 20 and depends chiefly on PIN length and whether or not the PIN is user selected).

> Note: Hardening differs from traditional key-stretching or strengthening via a KDF. Instead, it fuses the PIN with a hardware-protected, device-specific key.

The user device maintains a set of keyed mapping functions (e.g., HMAC, ECDSA, ECDH) that can harden the PIN. This process binds the two authentication factors and increases overall entropy by incorporating the device-resident key.

With smartphone-based implementations, the previously defined [PIN-hardening][2] method can be simplified (see, e.g., Signal’s [secure value recovery][3]). Specifically, access to HMAC allows bypassing the need to map the PIN to a random elliptic curve point for ECDH. Nonetheless, server-side rate limiting remains essential to defend against brute-force attacks.

> Platform support for key derivation functions (KDFs) is inconsistent: iOS supports HKDF, while Android's support is less clear. Given both platforms support HMAC, and considering the specific use case, HMAC alone may suffice without introducing an additional KDF layer.

>**Stefan:** As we will implement OPAQUE, we will need hash2Curve anyway. But that is not a problem because a) we have working implementations for both iPhone and Java, and b) we no longer need to support easy creation of custom clients. This means that the complexity of this is negligeble compared to the total development effort. I still think the strongest proposal is ```HKDF(DH(walletPrivate, H2C(PIN)))```

## Appendix B: Security assumptions

1. **Secure hardware**
  * Smartphones are equipped with secure elements and/or TEE, providing access to cryptographically secure keyed mapping functions like HMAC, various KDFs, and/or ECDH.
  * The server with a certified HSM supports HPKE-based KEM, OPRF, Argon2, and MAC operations. It can also store user-specific rate counters and cryptograms.

>**Stefan:** Server based HSM operations can be reduced to Diffie-Hellman operations and client key generation.

2. **Adversaries**
  * perform active network attacks, replay messages, and intercept all traffic.
  * gain software-level access to the server, but not extract key material from the HSM.
  * extract the TEE image and encrypted data from a client device but not bypass hardware protected keys.

## Appendix C: Security goals and OPAQUE

| Goal | Description                                                                                           | OPAQUE Security Analysis                                                                 |
|------|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| G1   | Each attack attempt requires online interaction.                   | Achieved through rate-limited online interactions.                                       |
| G2   | Two-factor assurance.          | PIN hardening implemented using the smartphone secure element.                           |
| G3   | Hardware protected keys.                     | PIN-hardened key protected by secure enclave; OPRF key protected by HSM.                 |
| G4   | Attackers must not trivially exhaust server-side rate limits.                         | Possible via exponential backoff and authenticated requests.                             |
| G5   | Protect user's PIN even if the server is compromised.                                                 | No password material is ever sent to the server.                                         |


The above list is not complete, it only highlights assumptions and requirements relevant for the current evaluation.


[1]: https://github.com/diggsweden/statligt-eleg-specifications/blob/main/authn_api/authn.md
[2]: https://github.com/diggsweden/statligt-eleg-specifications/blob/main/authn_api/authn.md#deriving-a-client-password-using-both-the-pin-and-the-piv
[3]: https://signal.org/blog/secure-value-recovery/
[4]: https://expg.eidasweb.se/s/pX6PMpNwp
[5]: https://expg.eidasweb.se/s/1SLyyBCHz#
[6]: https://github.com/diggsweden/statligt-eleg-specifications/blob/main/authn_api/authn.md#using-an-oprf-to-ensure-that-the-pin-never-leaves-the-users-device
[7]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/
[8]: https://github.com/diggsweden/statligt-eleg-prototype/tree/main/opaque-java
