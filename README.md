
# How it Works
Special thanks to [GoodiesHQ](https://github.com/GoodiesHQ) for the original code this project is based on.

PIMPTune is a SCEP ([Simple Certificate Enrollment Protocol](https://en.wikipedia.org/wiki/Simple_Certificate_Enrollment_Protocol)) proxy server designed specifically for devices managed through [Microsoft Intune](https://intune.microsoft.com/). It sits between Intune-managed clients and a [Smallstep step-ca](https://smallstep.com/docs/step-ca/) certificate authority, acting as a trusted intermediary that validates enrollment requests against Microsoft's APIs before issuing certificates.

The core problem it solves: Intune wants to validate that a SCEP challenge came from a device it provisioned, and step-ca wants a properly authenticated request before signing a certificate. PIMPTune bridges those two worlds.

```
Windows Device (SCEP client)
        │
        |
        ▼
    Optional Frontend Proxy
    (e.g. Cloudflare, WAF, Traefik, etc)
        |
        |
        ▼
    PIMPTune Server      
        |        ◄ ─ ► Microsoft Graph API (SCEP endpoint discovery)
        │        ◄ ─ ► Microsoft Intune API (challenge validation, notifications)
        │        ◄ ─ ► Smallstep step-ca API (certificate signing)
        ▼
    SQLite Database
    (local certificate cache)
```
PIMPTune typically runs behind a reverse proxy that handles TLS termination and exposes two HTTP endpoints:
 - SCEP enrollment endpoint for clients to send SCEP requests
 - CRL distribution point for clients to check revoked certs

## Recommended Setup
It is highly recommended that you utilize secure PKI practices when dealing with certificates along the chain used for PIMPTune. This may including using a cold, offline CA and/or a system of physical or cloud-based HSAs to store the private keys for this system.

Some related tools of mine:
- [bipkey](https://github.com/griefersutherland/bipkey): A way to derive deterministic ECC and RSA keys from a BIP-39 mnemonic and a salt.
- [revokr](https://github.com/griefersutherland/revokr)Create CRL or TBS CRL from a text file of serial numbers and/or an existing CRL.

The step-ca instance used by PIMPTune should utilize an Issuing CA provided by an existing offline root CA dedicated for this purpose. This Issuing CA should be provisioned as such in the microsoft certificate store(s) of all devices.

# AI Docuslop
Hello. It's me, a human! I used Claude Code to create a human-readable form of documentation of what this program does and how it happens. I believe it's done a great job:

## Startup Sequence

Before serving any requests, PIMPTune performs a series of validation steps to fail fast if anything is misconfigured:

1.  **Configuration loading:** All flags and environment variables are read, parsed, and validated. This includes parsing the RA (Registration Authority) certificate and private key pair, ensuring they match, and the RA cert issuing chain.
    
2.  **JWK provisioner key loading:** The JWK (JSON Web Key) used to authenticate with Smallstep is parsed from disk. If the key file is encrypted (JWE), it is decrypted using the provided password.
    
3.  **Microsoft client initialization:** An Azure credential is established using the provided **tenant ID**, **client ID**, and **client secret**. PIMPTune immediately makes a live call to Microsoft Graph to discover the Intune SCEP validation endpoint, and then fetches an Intune access token. This confirms that the credentials are valid and that the application has the required `scep_challenge_provider` role before accepting any client connections.
    
4.  **Smallstep client initialization:** A connection to `step-ca` is established. The CA's root certificate fingerprint is used to pin the TLS connection, so PIMPTune will refuse to communicate with any CA whose certificate doesn't match the expected root.
    
5.  **Certificate store initialization:** A SQLite database is opened (or created) in WAL mode. WAL (Write-Ahead Logging) mode is used so that reads and writes don't block each other. The schema is created if it doesn't exist.
    
6.  **Background purge worker:** A goroutine starts that runs once per hour, deleting any certificates from the store that expired more than 24 hours ago.
    
7.  **HTTP server start:** The server begins listening. Graceful shutdown is wired to `SIGINT`/`SIGTERM`: the server stops accepting new connections, waits up to 10 seconds for in-flight requests to finish, then closes the database.

---

## Handling a SCEP Enrollment Request

This is the main code path and where most of the logic lives. Every Windows device enrollment arrives as an HTTP `GET` or `POST` to `/scep/pkiclient.exe` with an `?operation=` query parameter.

### Operation:  `GetCACaps`

The client asks what capabilities the server supports. PIMPTune responds with a  list: `POSTPKIOperation`, `SHA-256`, `SHA-512`, `AES`, `DES3`, and `SCEPStandard`.
This tells the Windows SCEP client which algorithms it may use for the enrollment.

### Operation:  `GetCACert`

The client fetches the server's certificate chain so it can encrypt its enrollment request. PIMPTune responds with a PKCS#7 bundle containing the RA certificate followed by the full CA chain. The client uses the RA certificate's public key to encrypt its request.

### Operation:  `PKIOperation`  (the main enrollment flow)

This is the enrollment itself. The request body is a PKCS#7-wrapped PKI message.  Processing happens in the followest phases:

**1. Decryption and parsing**

The PKI message is decrypted using the RA's private key, revealing the Certificate Signing Request (CSR) and the challenge password that Intune provisioned for the device. The message type is checked, but `PKCSReq` (new enrollment), `RenewalReq`, and `UpdateReq` are all currently handled as new enrollment requests. `GetCRL` is handled separately. `GetCert` and `CertPoll` return 501 Not Implemented.

**2. CSR validation**

Before touching any external APIs, the CSR is locally validated:

-   The CSR's cryptographic signature is verified (the device proves it holds the private key)
-   The signature algorithm must be one of the supported types (RSA with SHA-1/256/384/512, or ECDSA equivalents, and SHA-1 is accepted for compatibility with older clients)
-   RSA key size must be at least 2048 bits
-   The Common Name must not be empty

**3. Certificate store lookup**

A lookup is made in the SQLite store using a SHA-256 hash of the CSR and challenge password combined. This catches duplicate requests from the same device:

-   **If a valid, unexpired certificate is found:**  it is returned immediately without re-signing or re-verifying. If Intune was never notified about this certificate (e.g., the notification failed on a previous attempt), notification is retried before responding.
-   **If the certificate is expired or not found:**  enrollment proceeds to the next phase.

**4. Intune challenge verification**

The CSR and challenge password are sent to the Intune `validateRequest` API. Intune checks that the challenge is legitimate and was issued for this device. If Intune says the challenge is invalid, enrollment is rejected immediately. This is the primary security gate; no certificate will be issued for a challenge that Intune didn't provision. If the challenge is verified, then enrollment proceeds.

**5. Device compliance check** _(optional)_

If compliance enforcement is enabled in PIMPTune settings, the device's compliance state is looked up via Microsoft Graph's Device Management API. The device is identified by its Common Name, which is expected to be either an Intune Device ID or an Azure AD Device ID depending on configuration. Devices in a "compliant" state pass. Devices in a grace period pass or fail depending on whether grace-period enrollment is enabled. All other states (non-compliant, unknown, etc.) result in a rejection, and Intune is notified of the denial.

**6. Certificate signing**

PIMPTune calls `step-ca` API to sign the CSR provided by the device, now that the CSR is verified to be legitimate. Authentication to `step-ca` is done with a short-lived JWT (5-minute validity) signed with the provisioner's JWK private key. The JWT carries the device's Subject Alternative Names and the CSR's public key fingerprint as claims. The signed certificate is returned.

**7. Storage and Intune notification**

The signed certificate is stored in the SQLite database, keyed by the `(CSR, challenge)` hash. PIMPTune then calls Intune's `successNotification` API, reporting the certificate's thumbprint, serial number, expiration date, and issuing CA. **If the success notification fails, the certificate is not returned to the client.** This ensures that Intune's records stay in sync with what was actually delivered. Only after Intune confirms receipt is the SCEP success response sent back to the device.

**8. Response delivery**

The signed certificate is wrapped in a PKCS#7 success envelope, encrypted and signed using the RA certificate and key, and returned to the Windows client.

## Microsoft Integration

### Token and endpoint caching

To avoid hitting Microsoft's APIs on every request, PIMPTune caches two things:

-   **The Intune SCEP validation endpoint URI:** discovered via Microsoft Graph's Service Principals API by querying Intune's well-known application ID. Cached for 30 minutes.
-   **The Intune access token:**  fetched from Azure AD using the OAuth 2.0 client credentials flow with the  `https://api.manage.microsoft.com//.default`  scope (note the intentional double-slash, which is a quirk of Intune's API). Tokens are considered expired 5 minutes before their actual expiry to avoid clock-skew failures, and refreshed automatically.

Both caches are protected by their own mutexes so concurrent requests don't trigger redundant API calls.

### Retry behavior

All three Intune API calls (challenge verification, success notification, and failure notification) use automatic retry with exponential backoff (up to 3 total attempts: 500ms wait, then 1s). Retries only happen on genuinely transient errors: network-level failures, `429 Too Many Requests`, and server-side errors (500, 502, 503, 504). Authoritative failures like `400 Bad Request` or `403 Forbidden` are not retried.

Each call carries a `client-request-id` header (a UUID generated per enrollment) that is preserved across retry attempts, so correlated log entries can be found in Intune's audit logs.

## Smallstep CA Integration

PIMPTune communicates with `step-ca` using Smallstep's provisioner JWT authentication scheme. For each new certificate:

1.  A short-lived JWT is constructed, signed with the provisioner's JWK private key. The JWT includes the device's Subject Alternative Names and a SHA-256 fingerprint of the public key from the CSR.
2.  The JWT is submitted to  `step-ca`'s sign endpoint alongside the CSR.
3.  `step-ca`  verifies the JWT signature against the provisioner's registered public key, checks the claims, and if everything is valid, signs and returns the certificate.

The TLS connection to `step-ca` is pinned to the root CA certificate fingerprint provided at startup. If `step-ca`'s TLS certificate doesn't chain to the expected root, the connection is refused.

## Certificate Store

The SQLite database maintains a record of every certificate that has been issued. Each record stores:

-   A SHA-256 hash of the  `(CSR, challenge)`  pair as the primary key, used for deduplication lookups
-   The raw CSR and the issued certificate (both base64-encoded DER)
-   The certificate's expiration time (used for cache invalidation and purging)
-   A flag indicating whether Intune has been successfully notified

The database runs in WAL mode with a single writer connection, which is correct for a service where writes are infrequent (one per enrollment) but reads may be concurrent. A background worker purges certificates that expired more than 24 hours ago, with SQLite busy-error retries to handle any contention with active enrollment writes.

## CRL Endpoint

PIMPTune exposes a CRL (Certificate Revocation List) distribution point at a configurable path (default: `/crl`). When requested, it fetches the current CRL from `step-ca`'s `/1.0/crl` endpoint, parses it to confirm it's a valid CRL, and returns it as a DER-encoded response with the appropriate MIME type. This allows Windows clients and other PKIX-aware systems to check certificate revocation status directly from Step CA.

## Thanks

All the actual heavy lifting here is done by other people's work. Thanks to
the [Smallstep](https://smallstep.com/) team behind
[step-ca](https://smallstep.com/docs/step-ca/), to the
[SQLite](https://www.sqlite.org/) and [Go](https://go.dev/) projects, and to
[GoodiesHQ](https://github.com/GoodiesHQ) (credited above) for the original
code this project builds on.

## Support open source

If this project was useful to you, consider donating to an open-source
project you rely on — most of them run on volunteer time and small
donations. A few of my own favorites:

- [KDE](https://kde.org/donate/)
- [ReactOS](https://reactos.org/donate/)
- [Matrix.org](https://donorbox.org/keep-matrix-exciting) — a free-speech,
  end-to-end encrypted chat protocol
- [LLVM](https://github.com/sponsors/llvm) — the compiler infrastructure
  underneath a huge share of modern software

Both feel especially important to keep funded right now, in these
uncertain times of dark enlightenment.

And if you'd like to help cover this project's own Anthropic API usage, or
support a personal local-inference homelab, that's separate and entirely
optional: [GoFundMe](https://gofund.me/815bb9c26)
