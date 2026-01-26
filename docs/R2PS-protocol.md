# Remote PAKE-Protected Services Protocol (R2PS)

## Abstract

This specification defines the Remote PAKE-Protected Services protocol (R2PS) as a generic protocol for service data exchange between a client and multiple services in a backend services infrastructure.
R2PS provides end-to-end encryption of service data from the client all the way to the backend service and allows separate backend services to exchange data with the client under separate security contexts.

## 1 Introduction

The R2PS protocol is designed to allow less capable clients, such as mobile phone apps, to provide critical services for the client in a secure server environment.

This protocol is generic and can be used to support any client application, but it is developed in particular to support wallet applications that need to meet the EU eIDAS regulation. The primary challenge for eIDAS wallets is that the security requirements imposed on eIDAS require the wallet to operate an HSM protected key. As many mobile phones do not offer this capability, this protocol offers an alternative that provides such HSM capabilities via a remote server over a secure protocol.

However, a remote server is also usable for many other purposes such as

- Common data storage to enable the user to operate the same wallet instance from multiple devices
- Private client data storage
- Audit logging

End-to-end encryption offered by R2PS is designed to meet the following security requirements:

- Encryption of service data uses a session key that provides forward secrecy.
- Cryptographic separation of keys used to encrypt data under different security contexts.

### 1.1 Encryption modes

Encryption of service data supports two defined modes:

- Device-authenticated encryption
- User-authenticated encryption

**Device-authenticated encryption**

Device-authenticated encryption uses ephemeral-static Diffie-Hellman JWE encryption as defined in RFC 7518. 
The client encrypts to the server public key, and the server encrypts to the client public context key.

This encryption mode is used for services that need to be exchanged before a user-authenticated encryption key has been negotiated.
This encryption mode is, for example, used for PAKE service exchanges to negotiate encryption keys bound to the user's PIN for user-authenticated encryption. 

**User-authenticated encryption**

User-authenticated encryption uses an encryption key negotiated through a PAKE key exchange that binds the encryption key to the user's PIN. Depending on the selected PAKE protocol, the encryption key SHOULD also be bound to the client context key as well as the server key pair. The RECOMMENDED configuration is to use OPAQUE in combination with PIN hardening (See 3.3.2).

## 2 Basic structure

R2PS defines a generic and stateless request/response protocol for client-initiated requests to a server infrastructure. Each service request and response includes encrypted service data defined by a service_type identifier, where the format of the service data is defined by the service_type identifier.

A service request also defines a context identifier that specifies the security context for the service data. This allows the server infrastructure to forward the encrypted data to the backend server that handles this context. The backend server that handles a particular context is typically responsible for negotiating the context session key, decrypting the request service data, and encrypting response service data back to the client, providing a true application level end-to-end protected exchange.

The following image illustrates a sample deployment of R2PS where HSM operations are dispatched to a separate HSM server under a unique security context.

```

                                         User
                                          |                             
                                     PIN  |                             
                                          v                             
                             +---------------------------+
                             |          Client           |
                             |                           |
                             |  Context Key Pairs 1..n   |
                             +------------+--------------+
                                          ^
                        R2PS              |
                        Request/Response  |
                                          v
                        +-----------------+-----------------+
                        |      Common Server (BFF)          |
                        |  +----------------------------+   |   context="hsm"
                        |  |        Dispatcher          |--------+
                        |  +----------------------------+   |    |
                        |        |               |          |    |
                        |        V               V          |    |
                        | +------------+  +---------------+ |    |
                        | |  Context   |  |Service Handler| |    |
                        | |PAKE handler|  +---------------+ |    |
                        | +------------+  +---------------+ |    |
                        |                 |Service Handler| |    |
                        |                 +---------------+ |    |
                        +----------+----------+-------------+    |
                                                                 V
                                          +-----------------+-----------------+
                                          |     Backend Server (HSM)          |
                                          |  +----------------------------+   |
                                          |  |        Dispatcher          |   |
                                          |  +----------------------------+   |
                                          |        |               |          |
                                          |        V               V          |
                                          | +------------+  +---------------+ |
                                          | |  Context   |  |Service Handler| |
                                          | |PAKE handler|  +---------------+ |
                  +---------------+       | +------------+  +---------------+ |
                  |      HSM      |<----------------------->|Service Handler| |
                  +---------------+       |                 +---------------+ |
                                          +----------+----------+-------------+

```

Service data under a common security context is dispatched to a suitable service handler for processing based on the service_type identifier.

The Context PAKE (Password Authenticated Key Exchange) handler is a special case service handler that is responsible for authenticating the client and its user and for negotiating a shared session key with the client.

The illustration above is only meant to provide guidance and shows one way to utilize the capabilities of the protocol. It remains an important choice for how this is deployed in practice.

## 3 Protocol

Generic protocol endpoint requirements:

- HTTP POST MUST be supported with Service request bytes as the HTTP request body.
- A successful service responses SHALL be retuned with an HTTP status code of 200. On failure of handling the service request, the server SHALL respond with an error response as defined below.

### 3.1 Service Request and Response

Service requests and service responses have the form of a JWS \[RFC7515\] represented by its compact serialization format. The Payload of the JWS is a JSON object with the defined parameters specified in the following sections.

#### 3.1.1 Common request/response parameters

The following parameters MUST be present in both service requests and service responses:

- `ver` : (**string**) - Holds a version identifier of this protocol. This version of the protocol SHALL be defined by the string "1.0"
- `nonce` : (**byte array**) - A random value that MUST be present in the request and returned in the service response
- `iat` : (**integer**) - Seconds since epoch when this service request or response was created
- `enc` : (**string**) - having the value `user`or `device`, where `user` indicates service data encryption using a PAKE negotiated session key and `device` indicates service data encryption to a device-bound key.
- `data` : (**byte array**) - Service data byte array. This is the bytes of JWE encrypted data using compact serialization.

#### 3.1.2 Service Request

The following parameters MUST be present in service requests in addition to the common request/response parameters:

- `client_id` : (**string**) - The identifier of the client entity. A client entity may reside on multiple devices using different keys on different devices.
- `kid` : (**string**) - Key identifier for the context key used by the client entity on the current device.
- `context` : (**string**) -  The security context under which the request is made
- `type` : (**string**) -  An identifier of the type of service that is requested. The service type determines the structure of the data byte array
- `pake_session_id` (**string**) - An identifier of the pake authenticated session to be used to support encryption of service data. Each pake session holds a unique negotiated session key used to encrypt data.

These parameters collectively give the server the necessary information to;

- route the request to the appropriate resource, 
- retrieve the correct signature validation key and data encryption key, and; 
- correctly parse the service request data.

This is achieved through the provided parameters in the following logical process:

- The `context` identifier is used to route the request to the backend resource that holds the keys necessary to process requests under this security context. E.g. a remote HSM server under a HSM security context.
- The `client_id` is used to retrieve all records associated with a client "account" in the server infrastructure, such as an EU wallet instance.
- The `kid` identifies the client public key used to establish a PAKE session for the current security context. This is by default also the key used to validate the signature on the service request, unless the JWS header specifies another `kid`, or validation key.
- the `pake_session_id` is used to locate an active session holding a session key used to extract the session key used to decrypt service request data.
- The `type` identifies what data that should be obtained as service data after decryption.

A service request SHOULD include the `typ` header parameter having the value `JOSE` (**TBD consider a specific defined typ parameter**).

A service request MUST contain required JWS header parameters as defined in \[RFC7515\]


#### 3.1.3 Service Response

A service response is bound to the service request by providing an identical nonce value. The server MUST ensure that the nonce value from the service request is non-null and provides at least 64 bits of entropy.

A service response MUST include all the common request/response parameters defined above.

A service response MUST NOT include any of the additional service request parameters. These values are already known by the client and bound to the request via the signed nonce.

A service response SHOULD include the `typ` header parameter having the value `JOSE` (TBD consider a specific defined typ parameter).

A service request MUST contain required JWS header parameters as defined in \[RFC7515\]

### 3.2 Error response

If a server for any reason fails to successfully process and respond to a service request, it MUST respond with an appropriate HTTP error code and a structured error response.

The following error response codes are defined:

| Response code            | HTTP response code |
|--------------------------|--------------------|
| ILLEGAL_REQUEST_DATA     | 400                |
| UNAUTHORIZED             | 401                |
| ACCESS_DENIED            | 403                |
| ILLEGAL_STATE            | 409                |
| UNSUPPORTED_REQUEST_TYPE | 415                |
| SERVER_ERROR             | 500                |
| TRY_LATER                | 503                |

The HTTP body MUST return a JSON data string (UTF-8 encoded) with the following parameters:

- `error_code` : (**string**) - The error code from the table above
- `error_message`: (**string**) - A human readable message with details of the cause of the error response

Example error response JSON:
```json
{
  "error_code" : "ACCESS_DENIED",
  "error_message" : "The service type 'hsm_ecdsa' under context 'test' is not supported by any handler"
}
```

### 3.3 PAKE exchanges

PAKE (Password authenticated key exchange) is used to negotiate session keys based on the client's context key and the client's PIN.

PAKE processing is handled through the following service type exchanges:

- `pin_registration` : Identifies a service exchange where the client registers a new PIN code for a particular security context
- `pin_change` : Identifies a service exchange where the client is changing an old PIN to a new PIN
- `authenticate` : Identifiers a service exchange where the client is creating a PAKE session by authenticating the client's PIN and context key.

These service type exchanges SHOULD use the following encryption modes (`enc` parameter value).

- `pin_registration` : `device` - Specifying encryption to a device-bound key.
- `pin_change` : `user` - Specifying that all data is encrypted using a PAKE negotiated session key. The session key MUST be negotiated under the old PIN to ensure that the user has successfully authenticated using the old PIN before any PIN change is allowed.
- `authenticate` : `device` - Specifying encryption to a device-bound key.

#### 3.3.1 PAKE service type data structures

All PAKE service types share common service request and response service data structures. Content requirements and requirements on mandatory or optional use of defined data parameters is specified by the underlying PAKE protocol

##### 3.3.1.1 PAKE service request data structure

The PAKE request data structure includes a JSON string that holds a JSON object with the following parameters:

- `protocol` : (**string**) - Identifier of the PAKE protocol used
- `state` : (**string**) - Identifier of the state of the PAKE protocol
- `authorization` : (**byte array**) - Authorization data for new PIN registrations
- `req` : (**byte array**) - PAKE request data

This document defines the `protocol` identifier `opaque` for the OPAQUE protocol (RFC 9807) in section 3.3.3. Profiles of this specification MAY define other identifiers for other PAKE protocols.

The `authorization` parameter, when sent, contains a value that asserts that the client is authorized to set a PIN for this particular client and context. The process through which this authorization code is agreed between the client and the server is outside the scope of this specification. Examples of such a process could be a one-time code sent to the client through a separate channel or the result of some challenge response algorithm.

##### 3.3.1.2 PAKE service response data structure

The PAKE response data structure includes a JSON string that holds a JSON object with the following parameters:

- `pake_session_id` (**string**) - The session identifier of a created PAKE session
- `resp` (**byte array**) - The PAKE response data for the identified state
- `msg` (**string**) - Message

#### 3.3.2 PIN Hardening

Implementations of this protocol SHOULD use PIN hardening to create strong cryptographic separation between different security contexts and to increase protection against off-line PIN guessing attacks by the server when using low-entropy user passwords/PINs. The choice of using PIN hardening remains, however, an implementer's choice based on the security requirements on the system that implements the protocol.

It should be noted that any attempt to establish a PAKE session using the wrong context key will fail as all PAKE requests are signed by the context key. This will cause any attempt to establish a PAKE shared key using an unauthorized context to fail due to signature validation failure. With PIN-hardening, however, the actual PAKE PIN verification is guaranteed to fail due to PIN mismatch, providing a stronger cryptographic separation.

Any PIN hardening algorithm can be selected without effecting interoperability as long as:

- The PIN hardening algorithm is deterministic and produces the same hardened PIN for a given PIN and context key pair.
- The same PIN hardening algorithm is used for authentication used during PIN registration.
- PIN hardening is influenced by the private context key used in the PAKE process

The following PIN hardening algorithm is recommended:

> Hardened PIN = HKDF (Diffie-Hellman(context private key, hash2Curve(PIN)))

hash2Curve(PIN) is defined in [RFC 9380]. This algorithm guarantees constant time and uniform distribution. However, a simpler hashing method without these properties could be used to simplify client implementations.

**Note** that hash2Curve is used also in the OPRF [RFC 9497] evaluation process of OPAQUE. It is recommended to use RFC 9380 here, as mandated by the OPAQUE [RFC TBD - Under publication] standard. Other simpler methods could be used, but this does require careful security analysis to ensure that the end protocol implementation meets necessary security goals. This is relevant in particular for requirements on constant time execution and requirements on random distribution of hash result bytes.


#### 3.3.3 OPAQUE as PAKE protocol

OPAQUE [RFC TBD - Under publication] when used as the PAKE protocol is identified by the protocol identifier `opaque`.

OPAQUE uses the following defined state identifiers:

- `evaluate` - Identifies the initial server evaluation state where the server evaluates the blinded OPRF data.
- `finalize` - Identifies the final state where PIN registration or authentication is finalized.

When OPAQUE is used for PIN registration, the `evaluate` state exchanges the registration request and registration response, while the `finalize` state is used to exchange the registration record as per section 3.2 of OPAQUE [RFC TBD].

When OPAQUE is used for authenticated key exchange (authentication), the `evaluate` state exchanges "AKE message 1" and "AKE message 2" and the `finalize` state exchanges "AKE message 3" as per section 3.3 of OPAQUE [RFC TBD].

##### 3.3.3.1 OPAQUE PIN registration exchange

WHen OPAQUE is used for PIN registration, the following structured JSON data is sent in the data parameter of the main protocol:

**Evaluate request:**

- `protocol` : "opaque"
- `state` : "evaluate"
- `req` : Registration request bytes

**Evaluate response:**

- `resp` : The registration response bytes

**Finalize request:**

- `protocol` : "opaque"
- `state` : "finalize"
- `authorization` : Authorization data on initial PIN registration requests, null on PIN change
- `req` : Registration record bytes

**Finalize response:**

- `msg` : The string "OK" if the registration record was accepted

---

The registration process of OPAQUE is stateless in the sense that the server does not store any information from the `evaluate` exchange. The client just uses this initial exchange to calculate the registration record sent in the `finalize` state. This is why the authorization parameter MUST be sent under the `finalize` state on initial PIN registration.

The authorization parameter contains authorization data exchanged between the server and the client by means outside of this protocol, such as a PIN reset code via mail or QR code.

The authorization code is not sent on PIN change, as the data parameter is sent encrypted under the old PIN session key (see the section below on PIN change).

**Exchange example:**

Service request - evaluate:

```json
{
  "ver" : "1.0",
  "nonce" : "b8b3b44c098eff93abccd94e27c06488465af1584c887946946c25f3dae89615",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKWVIzUkxka2d3YzBsc1JreDZaVWsyTlVKYWVqbHRZbFpYYUZkR09IQkhieTA0Y0ZOR1NtY3hURWxaSWl3aWVTSTZJbll3Y1V0Q1kyeGphVTVCYkUxWWEzZHZYMHczWVRRMFIyVjFRVEJIYnpkb1dteEVWVlJmUnkxUlNHTWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLktiNkRhQ2dOd2pfSmEwUkkuVzRpYi1tQllqWXdBTldrWmdlSmJ3ZWlIUFg3aEs3cTFBOWVvR3Q3eXJfUWU3ZFhZMzloX21hQ3ZpZVZ2STdyamF4R0FoVDRLdm1QcFJmQnhoX0hKTWUzTkQxcTdoeWZZZkFQblFXbnVFV2lWSUZzUE94MzJKVk9Sa3pObi5kTUlOM1Q2UFNFbUx5Y3JKU2tSbElR",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
  "context" : "hsm",
  "type" : "pin_registration"
}
```

Parsed and decrypted data content
```json
{
  "protocol" : "opaque",
  "state" : "evaluate",
  "req" : "A2VhN509hDBZqjH+1eX8zMxTNjgUGelYGUUjs5raLmAa"
}
```

Service response - evaluate:

```json
{
  "ver" : "1.0",
  "nonce" : "b8b3b44c098eff93abccd94e27c06488465af1584c887946946c25f3dae89615",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lJMlVscEtVVkZpTldKMFVrSjZSMVpyYWpSdGNERjNhakpDTjA5Mk9XdDFZa2RsVVdNeU9IVmhaMUJGSWl3aWVTSTZJbUZKVkRWbWFHVnBUVFJCY21zeGRua3hXblF3YlRSS1NWQllUMGRrY21kMlMyUnBabEptWHpKQ1lrRWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLjdVbkk1ZmJ6WlFfTmVnMHkuTk9kY2wzUWE3MDAtYjdEeHV0d2UtelVKLTE0Z2lhamJyWEtsYTFaanJrb1d3U0VFaDhjWW40VEhxb0RFNkFyX194MTBIY2VYNEVEREd1emJqNGZSS25qTy02Tms3MmFJZHpVSnl1QkFwNThVRWNrWWhNMjduMkM3dFVLbXhrR0tvb0c5Lnp2WDY1WW11MHRPd2xLS1Fmd3phTlE="
}
```

Parsed data content
```json
{
  "resp" : "A/O9ULDVsOAmUnEqypBsO2f8qLL6gjkxTMn3itCfdEgUAtq6rBdVXhCVNy4BV6lOTOKkjV/KshjUVheUB/ctmAA3"
}
```

Service request - finalize:

```json
{
  "ver" : "1.0",
  "nonce" : "5b869f34b41fe762f2c9977aadfe8fdb78073fed1558a38e02bd95fa322b4149",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lJeFJ6Y3dTelJWVXpseFFUZFNRWEk0YUhsTlJGOTNNM3B1TW5waVFWSlpOV3hSWTJoTVUxVndVMGxuSWl3aWVTSTZJbXB1VjJWeWNrNHdjM3BPV25ZNFdXSXhMVTQxVUZSNGFHRlZjR1JmYzFOeGVGUTFkbGhJU0ZCeUxXTWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLklpX21DazZ5UTNLc3FYbzAuMnBDblZObWNBa3hVZTRuM291MnRJVkhxSFc3MnhrYlBLdExFc3NlMkVZZ29fUU9OdjdKNjlySzFJQmVNTDFpYlo3RklMdzNJZ0JycjlQSEZpbE1fY3RUREgydDNYajB0YjM1cUNNV1N2bTRwWTRKQkZaeHR3V2ZGU1hJcHlsVGFuUk1uQ2FEeE9yU0FmVEVEV1JnNnF1TGYwMVRNRXJ6S05MN3dEVjBMMWpYSEVMVGk1ejI5WTZCajJHOWJpNWpKbWc1VVAyUHFkYmI5MmxoVl9OUWhBZ2hPT1B3R21wMEtaaDBySFJfZURGRDd1THhPaFROTXRaTFVFQ0NOMDEzTWRSV2RSWV9jaldjaXhlMUN1TVpNbE91VkdYOWNzVlpHSHd3aWZRVnBlLV8wb2lXWTFsNURTNmNzdTM5bFBlUTNyclVxc1VBQjRMZTRub1ZDLmlRNFYwc1hMM09wbHdvSEJobXNaaGc=",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
  "context" : "hsm",
  "type" : "pin_registration"
}
```

Parsed data content
```json
{
  "protocol" : "opaque",
  "state" : "finalize",
  "authorization" : "OTg3NjU0MzIx",
  "req" : "A2gjTwAIFoD62qTbFPuIwSS96w7CTfsHlnLZOlsdKuBFKwLBZYFbhLrE2tTbZ9qZfxuRADrEUfMdVOf3l4cCtVyPMMZbKMncJQByKEyquVuT3hjF19fpacbgB11zyvG7IT3BqTZo84ThAAQWPmybdl1ZPuxlaMr6kYknKJgmmQOn"
}
```

Service response - finalize:

```json
{
  "ver" : "1.0",
  "nonce" : "5b869f34b41fe762f2c9977aadfe8fdb78073fed1558a38e02bd95fa322b4149",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKblFUbFhRMVJzZFRGWldDMVBlR294V25CWFVFZEtXVEJKTjNweFMwbHlXRGg2YldkT1dWTnVRVFJ2SWl3aWVTSTZJbUZSZURKbVRtWnVkbmxqZGpkdlVHdDZjek53YlMxNGNXaE5ObkYwWDIxUFQxSmFOek53Wkc5U2RFMGlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLjRoa19fTHJzMzFQODIwM3QuR095VW5VS2dMOXEtdWlMUi5Tb2JTc2ZGaTNIeFlDM2FyWHItd2Vn"
}
```

Parsed data content
```json
{
  "msg" : "OK"
}
```


##### 3.3.3.2 OPAQUE authentication (Create session with a session key)

WHen OPAQUE is used for authentication, the following structured JSON data is sent in the data parameter of the main protocol:

**Evaluate request:**

- `protocol` : "opaque"
- `state` : "evaluate"
- `req` : AKE message 1 (KE1) bytes

**Evaluate response:**

- `pake_session_id` : Session identifier of the PAKE session being created
- `resp` : AKE message 2 (KE2) bytes

**Finalize request:**

- `protocol` : "opaque"
- `state` : "finalize"
- `req` : AKE message 3 (KE3) bytes

**Finalize response:**

- `msg` : The string "OK" if authentication was successful

---

The authentication process of OPAQUE has state in the sense that the client and server store data from the `evaluate` exchange that is used in the `finalize` exchange. This is why the `pake_session_id` is returned already in the `evaluate` state exchange. This `pake_session_id` MUST then be returned to the server in the `finalize` exchange as a reference to the associated `evaluate` exchange.

**Exchange example:**

Service request - evaluate:

```json
{
  "ver" : "1.0",
  "nonce" : "45c38e7db0993b35210f5cb05b73dc33fe9dd855ad32e2c641dd0e28b943961c",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKaVR6VktiSEpPUzNWbFR5MWFhVmMxVWpWdE9GaG9NRXRZZUhoeE56ZFVUbTU0TUZVd2NXeHpZV2xWSWl3aWVTSTZJblJJWm5WSWNIWTJlblZuT0hKbE9XOVVNWEUxVERWUGRXaDBNV3B1Y21kS1UyVnZWMWhYWTNGR2VXTWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLnhWUjBPWndiM2VMRVRuNkwuTG9QUTdVdmdKQ1pNWlRpSW4wRF9yNHdKSi0yNUY5bWQ5S0JfQUpFX3BDVzJpUEZRSkdNYnZFSVpTMmZ1dHRSS0RzUkhPOGZ4X3Mydnktb05KTUlHZjVScmR0YWlTdHJTeEhWY21BajU4M2dPTGNSMzM1RFRYQXF4Tk01OXNyeG8tUWRsYlFqZ05xMVNPU3dTLXVRR0JPTGx0d1cyYXBZbHpwUmhDc3d5SkpuQktlWEVORDhNLWhydXBVUUwxWjJmS1VOVklFaFFhaEJRSUE5VWl5aWxnVllVVmhDcTVHelRSSTlrNzRDeFBaeWRZTmdVbWcudE1JUDNYVFF5clhQX0tPbEVOMlRxdw==",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "authenticate"
}
```

Parsed data content
```json
{
  "protocol" : "opaque",
  "state" : "evaluate",
  "req" : "Ayw6J1aUYVxAbQVbl5Y5siT8ikF/FRJntNyxqnsGgFvYdlz+y65eL4Q8THF6bYwmebqC3t6Q/EqvSInVtgojyIYDoFTmpNYccKUgfDG9PhHo4KvfRSW799HOXhGZWkL71As="
}
```

Service response - evaluate:

```json
{
  "ver" : "1.0",
  "nonce" : "45c38e7db0993b35210f5cb05b73dc33fe9dd855ad32e2c641dd0e28b943961c",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKbFNFSmhUa1JCUVVaSmEyOWhaMk5TVlUweFpsbFFTQzE1VDFkWWJISnJZbEpxZEVSbmVHYzViMEp6SWl3aWVTSTZJakJOZG1OS04yMTFhMGh2YUU1c01WRnNZa0ZYVTNaNGNHWjZRa0l3T1ZKUk5qQXhPV2RpUTNkS2JXOGlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLjIxeFpCV2JWR216UVkyNXYua2lxVXU0UEVqU3BlYVFoazFHTmh3N2w0eEZEUnNsc3JVWmVVTy1uNU41NlB5V3Jvb0NXcGFGbV9XbDEwb3BjQnhrYmxHbDlicE8xb1VodEc0R3ZoM1liR2xQMWVNQUMySXhKdkduekxuT3VGa3pMZ1dJMGVVMDEwWUZDN0J5N19qNDY2VThYVEtvTzNjMHpKWGx5NGJGNnVkRlYwNVZYRmRobzFnS04zeHVBUFVPVEp2MnM4eUxwMFlhaVJmd0Y3SEpfWXptRm85YUF1OGpVWXo0R2ZEbmJ2Tnc4YWtvd1BUWVM4NTVmU0FrVDJRQWFURVhQdFczZjZQMWZqaFNQWTB5NU5TRkhpRFdGSTJaS3A0bzFFVm5GOXI0NDBkUjBIT3Rwbkx5OU9NeldZNUotbHEzRU9uUExLbUtiQkxmc2tId0VydC1HYVVEWW5BQ2dDbno4d3FPUkNTWVVGUTNNbzNMaWJ1Zko3SXhWUXN3cjhDWmNuM0NFUTAxZ1BwLWdYeGIweXBuNFR4NGpCOG1EY1NFenFJQ2dtUGVPN29fNmdmb2Nrd3ZEcjVTaGRzakJhdWVjaktnS2lWc0YzRVo3Vmh0cl9tTmQ2Y1hjVE1XaWtrd0hjQzZuMVZnZzJWSXByczR2ZmZhSF96Wm4tSzV4c3BXY2lDNTIxb0dHMGNYZGt5UnpKYkJkR0dYcnYzdEF0OXNISUV3OHJ4Z2x4dlA4OHkteGFZLTlLa3d5VWtBS3Z3MW9HWkI1LWhudEFnY2RCUjlzdHVzN1gwb2V4NmxuYy4tYmdsci0yWnhLcDFUQnk1Y3FBSDN3"
}
```

Parsed data content
```json
{
  "pake_session_id" : "1332f2c7b64c8eb2c2f2c95bca4d71988badc2cac351408af78ac6a4552a56cd",
  "resp" : "A0HE/aHekqoVZotwnR4ZlHH1VRIeKi1EuZ5Nb4uS9DuRBSv2dq6/eYWoMcV3yEwO9sBv5qG+wpuvTQ0+pIJ6xJUeAI2pqHdWFTWS8IfgwSyu2t/bJJTELvbZllKSRyl86dIkTrQwxtilUKob0NkMvBLUrOfBnVGblU0AMJPqYD7LRoQrOmAEecduVxlnypMmEo6UHyinprjOpgUF9auhuopgb0W0gbc0/YtLCAIAK1Cf0C0tuH+o0X5T4PLl+tPzi3wC5k+90ZWRKzFS5ZCuhT7tF9rbOvCRYBxHFIw/HATuJOv4/x05g02evdMY/wQtZaKPUlQYRIlAEN5Cjg/bWYMbqw=="
}
```

Service request - finalize:

```json
{
  "ver" : "1.0",
  "nonce" : "1207c42b0702b6de3c95dc2248213156932c4c125a8cd215d54a58386d8b8fd3",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKU2NUbFJOMDFpWnkxUk5IVkZURjlUTkVoSFVWRTJZbkF6V2tRNFN6aEZWR2hhZFZGTVRXeDJjRE5aSWl3aWVTSTZJamhhU201SlQyZGFRV1J0ZVdoRmEzZHZlR3d4VWtodmVFbG1OV2RqVVRrd2JIb3hSWE5QZVMwM1RtY2lmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLmR1S2xVYThyRTgySU9LSzcuaXB1azBTUjVIbUVZd25ieF9WTUFUb20xODVlWXJMb2FBZXZ0N0F3SEYtYXpOV0RFSzc4QXZCLUpyTWxRTTdBNUZ6SDFtblFHN2VJVEtyc1FZUzFzMjc5cXY1cktjbGZuN3lHRjZpdG5rd1NaaWhnY1FVMlo3a242MDRSdS53b3NVUUk5d3lPVDh2UmEyNWY1ZE1n",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "authenticate",
  "pake_session_id" : "1332f2c7b64c8eb2c2f2c95bca4d71988badc2cac351408af78ac6a4552a56cd"
}
```

Parsed data content
```json
{
  "protocol" : "opaque",
  "state" : "finalize",
  "req" : "rs7OM+/ZCMoWIkisEiWJhzc7rD97BCZYfsCBj5V4J5A="
}
```

Service response - finalize:

```json
{
  "ver" : "1.0",
  "nonce" : "1207c42b0702b6de3c95dc2248213156932c4c125a8cd215d54a58386d8b8fd3",
  "iat" : 1753970875,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lJeFdqaG9aV2c1YWpVd2JqVTBUbVZHVDE5VmExOVFOVzlmU1dsRFozQmtSR1pCTlcwdFIxTjFVM0ZySWl3aWVTSTZJbmczVkZOeVQzVkNjWEZIT0RKQ1JXUnhkVFZXVVhFd1RtWndZVU5mZUhWMGRITjNXVU01T0hsR1VrMGlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLlZBUU15SFFwR3ZJS2Z4YlMuSmlZUzJSRHZkWk91dEFaVy4wNzloYjJqZWN1YUZ3Z2I1N1U5aXNB"
}
```

Parsed data content
```json
{
  "msg" : "OK"
}
```


##### 3.3.3.3 OPAQUE PIN change

PIN change is done using the following steps:

- A new PAKE session is created under the old PIN
- A PIN change (new PIN registration) exchange is made encrypted under the session key created under the Old PIN.

Once this is complete, a normal operation would then be to invalidate the session under the old PIN and to create a new session under the new PIN. This is not illustrated in the example below.

**Example of a complete PIN change exchange:**

Authenticate with old PIN - evaluate request

```json
{
  "ver" : "1.0",
  "nonce" : "4d113cb59e52304226a4d6c4c110c2a68680c784d097a1d6284037bd93dadc8d",
  "iat" : 1754008895,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKSWRYWldaRGRCUlZka1drbEdlVWRsZG1FMlkyTklTeTFXVWt0clVIVXliSGxrU1V4TmFqQTFlVVJGSWl3aWVTSTZJbVJ2VFhOdUxWWlBiRVZ2Y1dSd04yVnliMkpVZDFWVmMwMDNTSGxpVjFsSE1sZHlNME14ZVZSVlNYTWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLjBBZFZvMGxLbExSS01sQzcuVjZyU0h1WngtLWN4N2hrQ3g3aFgya2JVZENOWDUyTno0UXF1ZHJNV19nMEtiY0FMOVQyclBHc0tKdExrOU1LUlhVV1p3TjNMN1FaTjhkSGs1a2E2Y0I5Zml0U1NHcFZJdl9aNC0tdHNWUkhqbnI4MjBmVkxmUU1faHNfNDZYRFg3ZUt0UUVVT2IzZkVSYmRYVjJhQTMwcVVJUy1ud01xVzJneWNXUUZEOE1ma3pNb3ZlZThiY3otVlF5QWVQaFF2YW9GRTZMWGVIWERyM0FoY2NJcUo0OGhZVEgtRDdzSmJmYUJfd3I1OE1rV3lRY240bEEucE5PT1Iwd0tGQzk3VUVRclNxYzh3dw==",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "authenticate"
}
```

Parsed data content
```json
{
  "protocol" : "opaque",
  "state" : "evaluate",
  "req" : "A4OKak5KWXH3exxZbYWNu56TSJLLihak3VADkdrm/ZFQojL6Ptcb8v1ha/1+/UuFdr+S84litnM0ci97VsiyN4YCXnUzLQrBMXOzfyDN7omWzF2SVh3Q56Qq3IPLcULwImA="
}
```

Authenticate with old PIN - evaluate response

```json
{
  "ver" : "1.0",
  "nonce" : "4d113cb59e52304226a4d6c4c110c2a68680c784d097a1d6284037bd93dadc8d",
  "iat" : 1754008895,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lKamJucEJjM1V6WWtWcGFtSkZNRk5NTVd4dGNWQmpVRFV5VWpCUGFubFJUelI2VlVOUGEzQlhPR2xSSWl3aWVTSTZJa3R4V21KNWFVSlpjVlJ0ZG0xTWVqZHlhbEJPTVU1TE5teENRVUUzWTI0eWNXZDFjalpDZDFwTGJuTWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLkpCYmo1NlRpeXYzSGRhOXguUWdhN1ZFMHdsUWRNVkI3Z2VDdkdYWXhvUTVUSm5yUWJLbGZQQVZKZy1uVy0ya3hTeGlDT3N2YjNaaUhwVmF1LWNZcVEtLVJDcmdvUElvUHp0M1hfaUFhNkZSeFVDbkh1TzBfeVN3UFhsalF0MlkzXzNxRWV5S0E2aXVKNi1HVHZpYTgtaHFJUGxWcWxSY0xQTnNsVnlqZ0c5eEZfUGZZZFdZMDBMUzRabFRZeTdLZDJPS0RrSldLeC1tZ2pxUTRtY3MtWUlzcjRObG1oaGIxVzZ4QTFua0U5QTM3dF9hMWZ3VlNoeDVxWmhJSm1yc0ZjSTliYzI0cnFocFpmdnFoc3BTdnJTaG1ldnFOLTNSYkdQX2FnUV9nei03aUpVTzZaWHliSWxKc251bmdFS2RtbXVGYThTQ3VFcDBEaFgtTUxEYVhVZlQtOVpDeWxGR1lMSGMyN0lUS3NMeER3UlhGdDVMM2dITWoyVHdBbjFpYjkyRDBDN3ZjWnMtaXM5Sk43X2RraUlRLTVJZWpRTUNrN0JpX3d5VzViMXNhcUctbEM0TVFad21FalhJd2MwVXdoX25MSl91QmZvRmZWRUVZNFdHcWVxXy0xX0hYanhQNWRKSnZzLThSS19vc3ZVZzVQM0hLSm9hMHc5a245YUo0R2syWkFCVl9BMDJFczcyVUVjMU1xTTFFZTllWHdPRkNsUWFyWDNjd3lpd2pQV2d4NzhpNDlQM2pFcE9JTk9SaUlUN2hzekNKamJJRmJ0LWRBWnFqRkl4Z1J0a0tRWDZNVi5MM0ZUTS1SenFjOUtZaTdDWEVzNEN3"
}
```

Parsed data content
```json
{
  "pake_session_id" : "6fe6e2c0bb0fe89d426783b2d78cd416b379452330dba758172d013d4a4e0508",
  "resp" : "A/KBWT8RocPPJEA3uQF+gq+amHLDgiqy8ouBHqDsAxE3CnmLT90psJ7ua/eqsBaUWSRxwlR5Z0FGLQ8uw/CVFwY/kdYMP5WJ/ZCoj9sPerF9bW2zPXztq1Gs/LvghMm8xWLwjneGMFseRel8HmGQjiG15uCDrgIwoKR9CIzIvu3IraofBaWbHjT4nEVS4CadSaOnRlT4akyySHUhe21ZmPfHYpjqoaRwKeFoJcWYc8yQhjzExV1Q9OcBkGqzMMM6PeMD58cU4UHRur4sCRNDJvNAiwP48TrtCxh94U8ILy21a/ZdgveeA7p5QGPup8L8HU/xIFYoFp8N5qzNUpDFcbL86A=="
}
```

Authenticate with old PIN - finalize request

```json
{
  "ver" : "1.0",
  "nonce" : "a652648d3498e31c0747b0c1536b98c8aadf59f7cb7bd528ad527f05f395511c",
  "iat" : 1754008895,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lJeFVXVlRVM05KZWtRNGMycElOM0V6UlVwc2JXRkJhbXRFYlZFNWJWVTViVnB5TUUxVVpXcE1SeTFqSWl3aWVTSTZJa1pGV1RoTmNEUmtSa2xwZVZSd2FFaHRPVmxTTTNWR1NGazBXVkpwYTA5SVRrZHRXWE4zUVdRNU4xVWlmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLkFSbFlkNFVFdUxITEtELTIuNk03RDJKM2w3S0hfb3kxdDBpZ3BPbVZpaFo0SlhvRHFBeFVFd0JmZmtobm5jNlFaWl9UTGtSQ0x6ODlKdl85LXR2RGtnVjQ3V3czRERmNXdQYm9Md2lSRGZqd0VzWnFjVjZxaVlJMndSak9tcUhYZUttUjNNb2V3Ui1MVi5FR1doTHNSdTBTUGRFUXRKWm5oNEdB",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "authenticate",
  "pake_session_id" : "6fe6e2c0bb0fe89d426783b2d78cd416b379452330dba758172d013d4a4e0508"
}
```

Parsed data content
```json
{
  "protocol" : "opaque",
  "state" : "finalize",
  "req" : "+zoSyAQJMXXzDYP2NA6s9vIHrih4BWhxUDVLl904r/0="
}
```

Authenticate with old PIN - finalize response

```json
{
  "ver" : "1.0",
  "nonce" : "a652648d3498e31c0747b0c1536b98c8aadf59f7cb7bd528ad527f05f395511c",
  "iat" : 1754008895,
  "enc" : "device",
  "data" : "ZXlKbGNHc2lPbnNpYTNSNUlqb2lSVU1pTENKamNuWWlPaUpRTFRJMU5pSXNJbmdpT2lJNVFUUnplVWRxYmxwa2RYWlNWSGxyT1hsdVFrSmpibE5EYkhoeVlVWlZSRTlTTUhKUFdXWkJja3h6SWl3aWVTSTZJbGRLY1hoTlpXdHZSbVJTTkdaSlFuRk5aMUpxVFhKMlZEZzNRVVprVDBsQ2VsaFZVWFJaY25NdFMyc2lmU3dpWTNSNUlqb2lZWEJ3YkdsallYUnBiMjR2YjJOMFpYUXRjM1J5WldGdElpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltRnNaeUk2SWtWRFJFZ3RSVk1pZlEuLlVWSm56TnlJZXgwQ0J3dUsuYUh3Z0pnRnQ4QnNpTGQ5My5sVUtkLU1iTVlLNmN4elk1eVJNWHN3"
}
```

Parsed data content
```json
{
  "msg" : "OK"
}
```

---

Change PIN - evaluate request

```json
{
  "ver" : "1.0",
  "nonce" : "23006c6ed0403beec7ef4b85f884f26553087f67a4a96d543a63eca1e75b5d8b",
  "iat" : 1754008895,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5nQk5Bb0dWM2FiZzFGNDFrLjlLcl9XWm5ydS1aemREUWtGdERTUk5BVmlUcmpTbDB6SWhINnlEQ01WbHFOblJ1UVV2Sk5kdDNOb0xfWVNvU19LUjEwQzVMOW9ZOHBvdFBfUlF1NGtfZ2J1VlRIYzdUR2EyTVRwYk5LdDh0MUJ4eS05eHJxRk5KUktoeUsuSlA0dXcxbVZBUlVTTWhHMVd4N2tGQQ==",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "pin_change",
  "pake_session_id" : "6fe6e2c0bb0fe89d426783b2d78cd416b379452330dba758172d013d4a4e0508"
}
```

Decrypted JWE data payload
```json
{
  "protocol" : "opaque",
  "state" : "evaluate",
  "req" : "Al6xR/ilUyThC6Ymk+l40xgUJXh9i0FyCx0u/obhykyp"
}
```

Change PIN - evaluate response

```json
{
  "ver" : "1.0",
  "nonce" : "23006c6ed0403beec7ef4b85f884f26553087f67a4a96d543a63eca1e75b5d8b",
  "iat" : 1754008895,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5nM3J5VmtYX2JydXc4NnRTLk95RjZObFJPQ0FVOE5lWkp4SXRCLWFNTURMN0hoeUxGek5QNVBwcEZQQ2hXWFo4anQ2RmF0SVVEVVhhTlpkR1lCSHRvYU1tbzMybzBOejdwbVVKNy1XM1Nld2V2SUthVEZUNGIydnNiQnNJVkFuaGdWNmN0dE1GMUxpXzg5UVZRMTZXQy5fenFUb2pfMjV5dVdFNm01VXJEenhn"
}
```

Decrypted JWE data payload
```json
{
  "resp" : "As8r8bLemY0xNb48L7gPAoSwSo0qLSc5q6eMXZhJ25C9Atq6rBdVXhCVNy4BV6lOTOKkjV/KshjUVheUB/ctmAA3"
}
```

Change PIN - finalize request

```json
{
  "ver" : "1.0",
  "nonce" : "e1502315b756a6c5b8ec791d6fa03a2828a77964d0ed479375f15a4d03ec8365",
  "iat" : 1754008895,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5BZVUtTVE1YUlYa1JiSzZoLmZBNjFJT2g1aWpyR0V4dHh0endZTk1JYlVwd0NJNWJFMDFCMmVNV0NYdzBuM3kwbkZDM2I1QTRvWGZKZnJxek8zVFBoWGJra2h5RWUwT0UyZjQtNnBUYnIwbFNXM1pFWHZua0pJZGxMdVlRSjltUmxIQXpvOWpEVzljYzh1TzlCZnNyY0s4Q3hMR05hSFRkeEVxR0dFODZack9CU29ZRGhlb1RhLVdWVnhqY2JROFRvWG5XREU2cGZYYzVZSTVXczNBM0NMZzVEaXowTzBjTm14YzM2MTZzRmRIZWh1czVyYjBpTzQ4VXZ0VlBlT096c043ejYzYktrNFJSSkFMbnpENnlyMG56ZHRtdnByZkllWVc2cFlkaHdNU1dRUDdremlBcEJaS28uTHpSX083bF95dERFb1h2WVVtdndMQQ==",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "A06RIGh7ANlE20pJ+4SW9yn765QDG/qe9eRsP6ucdNWY",
  "context" : "test",
  "type" : "pin_change",
  "pake_session_id" : "6fe6e2c0bb0fe89d426783b2d78cd416b379452330dba758172d013d4a4e0508"
}
```

Decrypted JWE data payload
```json
{
  "protocol" : "opaque",
  "state" : "finalize",
  "req" : "A+8GixDWn9UOsMwe4HkVgdcxddqaS92zfSf5+HthiJpfPRtEeUAI9yl6ZysfIrUtswVza33C3tv9mlPpYYdX86+3kaStNPZ5YkYIlISyfRMivt1ZegRzTyDZIn2q/E08PwnnAWG42a6C1ZdewvUqiNeTPVRZ31sxTGTx4cf8Cjh9"
}
```

Change PIN - finalize response

```json
{
  "ver" : "1.0",
  "nonce" : "e1502315b756a6c5b8ec791d6fa03a2828a77964d0ed479375f15a4d03ec8365",
  "iat" : 1754008895,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi53bWpQb0pPUHNPcHBld21uLlJaNFdOTlh6eklJdS1fQzEuNFlieTBvd3FBSzRlNnozRkVCejVnZw=="
}
```

Decrypted JWE data payload
```json
{
  "msg" : "OK"
}
```


## 4 Service type definitions

This base profile only defines service types for PIN registration, PIN change, and PAKE authentication, providing the basic platform for creating encrypted session exchange.

Profiles of this document can define any number of service types and the data structures that are communicated under within each service type exchange.

Each service type MUST define the following:

- The identifier of the service type
- The data structures that are exchanged (requests and responses)
- The encryption mode used to encrypt service data.

A server that receives service data encrypted under the wrong mode MUST reject the service request with the error UNAUTHORIZED.

# Appendix A: Guidance on security context usage

Informational

## A.1 Separation of security context

The security context as defined in this specification is a versatile tool that presents options for the deployment infrastructure. How this tool is used is entirely up to the implementer. This section offers some guidance on the rationale for this design and for what purpose it was intended.

A typical use case for security context separation is if a particular process is:

1) Subject to separate security evaluation and/or certification
2) Requires separate PIN verification (such as a signing process)

**Use-case: Remote HSM**

When a wallet application needs certification against requirements to use an HSM protected key, then it would be suitable to execute all HSM operations under a separate security context. This enforces that only the client application resource that has access to the "HSM" client context key can create a secure session under that context and successfully request operations on the HSM protected keys.

**Use-case: Signing process with separate PIN validation**

This is applicable when the usage of a dedicated signing key requires PIN validation for each instance of usage. This can be achieved by a unique security context in combination with a service handler policy that imposes restrictions on services handled in a session under that context. Such a context-dependent service handler policy could be:

1) This context restricts usage of a particular key
2) A service request must be received at a maximum time after session creation
3) A context session is deleted after one service operation (with the designated key).

## A.2 Cryptographic separation between security contexts

A security context, when implemented as intended, offers cryptographic separation between services that are offered under different contexts. It remains an implementer's choice whether each context uses separate context keys or separate user PINs or both. The design is intended to allow usage of the same PIN, for the best user experience, while using separate context keys as the means to achieve cryptographic separation of session keys.

Whether cryptographic separation is achieved is ultimately decided by the choice of PIN hardening and the choice of PAKE protocol. The design goal above is met when OPAQUE is used and further reinforced by PIN hardening.

## A.3 Supporting multiple devices for a common client ID

The protocol supports when a client is made available on multiple devices under a common client ID. This could be the case if the same wallet instance is made available to a user on multiple devices but still shares the same data, attestations, and history.

This is enabled by allowing a common context to use more than one context key, where each device can generate and register its own unique context key on each device, thus avoiding distribution of private keys between devices.

This feature is enabled by the `kid` parameter in service requests, informing the server of which key that will be used under this context to negotiate a PAKE session.

However, sharing the same context key may also be desired, in particular when OPAQUE is used as the PAKE protocol. OPAQUE also outputs a static client storage key. The client can use this key across multiple sessions to encrypt data to be stored on the server in a way that ensures that the server can never decrypt or access this data. However, in this case, we do want multiple devices to extract the same storage key, which requires a context key that is shared among the devices.

This is another reason why it is desired to have separate security contexts. While secure services, e.g. HSM key operations, use separate per-device context keys; user storage can be handled by another separate security context using a device-shared context key.