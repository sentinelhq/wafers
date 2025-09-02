# Wafers

*A fast, offline-delegable capability token with layered caveats that lets you delegate safely across third-party services*

### What are Wafers?

**Wafers are portable capability tokens you can restrict and pass along**. Each Wafer carries identity (who it’s on behalf of), a cryptographic attestation chain of who was allowed to extend it, and an explicit description of what the token is allowed to do (the actions it permits, with specific limits like time, scope, or location).

If a JWT tells a system who you are, a Wafer tells it *who this request is on behalf of* and *exactly what it can do*. You can delegate a Wafer to a third party with stricter limits each time. For example, if you hold an admin-level Wafer for GitHub; you can a narrower Wafer that permits read-only access to one repository for 15 minutes and hand it to an AI agent reviewing a PR. Later, you can issue a different Wafer that allows merge on that PR.

As a Wafer is delegated, each holder adds caveats that only reduce what’s permitted and may hand it to the next holder. The result is a clear, auditable chain of custody with permissions that become more precise over time. 

Wafers don’t replace your authorization stack. They’re engine-agnostic and play nicely with policy engines like Cedar, OPA/Rego or Zanzibar-style systems.

### How do they work

A Wafer is issued (*baked*) by a service (the issuer). It includes a unique ID, expiry date and the issuer's public key. The issuer keeps a private root key linked to the wafer. A Wafer grows by appending `Layers` and `Holders`. Optionally, the issuer signs this header (ID/Expiry), so intermediaries (e.g., Cloudflare) can verify the wafer was issued by the service before forwarding a request (instead of `Web Bot Auth`)

Layers carry the rules (what restrictions apply to the token) while holders record the delegation chain (who was allowed to extend it, in what order).

After a Wafer is issued, the current holder may add one Layer: a short list of actions and limits (time window, scope, region, repo, etc.). The Layer is then sealed with a tiny cryptographic tag. That seal is verifiable by the issuer and makes the Layer append-only and tamper-evident. Layers only narrow what’s allowed.

Optionally, the current holder links the next public key. That ties the freshly sealed head to the next holder and lets exactly that party continue by adding the next Layer. The handover and appending of a layer can happen entirely offline, without contacting the issuer of the Wafer.

When a request arrives with a Wafer, the issuer verifies the origin, checks every Layer seal and the full Holder chain, then evaluates the accumulated rules in your policy engine (Cedar, OPA/Rego, Zanzibar-style...) to allow or deny the specific request. In practice, only the original issuer can authoritatively validate a Wafer; any attempt to alter rules or the delegation chain is detected and rejected.

> Under the hood, Wafers use a mix of symmetric and public-key cryptography to keep seals tiny, verification fast, and delegation offline—without exposing long-lived credentials.

### Core Mechanics

A Wafer has a straightforward flow: it is baked by a service, extended by successive holders, and finally enforced when it returns to the service. Three roles make this possible: the issuer, who creates and ultimately verifies it; the current holder, who may append a Layer of restrictions; and the next holder, nominated through a handover, who can continue the chain offline.

Unlike macaroons, Wafers use HMACs to seal entire Layers, allowing multiple caveats to be grouped under a single seal. At each step, only the current holder has the material needed to add restrictions, ensuring that no one else can modify or append to the Wafer. On top of this, Wafers use public-key cryptography to anchor handovers, so that only the issuer and the explicitly named next holder can derive the secret required to continue the chain.

The result is the safety of cryptographic attestation for delegation, while keeping the fast path lightweight with symmetric crypto—public-key operations are only used when ownership changes.


#### Issuing a Wafer

A Wafer is baked by the issuer, the end service that will ultimately enforce it. At issuance, the service generates the initial cryptographic state:
- A long-term key pair (`sk_I`, `pk_I`) for the issuer. 
    - The public key `pk_I` is published in the Wafer header
    - The private key `sk_I` is kept secret and used to derive shared secrets for delegation (handovers).
- A root secret `S_0` (random 32 bytes) that is kept private in secure storage. 
- `S_0` is used to derive the first per-layer key `K_0`:
    - `K_0` = `HMAC-SHA256(S_0, "wafer/{version}/K0" || id_bytes)

A Wafer header contains:
- A version `version`
- A unique ID `id`
- An expiry timestamp `expires_at`
- An issuer identifier `issuer` (e.g., the issuer domain)
- The issuer’s public key `public_key`
- (Optional): a signature `signature` valid for the public key so third parties can verify that this Wafer really targets that service.

The issuer needs to keep `S_0` (linked to the Wafer id) and `sk_I`.
The first holder receives the Wafer header (and optionally an initial Layer if the issuer chooses to add one).

From there, the first holder can use the derived key `K_0` to seal the first Layer of caveats. Only the issuer (with `S_0`) and the holder (with `K_0`) have the material required to extend the Wafer at this point.

#### Attenuating a Wafer

Attenuating a Wafer means the current holder adds a new Layer of restrictions. A valid Wafer can always be used as-is to access the service, but if the holder wants to further constrain it (time-limit it, scope it, narrow actions), they must compute the sealing key for the next Layer.

- First holder: uses the initial key `K_0` directly.
- Subsequent holders: derive a fresh per-Layer key `K_i` from two ingredients:
    - The integrity of the previous Layer (its HMAC `M_{i-1}`)
    - A Diffie–Hellman shared secret between the current holder’s private key and the issuer’s public key (`ss = X25519(sk_holder, pk_I)`).

These values are mixed together with HKDF to compute the sealing key `K_i`. Only the named holder and the issuer can produce the same `K_i`.

With `K_i` in hand, the holder can now append a new Layer. That Layer contains the chosen caveats and is sealed with a single HMAC:

```
mac_i = HMAC-SHA256(K_i, layer_bytes)
```

This guarantees two things:

1. Layers can only be added by the rightful holder (since only they can derive `K_i`).
2. Each Layer is tamper-evident, append-only, and cryptographically tied to the chain.


Once a Layer is sealed, the Wafer is in a terminal state. No further Layers can be added unless the current holder explicitly declares a next holder. This is done by appending a new Holder entry that:
- Includes the next holder’s public key and an holder identifier
- Is sealed with an HMAC under the same key `K_i`, but with a domain-separated input to distinguish it from Layer sealing (e.g., "wafer/v0/holder").

The newly named holder can now derive the next sealing key and append the next Layer. Without such a Holder entry, the Wafer remains valid for use, but it is no longer extensible.

#### Verifying a Wafer

Verifying a Wafer

When a request hits the issuer’s service, the first step before processing it is to verify the Wafer that accompanies it. Verification happens in three levels:
- **Header check**: If the Wafer header is invalid (unknown id, expired expires_at, or bad optional signature), the request is rejected immediately. This check only needs the header fields and the issuer’s public key.

- **Layers/Handovers check**: If the header is valid, check if any HMAC or key derivation fails. The service recomputes the sealing keys step by step:
	- Start from the bootstrap secret `S_0` and recompute `S_0`.
	- For each Layer, verify its HMAC with `K_i`.
	- If a Holder entry is present, verify its HMAC (domain-separated) and, if valid, derive the next sealing key `K_{i+1}` using Diffie–Hellman with the recorded next public key.
	- Continue until the end of the chain.

- **Policy check**: With a valid chain, the service folds all caveats from the Layers and evaluates them against the current request context in the chosen policy engine (Cedar, OPA/Rego, Zanzibar-style, or custom). If the policy evaluation fails, the request is denied.

### License
The Wafer source files are distributed under the Apache 2.0 license found in the LICENSE file.