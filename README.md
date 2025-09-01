# Wafers

*A fast, offline-delegable capability token with layered caveats that lets you delegate safely across third-party services*

### What are Wafers?

**Wafers are portable capability tokens you can restrict and pass along**. Each Wafer carries identity (who it’s on behalf of), a cryptographic attestation chain of who was allowed to extend it, and an explicit description of what the token is allowed to do (the actions it permits, with specific limits like time, scope, or location).

If a JWT tells a system who you are, a Wafer tells it *who this request is on behalf of* and *exactly what it can do*. You can delegate a Wafer to a third party with stricter limits each time. For example, if you hold an admin-level Wafer for GitHub; you can a narrower Wafer that permits read-only access to one repository for 15 minutes and hand it to an AI agent reviewing a PR. Later, you can issue a different Wafer that allows merge on that PR.

As a Wafer is delegated, each holder adds caveats that only reduce what’s permitted and may hand it to the next holder. The result is a clear, auditable chain of custody with permissions that become more precise over time. 

Wafers don’t replace your authorization stack. They’re engine-agnostic and play nicely with policy engines like Cedar, OPA/Rego or Zanzibar-style systems.

### How do they work

A Wafer is issued (*baked*) by a service (the issuer). It includes a unique ID, expiry date and the issuer's public key. The issuer keeps a private root key linked to the wafer. A Wafer grows by appending `Blocks` and `Handovers`. Optionally, the issuer signs this header (ID/Expiry), so intermediaries (e.g., Cloudflare) can verify the wafer was minted by the service before forwarding a request (instead of `Web Bot Auth`)

Blocks carry the rules (what restrictions apply to the token) while handovers record the delegation chain (who was allowed to extend it, in what order).

After a Wafer is issued, the current holder may add one Block: a short list of actions and limits (time window, scope, region, repo, etc.). The Block is then sealed with a tiny cryptographic tag. That seal is verifiable by the issuer and makes the Block append-only and tamper-evident. Blocks only narrow what’s allowed.

Optionally, the holder adds a Handover naming the next public key. That ties the freshly sealed head to the next holder and lets exactly that party continue by adding the next Block. The handover and appending of a block can happen entirely offline, without contacting the issuer of the Wafer.

When a request arrives with a Wafer, the issuer verifies the origin, checks every Block seal and the full Handover chain, then evaluates the accumulated rules in your policy engine (Cedar, OPA/Rego, Zanzibar-style...) to allow or deny the specific request. In practice, only the original issuer can authoritatively validate a Wafer; any attempt to alter rules or the delegation chain is detected and rejected.

> Under the hood, Wafers use a mix of symmetric and public-key cryptography to keep seals tiny, verification fast, and delegation offline—without exposing long-lived credentials.

### Minting, Attenuating and Verifying Wafers

TODO(positiveblue): write this section with the cryptographic details


#### Minting a Wafer

#### Attenuating a Wafer

#### Verifying a Wafer


### FAQ

TODO(positiveblue)
