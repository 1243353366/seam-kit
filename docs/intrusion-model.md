# What the intrusion side should record

Read rather than recalled. Two documents, both public:

- **CISA**, *Cybersecurity Incident & Vulnerability Response Playbooks* (November 2021, 44 pages,
  TLP:CLEAR), the document behind the August 2024 file at
  `cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf`.
- **Europol**, *Organised crime online: How Europol disrupts cybercrime* (2025, ISBN
  978-92-9414-060-9), the companion paper to the IOCTA 2025 stolen-data-economy theme.

Two access notes, because provenance is the point of this repository. `cisa.gov` refuses automated
requests from this environment (Akamai, "Access Denied"), so the playbook text was read through a
public reader proxy of the same URL; the quotations below were taken from that extraction. The
IOCTA landing page renders only through JavaScript and returned no text, so the Europol quotations
come from the companion PDF, not from the assessment itself. Neither document is quoted beyond what
appeared in the extracted text.

## The seven things CISA actually asks for

Each of these bears directly on reconstructing an intrusion, and each has a different answer in
this repo today.

1. **Preparation includes evidence capability.** Preparation activities include "Establishing means
   for collecting digital forensics and other data or evidence", and later "Establish secure
   storage (i.e., only accessible by incident responders) for incident" material. *Have:* sealed
   manifests and an append-only exhibit chain. *Missing:* no notion of who may read the store.

2. **Scope is determined, then re-validated.** The playbook has "Determine Investigation Scope" and
   then "Validate and Refine Investigation Scope", where new indicators may expand it. *Missing:*
   scope is not a first-class object anywhere in this repo, so a scope revision leaves no trace.

3. **Preserve what may become evidence.** "When necessary and possible, such information should be
   preserved and safeguarded as best evidence for use in any potential law enforcement" purpose.
   *Have:* the seal and the hash chain. *Missing:* preservation is not ordered against other
   actions, which is requirement 7.

4. **Correlate events and document the timeline.** "Acquire, store, and analyze logs to correlate
   adversarial activity", and "Thoroughly document every step taken during this and subsequent
   phases." *Have:* `lab/graph.py` correlates clock-skewed observations. *Missing:* the responder's
   own steps are not recorded anywhere, only the adversary's.

5. **Map to ATT&CK.** "Compare TTPs to adversary TTPs documented in ATT&CK and analyze how the TTPs
   fit into the attack lifecycle." *Missing:* no tactic or technique identifiers in any record.

6. **Containment has an evidence cost.** Containment considerations list "Any impact on the
   collection, preservation, securing, and documentation of evidence", and note that "adversaries
   may actively monitor defensive response measures". *Missing:* containment is not modelled at all,
   so the cost is invisible.

7. **Preserve before you eradicate.** In eradication: "Take actions to eliminate all evidence of
   compromise... Ensure evidence has been preserved as necessary." This is an ordering constraint,
   and ordering is the one thing a hash chain can actually enforce.

## What Europol changes

1. **Initial access is bought, not always achieved.** "A thriving part of the criminal ecosystem
   revolves around selling access to compromised systems and accounts. Initial Access Brokers
   (IABs) are increasingly advertising these services." So a credential's activity may belong to a
   third party who bought it, and "who authenticated" is not "who operated". `lab/identity.py`
   binds a credential to a device and a nonce, and has no concept of a credential changing hands.
   That is a real gap, named rather than papered over.
2. **Fragmentation makes attribution a claim about a market, not a person.** "The cybercrime
   landscape has become more fragmented, with shorter life-spans and splintering of markets and
   ransomware groups, making identification of threat actors more challenging." Attribution should
   therefore inherit the same ceiling as everything else here: `unknown` unless something outside
   the intrusion record corroborates it.
3. **Disruption is a different objective from detection.** The paper's operation example is a joint
   action against a named network over four days in July 2025. That is law enforcement's work, not
   a lab's, and it is not modelled here.

## Consequences, in the order they would matter

- **A baseline requirement.** CISA's detection step is deviation from "the established baseline".
  Without one, an anomaly claim cannot be graded above `suspected`, for the same reason a media
  claim cannot be `confirmed` on one signal. This is a ceiling, not a feature.
- **Ordering: preserve, then act.** The seal must be written before any remediation entry appears
  in the same timeline, and the check is cheap: a remediation record whose timestamp precedes the
  preservation seal is a finding.
- **Two records, not one.** "Document every step taken" means the responder's actions are evidence
  too, and their absence is indistinguishable from a deleted log.
- **Access as a commodity.** A credential that has been sold gives an authenticated actor who is
  not the owner. Until `identity.py` can express that, its output should say `unknown` about
  operation even when authentication succeeds, which the museum case already does for a different
  reason.

## Not built, and why

No ATT&CK mapping (it would be a lookup table that proves nothing), no containment modelling
(nothing here touches a live system), no attribution engine (Europol's fragmentation point argues
against one), and no reproduction of any real operation. The museum case remains the only case, and
it is synthetic.
