import React from 'react';
import LegalDocument, { LegalTable } from '../../../../components/LegalDocument';
import PassphraseGate from '../../../../components/PassphraseGate';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia' },
];

const domains = [
  ['Civic voting + hostile-regime', 'shyvoting-v1',    '4-party count-match',    '23/23', 'civic-voting'],
  ['Wire transfer',                 'shywire-v1',      '4-party count-match',    '20/20', 'wire-transfer'],
  ['Private chat',                  'shychat-v1',      '3-party sealer-governed','43/43', 'private-chat'],
  ['Browser analytics',             'shybrowser-v1',   '3-party sealer-governed','19/19', 'browser-analytics'],
  ['Commodity custody',             'shycustody-v1',   '4-party count-match',    '17/17', 'custody'],
  ['DAO governance',                'shyshares-v1',    '4-party count-match',    '18/18', 'dao-governance'],
  ['Anonymous smart contracts',     'shycontracts-v1', '4-party count-match',    '21/21', 'financing'],
  ['Health record vault',           'shystore-v1',     '3-party sealer-governed','23/23', 'health-record-vault'],
  ['Credential vault / authenticator', 'shystore-v1', '3-party sealer-governed','23/23', 'credential-vault'],
  ['Anonymous betting',             'shybets-v1',      '4-party count-match',    '17/17', 'betting'],
  ['Informant stream',              'shyrest-v1',      '4-party count-match',    '15/15', 'informant'],
  ['Sealed-bid auction',            'shylots-v1',      '4-party count-match',    '16/16', 'sealed-bid'],
  ['Private streaming',             'shystream-v1',    '3-party sealer-governed','15/15', 'private-streaming'],
];

function DPIAPublic() {
  return (
    <>
      <p>
        This index covers all Data Protection Impact Assessment documents, Stack 4–6 test evidence,
        and compliance tooling for the shyware protocol.
      </p>
      <p>
        Shyware achieves GDPR Art. 5(1)(c) data minimisation and Art. 25 data-protection-by-design
        through a <strong>structural information-theoretic mechanism</strong>, not through policy or
        access control: the two-list atomic write ensures no join key between submission identifiers
        (List 1) and identity records (List 2) is ever materialised in canonical state.
        The count-match invariant <code>|L1(S)| = |L2(S)|</code> is the machine-verifiable
        structural property that replaces the "proportionality" and "necessity" assessments ordinarily
        required of controllers — the architecture structurally excludes over-collection by construction.
        The three-stack test suite verifies this invariant across Node.js (Stack 4), Swift/iOS (Stack 5),
        and Kotlin/Android (Stack 6) using identical live service endpoints and Cognito-authenticated
        sessions, producing three independent chains of custody anchored to immutable GitHub Actions logs.
      </p>
      <p>
        All three stacks pass as of unified run <code>26383938410</code> (2026-05-25, commit eb9aa01f). Each stack passed 379/379 assertions. The unified artifact
        reports 14/14 assertion-count parity, 14/14 claim-coverage parity, and 13/13 consumer
        requirement parity, with no remaining parity gaps.
      </p>

      <h2>Evidence Summary</h2>
      <LegalTable
        headers={['Stack', 'Runtime', 'Assertions', 'GitHub Actions run', 'Commit SHA', 'Infrastructure']}
        rows={[
          ['Stack 4', 'Node.js 24 / Ubuntu', '379/379 — 13 consumer suites + SDK protocol', '26383938410 (2026-05-25)', 'eb9aa01ffab20cde8d91e4bec7ba3321319220fa', 'GitHub-managed Ubuntu runner'],
          ['Stack 5', 'Swift 6.2 / XCTest / macOS 15 arm64', '379/379 — 13 consumer suites + SDK protocol', '26383938410 (2026-05-25)', 'eb9aa01ffab20cde8d91e4bec7ba3321319220fa', 'GitHub-managed macOS runner'],
          ['Stack 6', 'Kotlin 2.0 / JUnit4 / JVM 24 Ubuntu', '379/379 — 13 consumer suites + SDK protocol', '26383938410 (2026-05-25)', 'eb9aa01ffab20cde8d91e4bec7ba3321319220fa', 'GitHub-managed Ubuntu runner'],
        ]}
      />
      <LegalTable
        headers={['Item', 'Value']}
        rows={[
          ['Assertions passing', '379/379 on each of Stack 4, Stack 5, and Stack 6; 0 failures and 0 skips'],
          ['Domains covered', '13 consumer embodiments + SDK protocol invariant suite'],
          ['Cross-stack parity', '14/14 assertion-count parity; 14/14 claim-coverage parity; 13/13 consumer requirement parity'],
          ['Infrastructure', 'GitHub-managed runner — inventor cannot alter log post-execution'],
          ['Verify (no credentials)', 'curl https://confidential.scytale.fyi/health'],
          ['Stack 4 summary SHA-256', '3d729c725ebce170ae57633e38cb0e286da8d45bfe4e22d8657cd2b33a00ea89'],
          ['Stack 5 summary SHA-256', 'f5222e5d35a68f76ae9997be986508a4f65f7c0f8c870c0b8a5cd630f678245b'],
          ['Stack 6 summary SHA-256', '811376292e44e7668e34133b0060b4d3e396a099494d0d59c6eb39481544e42f'],
        ]}
      />

      <h2>SHA-256 Chain of Custody — Stack 4/5/6 Sweep</h2>
      <p>
        The "Hash result files" step in the respective runs printed the result-file hashes.
        Any modification to a committed result file produces a different hash, anchoring each file to the GitHub-managed run log.
      </p>
      <LegalTable
        headers={['File', 'SHA-256 (first 16 hex)']}
        rows={[
          ['dpia-stack4-summary.json',        '3d729c725ebce170...'],
          ['dpia-stack5-summary.json',        'f5222e5d35a68f76...'],
          ['dpia-stack6-summary.json',        '811376292e44e766...'],
          ['sdk/web/docs/unit-results-stack4.json', '968e8af240178482...'],
        ]}
      />
      <p>
        Full hashes: <a href="https://github.com/NickCarducci/Populist-Backend/actions/runs/26383938410" target="_blank" rel="noopener noreferrer">Unified run 26383938410</a>.
      </p>

      <h2>Data Processing Agreement</h2>
      <p>
        The Shyware DPA and sub-processor schedules are at{' '}
        <a href="/legal/privacy/dpia/dpa/">/legal/privacy/dpia/dpa/</a>.
      </p>
    </>
  );
}

function DPIADetail() {
  return (
    <>
      <h2>Per-domain DPIAs</h2>
      <LegalTable
        headers={['Domain', 'Contract', 'Authority model', 'Assertions', 'Downloads']}
        rows={domains.map(([domain, contract, auth, assertions, slug]) => [
          domain,
          <code style={{ fontSize: '0.78rem', color: '#a78bfa' }}>{contract}</code>,
          auth,
          assertions,
          <span style={{ display: 'flex', gap: '0.4rem' }}>
            <a href={`/legal/privacy/dpia/${slug}/dpia.pdf`} download style={{ fontSize: '0.75rem', color: '#71717a' }}>PDF</a>
            <a href={`/legal/privacy/dpia/${slug}/dpia.docx`} download style={{ fontSize: '0.75rem', color: '#71717a' }}>DOCX</a>
          </span>,
        ])}
      />

      <h2>Structural Compliance Guarantees</h2>
      <p>
        Shyware's GDPR compliance is achieved through <strong>write architecture</strong>, not
        policy. The following properties are <em>structurally enforced at the ABCI validation layer</em>,
        not asserted by SDK-layer checks:
      </p>
      <ul>
        <li><strong>Art. 5(1)(c) Data minimisation (Claim 1):</strong> No join key between List 1 (submission identifiers) and List 2 (identity records) is ever written to canonical state. The validation predicate rejects any transition that would create such a state. Formally: for any reachable canonical state, no algorithm with access only to public on-chain data can derive a participant-specific identity–payload association. This is a state-space exclusion, not a policy. Verified by the field-exclusivity assertions in Stack 4–6 (no <code>identity_hash</code>, <code>amount_usdce</code>, <code>sender_uid</code>, <code>direction</code>, or <code>weight</code> fields appear in canonical L1 responses).</li>
        <li><strong>Art. 5(1)(f) Integrity + confidentiality (Claims 18, 21, 22):</strong> The count-match invariant <code>|L1(S)| = |L2(S)|</code> (Claim 18) is enforced atomically — the ledger cannot have more submission records than identity records or vice versa. Mapping-op exclusion (Claim 21) and intermediate-state non-materialization (Claim 22) prevent any partial-state read that would expose a join. Verified by the <code>l1Count == l2Count</code> and <code>countMatch == true</code> assertions across all 13 domains in Stacks 4–6.</li>
        <li><strong>Art. 25 Data protection by design (Claim 11):</strong> Write-only posture (triggered by Play Integrity failure, hostile network, or untrusted device attestation) structurally suppresses receipt storage on the device — the device retains no linkable record after submission. Verified by <code>effectivePosture().writeOnly == true</code> assertions in Stack 5 (Swift) and Stack 6 (Kotlin) under the coercion-resistant configuration.</li>
        <li><strong>Art. 15/17 Access + erasure rights (Claims 32, 56, 57, 59):</strong> Reconciling authority exposes only per-participant, identity-gated retrieval (Claim 56 — non-composable reconcile kernel; Claim 57 — boolean-only presence surface; Claim 59 — fresh-input non-enumerability). Credential-free erasure (Claim 32) tested across shystore-v1, shystream-v1, and shyrest-v1: DELETE own record → confirmed absent from subsequent reconcile. Two-party threshold rescission (Claim 2) requires co-signing from eligibility and reconciling authority. Wire embodiments: L1 immutable per conservation invariant (Claim 38) + BSA retention; Art. 17 satisfied by L2 identity anonymization after retention window (Claim 66–67).</li>
      </ul>

      <h2>Residual Risk</h2>
      <p>
        The single unfalsifiable structural residual is <strong>authority collusion</strong>.
        Count-match embodiments require active coordination across 4 structurally separated
        parties (Auth + IDV/KYC + Enrollment/Eligibility + Reconciling Authority), each generating
        an independent auditable trail on separate infrastructure. No single authority holds
        a join key. Sealer-governed embodiments (shychat, shystore, shybrowser, shystream)
        have no rescission pathway by construction — the sealer can decrypt but cannot associate
        the sealed payload with the identity record without the off-chain reconciling authority.
        Single-node deployments substitute OTel/CloudWatch audit logging for BFT-consensus
        operator-purge prevention; see per-domain DPIAs for cert-tier backup requirements.
      </p>
      <p>
        Operator governance residuals are itemised per domain in the regulatory annexes
        (Annex A: deployment contexts, Annex B: primary regulation, Annex C/D: jurisdiction-specific).
        Common residuals: Art. 6 lawfulness basis, Art. 9 explicit consent where biometric
        processing is invoked, Art. 28 sub-processor DPA execution, key independence verification,
        quarterly independent audit.
        See <a href="/legal/compliance/">Compliance Guide</a> for operator obligations.
      </p>

      <h2>Compliance Tooling</h2>
      <ul>
        <li>
          <strong>Art. 30 RoP generator:</strong>{' '}
          <code>node scripts/generate-rop.mjs --config shyconfig.json</code> — 92 assertions
          verify correct structure for all 13 contract versions.
        </li>
        <li>
          <strong>Retention:</strong> add <code>retention</code> block to{' '}
          <code>shyconfig.json</code> to configure <code>deletion_cron</code>.
        </li>
      </ul>
    </>
  );
}

export default function DPIAIndex() {
  return (
    <PassphraseGate>
      <LegalDocument
        title="DPIA Package"
        eyebrow="shyware.fyi/legal/privacy/dpia"
        effectiveDate="2026-05-24"
        pdfHref="/legal/privacy/dpia/dpia-index.pdf"
        breadcrumbs={breadcrumbs}
      >
        <DPIAPublic />
        <DPIADetail />
      </LegalDocument>
    </PassphraseGate>
  );
}
