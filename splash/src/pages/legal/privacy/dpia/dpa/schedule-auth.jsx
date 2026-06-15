import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-auth' },
];

export default function ScheduleAuth() {
  return (
    <PassphraseGate>
      <LegalDocument
        title="Authentication Provider"
        eyebrow="Sub-processor Schedule"
        effectiveDate="upon publication"
        pdfHref="/legal/privacy/dpia/dpa/schedule-auth.pdf"
        docxHref="/legal/privacy/dpia/dpa/schedule-auth.docx"
        breadcrumbs={breadcrumbs}
      >
        <p>
          Governs the <strong>Authentication Provider</strong> — the party managing account
          credentials, session tokens, and JWKS-based token verification. Applies to{' '}
          <strong>every shyware embodiment</strong> — all 13 contract variants use the auth
          layer. In all current production deployments the provider is{' '}
          <strong>AWS Cognito</strong>. Configured via{' '}
          <code>api.auth_scheme: cognito | jwks</code> in shyconfig.
        </p>

        <LegalTable
          headers={['Field', 'Value']}
          rows={[
            ['Role', 'Account authentication and session management'],
            ['Named provider', <Req />],
            ['shyconfig field', <><code>api.auth_scheme</code>: <code>cognito</code>, <code>jwks</code>, or equivalent</>],
            ['Location', <Req />],
            ['Transfer mechanism (if outside EEA)', <Req />],
          ]}
        />

        <h2>Cognito's Role by Embodiment Type</h2>
        <p>
          Cognito's role is <strong>authentication gate</strong> in all embodiments. It does not
          hold a canonical co-signature key in any embodiment. Its relationship to erasure differs
          by embodiment type:
        </p>
        <ul>
          <li>
            <strong>Account layer — all 13 embodiments.</strong> Cognito authenticates users at
            every API surface. The <code>sub</code> claim from the verified JWT is the primary
            input to the participant identity hash written to List 2:{' '}
            <code>identity_hash = SHA-256(sub ‖ scoping_id ‖ domain_separator)</code>. A party
            with both Cognito access and the reconciling authority's off-chain linkage store could
            link canonical submissions to accounts — this is the cross-authority collusion risk
            documented in all deployment DPIAs.
          </li>
          <li>
            <strong>Count-match embodiments (shyvoting, shywire, shyshares, shycustody,
            shycontracts, shybets, shylots).</strong> <code>TxTypeAuthorityRescind</code> is
            available. The eligibility authority (voter registration, bank, DAO admin, etc.) and
            the reconciling authority each hold a registered Ed25519 co-signature key. Both
            must co-sign a rescission — Cognito gates the API call but holds no co-signature key.
          </li>
          <li>
            <strong>Sealer-governed embodiments (shybrowser, shystore, shychat).</strong>{' '}
            <code>TxTypeAuthorityRescind</code> is <strong>structurally unavailable</strong> —
            the state machine rejects it if no eligibility and reconciling keys are registered at
            scoping-identifier creation. There is no canonical delete-only co-signer. Erasure
            means the reconciling authority deletes the sealer key from the off-chain store on
            an authenticated (Cognito-gated) request. The canonical L1 and L2 records are
            BFT-immutable and persist; the payload becomes permanently undecryptable. Cognito
            authenticates the request — it does not co-sign anything and does not hold a deletion
            key. This is distinct from: (a) canonical record deletion (impossible in sealer
            embodiments without BFT supermajority), (b) database-level operator purge
            (infrastructure-level, not a protocol operation).
          </li>
        </ul>

        <h2>Data Processed</h2>
        <LegalTable
          headers={['Data element', 'Purpose', 'Legal basis']}
          rows={[
            ['Account credentials (username/email, hashed password, MFA state)', 'Authentication', 'Art. 6(1)(b) contract performance'],
            ['Session tokens (JWT access, refresh, ID)', 'Session management', 'Art. 6(1)(b) contract performance'],
            ['Account sub claim', 'Input to List 2 identity hash derivation', 'Art. 6(1)(b) / (f) — disclose in privacy notice'],
            ['Auth events (sign-in, sign-out, MFA, recovery)', 'Security audit trail', 'Art. 6(1)(f) legitimate interest'],
            ['JWKS public keys', 'Server-side token verification', 'Art. 6(1)(b) service performance'],
            ['Account metadata (creation date, last sign-in, status)', 'Account management', 'Art. 6(1)(b) contract performance'],
          ]}
        />

        <h2>Critical: sub Claim to List 2 Derivation</h2>
        <p>
          The <code>sub</code> claim is written into the List 2 identity hash. This means the
          authentication provider holds the credential from which the canonical List 2 commitment
          is derived. Structural non-linkability still holds — the hash is one-way and List 1
          and List 2 have no join key. But cross-authority collusion between the authentication
          provider and the reconciling authority would break structural anonymity.
        </p>
        <p>
          <strong>Operator obligation:</strong> The privacy notice must disclose the{' '}
          <code>sub</code>-to-List-2 derivation path. Required under Art. 13 GDPR.
        </p>

        <h2>Structural Constraints</h2>
        <ul>
          <li><strong>Cannot write canonical records</strong> — no canonical commit authority; cannot write List 1 or List 2 directly.</li>
          <li><strong>Cannot access off-chain linkage store</strong> — does not hold the reconciling authority's data.</li>
          <li><strong>No co-signature role in any embodiment</strong> — authenticates API requests but holds no canonical commit key and cannot co-sign rescissions in count-match embodiments. In sealer-governed embodiments, <code>TxTypeAuthorityRescind</code> is structurally unavailable; Cognito gates the sealer-key deletion request but does not hold the deletion key.</li>
          <li><strong>Key independence required</strong> — at scoping-identifier creation, auth key ≠ eligibility key ≠ reconciling key. Pre-production check.</li>
          <li><strong>Collusion is the residual risk</strong> — the guarantee holds unless auth provider and reconciling authority collude. Assess and document in deployment DPIA.</li>
        </ul>

        <h2>Account Deletion and List 2</h2>
        <p>
          Deleting the Cognito account does <strong>not</strong> automatically delete the List 2
          identity hash in canonical state. Art. 17 erasure path differs by embodiment:
        </p>
        <ul>
          <li>
            <strong>Count-match embodiments:</strong> (1) Cognito account deletion, (2) canonical
            rescission (<code>TxTypeAuthorityRescind</code>) co-signed by the eligibility authority
            and the reconciling authority — Cognito is not a co-signer in this step.
          </li>
          <li>
            <strong>Sealer-governed embodiments:</strong> (1) Cognito account deletion, (2)
            sealer key deletion by the reconciling authority on an authenticated request — the
            canonical L1/L2 records persist but the payload is permanently undecryptable. There
            is no canonical record deletion step; <code>TxTypeAuthorityRescind</code> is
            unavailable.
          </li>
        </ul>

        <h2>Operator Obligations</h2>
        <ul>
          <li>Execute a signed DPA with the authentication provider before processing any personal data.</li>
          <li>Disclose the <code>sub</code>-to-List-2 derivation path in the privacy notice.</li>
          <li>Configure shortest viable token expiry; disable unused Cognito attributes.</li>
          <li>Implement the correct Art. 17 erasure path for the embodiment type (see above).</li>
          <li>Verify key independence at scoping-identifier creation (count-match embodiments).</li>
          <li>Confirm SCCs or adequacy decision for EU data processed in non-EEA AWS regions.</li>
          <li>Notify Shyware of any change of authentication provider at least 30 days in advance.</li>
        </ul>
      </LegalDocument>
    </PassphraseGate>
  );
}
