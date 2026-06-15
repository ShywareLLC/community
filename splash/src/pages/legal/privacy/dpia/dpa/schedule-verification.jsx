import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-verification' },
];

export default function ScheduleVerification() {
  return (
    <PassphraseGate>
      <LegalDocument
      title="Identity Verification Provider"
      eyebrow="Sub-processor Schedule"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/dpia/dpa/schedule-verification.pdf"
      docxHref="/legal/privacy/dpia/dpa/schedule-verification.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>
        Governs the <strong>Identity Verification Provider</strong> — the party fulfilling IDV,
        KYC, and biometric re-derivation. Activated when <code>identity.provider</code> is set
        to a biometric or KYC provider (primary IDV), <em>or</em> when{' '}
        <code>biometric_rederive</code> appears in <code>anon_layer.required_flows</code>{' '}
        regardless of the primary identity provider (break-glass biometric fallback, e.g. the
        KEYBOX authenticator surface where <code>identity.provider: wallet</code> but Didit
        biometric is invoked as a circular-dependency escape path). Swap the named provider by
        updating the relevant shyconfig field and executing a new DPA before transitioning
        production data.
      </p>
      <LegalTable
        headers={['Field', 'Value']}
        rows={[
          ['Role', 'Identity Verification / KYC / biometric re-derivation'],
          ['Named provider', <Req />],
          ['Location', <Req />],
          ['Transfer mechanism', <Req />],
        ]}
      />
      <h2>Data Processed</h2>
      <ul>
        <li>Biometric enrollment data (facial scan, liveness check, or equivalent)</li>
        <li>Government-issued identity document data</li>
        <li>Participant public key — attested for oracle-forgery prevention; the provider does <strong>not</strong> receive the per-scoping private key</li>
        <li>Attestation logs</li>
      </ul>
      <h2>Special Category (Art. 9)</h2>
      <p>Biometric processing requires explicit consent per jurisdiction. Some jurisdictions prohibit it entirely. Operator must confirm lawfulness before production and complete a biometric DPIA.</p>
      <h2>Structural Constraints</h2>
      <ul>
        <li><strong>Oracle-forgery prevention:</strong> provider attests public key only — cannot forge submissions</li>
        <li><strong>No canonical state access:</strong> holds no submission payloads or off-chain linkage data</li>
        <li><strong>No cross-operator correlation</strong> without documented instruction</li>
        <li><strong>Independent auditable trail:</strong> logs constitute one leg of the three-authority collusion detection surface</li>
      </ul>
    </LegalDocument>
    </PassphraseGate>
  );
}