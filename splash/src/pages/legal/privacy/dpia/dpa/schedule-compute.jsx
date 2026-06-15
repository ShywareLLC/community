import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-compute' },
];

export default function ScheduleCompute() {
  return (
    <PassphraseGate>
      <LegalDocument
      title="Compute and Signing Provider"
      eyebrow="Sub-processor Schedule"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/dpia/dpa/schedule-compute.pdf"
      docxHref="/legal/privacy/dpia/dpa/schedule-compute.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>
        Governs cloud infrastructure, application-layer signing, and HSM period-close attestation.
        Activated by <code>signing.backend</code> in shyconfig. One provider may fulfill both
        compute and signing sub-roles, or separate providers may be used. Account authentication
        is governed separately by the{' '}
        <a href="/legal/privacy/dpia/dpa/schedule-auth">Authentication Provider schedule</a>.
      </p>
      <h2>Infrastructure</h2>
      <LegalTable headers={['Field','Value']} rows={[['Role','Cloud compute, networking, and runtime infrastructure'],['Named provider',<Req />],['Location',<Req />],['Transfer mechanism',<Req />]]} />
      <h2>Signing and HSM Attestation</h2>
      <LegalTable headers={['Field','Value']} rows={[['Role','KMS signing + HSM period-close attestation over disjoint Merkle roots'],['Named provider',<Req />],['shyconfig field','signing.backend: aws_kms_x_aws_cloudhsm or equivalent'],['FIPS standard','FIPS 140-3 L3 required for HSM period-close; L2 minimum for KMS application-layer signing']]} />
      <p>The signing provider holds no canonical ledger state and no off-chain linkage data. The HSM period-close attestation over two disjoint Merkle roots (List 1 identifiers + List 2 identity hashes) enables operator-independent third-party verifiability of count-match results.</p>
    </LegalDocument>
    </PassphraseGate>
  );
}