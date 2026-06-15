import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-token' },
];

export default function ScheduleToken() {
  return (
    <PassphraseGate>
      <LegalDocument
      title="Token Issuer"
      eyebrow="Sub-processor Schedule — shywire-v1 only"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/dpia/dpa/schedule-token.pdf"
      docxHref="/legal/privacy/dpia/dpa/schedule-token.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>Governs the stablecoin or asset-rail issuer with read-only AML/OFAC reconcile access. Activated when <code>wire.provider</code> is set in shyconfig. shywire-v1 deployments only.</p>
      <LegalTable headers={['Field','Value']} rows={[
        ['Role','Token issuer with read-only AML/OFAC reconcile access'],
        ['Named provider',<Req />],
        ['Location',<Req />],
        ['Transfer mechanism',<Req />],
        ['Data processed','Transfer records for AML/OFAC screening; read-only reconcile access'],
      ]} />
      <h2>Structural Constraints</h2>
      <ul>
        <li><strong>Read-only:</strong> cannot write to canonical state or produce valid rescission transactions</li>
        <li><strong>Independent from eligibility authority:</strong> the enrolling bank and the token issuer are separate roles and must be separate parties</li>
        <li><strong>Operator retains controller responsibility</strong> for data subject rights workflows</li>
      </ul>
      <h2>Legal Basis for AML/OFAC</h2>
      <p>Disclosure to the token issuer for AML/OFAC screening may be processed under Art. 6(1)(c) (legal obligation) where applicable financial-services law requires it. Document the basis in the deployment Records of Processing.</p>
    </LegalDocument>
    </PassphraseGate>
  );
}