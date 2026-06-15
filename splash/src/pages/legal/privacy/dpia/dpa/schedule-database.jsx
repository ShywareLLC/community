import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req, Code } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-database' },
];

export default function ScheduleDatabase() {
  return (
    <PassphraseGate>
      <LegalDocument
      title="Off-chain Linkage Database Provider"
      eyebrow="Sub-processor Schedule"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/dpia/dpa/schedule-database.pdf"
      docxHref="/legal/privacy/dpia/dpa/schedule-database.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>Governs the reconciling authority data store. Required for all non-write-only deployments.</p>
      <LegalTable headers={['Field','Value']} rows={[
        ['Role','Off-chain linkage store (reconciling authority)'],
        ['Named provider',<Req />],
        ['Location',<Req />],
        ['Transfer mechanism',<Req />],
        ['Data processed','Off-chain linkage records, sealer-key mappings, reconcile audit logs'],
      ]} />
      <h2>Structural Constraints</h2>
      <ul>
        <li><strong>No global scan:</strong> provider must not expose bulk export or enumeration APIs — per-participant identity-gated retrieval only</li>
        <li><strong>Art. 17 erasure atomicity:</strong> sealer-key deletion is permanent and irrecoverable; must be atomic with audit log entry</li>
        <li><strong>No canonical state writes:</strong> provider holds only the off-chain supplement</li>
      </ul>
      <h2>Operator Purge and Backup</h2>
      <p>
        BFT consensus (multi-node deployments) prevents operator purge of canonical state —
        a supermajority of validators must approve any state transition. Single-node deployments
        without consensus provide no such structural guarantee; operator purge of the off-chain
        linkage store is detectable via OTel/CloudWatch audit logs but not preventable at the
        protocol level. Database backup requirements are cert-tier-dependent, not a blanket SDK
        mandate — see the per-domain DPIA regulatory annexes for the backup posture required for
        each certification tier.
      </p>
      <h2>Retention</h2>
      <p>Configure via <Code>retention.off_chain_linkage_days</Code> and <Code>deletion_cron</Code> in shyconfig.json. Operational enforcement is a governance obligation.</p>
    </LegalDocument>
    </PassphraseGate>
  );
}