import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa' },
];

const schedules = [
  ['Authentication Provider', '/legal/privacy/dpia/dpa/schedule-auth', 'all deployments — api.auth_scheme in shyconfig; delete-only authority in sealer embodiments'],
  ['Identity Verification Provider', '/legal/privacy/dpia/dpa/schedule-verification', 'identity.provider: didit | identus (primary IDV), OR biometric_rederive in anon_layer.required_flows (break-glass fallback)'],
  ['Compute and Signing Provider', '/legal/privacy/dpia/dpa/schedule-compute', 'signing.backend + api.auth_scheme'],
  ['Off-chain Linkage Database', '/legal/privacy/dpia/dpa/schedule-database', 'all deployments'],
  ['Device Attestation Provider', '/legal/privacy/dpia/dpa/schedule-attestation', 'deployment.runtime_fallbacks.write_only_on_missing_play_integrity or write_only_on_untrusted_device_attestation'],
  ['Token Issuer', '/legal/privacy/dpia/dpa/schedule-token', 'wire.provider = circle_usdc (shywire-v1 only)'],
  ['EHR / FHIR Health Records Provider', '/legal/privacy/dpia/dpa/schedule-health', 'store.ehr_provider + health_record or health_record_era in secret_categories'],
];

export default function DPA() {
  return (
    <PassphraseGate>
      <LegalDocument
      title="Data Processing Agreement"
      eyebrow="shyware.fyi/legal/privacy/dpia/dpa"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/dpia/dpa/dpa.pdf"
      docxHref="/legal/privacy/dpia/dpa/dpa.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>
        This Data Processing Agreement governs how shyware processes personal data as a processor
        on behalf of customer controllers. It is incorporated into the shyware Terms of Service.
        Controllers using shyware to process personal data must execute this DPA before production.
      </p>

      <h2>Roles</h2>
      <LegalTable
        headers={['Party', 'Role', 'Responsibilities']}
        rows={[
          ['Customer', 'Controller', 'Determines purposes and means; provides notices; identifies legal basis; configures retention; responds to data subject requests; approves sub-processors.'],
          ['shyware', 'Processor', 'Processes customer data on behalf of the customer under documented instructions; implements security measures; assists with DPIA and data subject request workflows.'],
          ['Sub-processors', 'Sub-processors', 'Provide infrastructure, signing, identity verification, database, or token-issuance services under the schedules below.'],
        ]}
      />

      <h2>Sub-processor Schedules</h2>
      <p>
        Named providers for each role are documented in the schedules below. Swap any provider
        by updating the relevant <code>shyconfig.json</code> field and executing a new DPA with
        the replacement before transitioning.
      </p>
      <LegalTable
        headers={['Role', 'Schedule', 'shyconfig trigger']}
        rows={schedules.map(([role, path, trigger]) => [
          <a href={path}>{role}</a>,
          <a href={path} style={{ fontSize: '0.8rem', color: '#71717a' }}>{path}</a>,
          <code style={{ fontSize: '0.78rem', color: '#a78bfa' }}>{trigger}</code>,
        ])}
      />

      <h2>Processing Details</h2>
      <LegalTable
        headers={['Field', 'Value']}
        rows={[
          ['Subject matter', 'Processing of personal data by shyware SDK and hosted services on behalf of the customer controller'],
          ['Duration', 'Term of the customer agreement; post-termination return/deletion per this DPA'],
          ['Nature', 'Canonical state machine operations, off-chain linkage store, identity verification, signing, authentication'],
          ['Purpose', 'Provide, secure, maintain, and support the shyware SDK and related services under customer instruction'],
          ['Data categories', 'Direction-free submission IDs, pseudonymous identity hashes, off-chain linkage data, account credentials, operational logs'],
          ['Data subjects', 'End users of customer products deploying shyware'],
        ]}
      />

      <h2>Security</h2>
      <p>
        shyware implements: two-list structural anonymity (join key never written to canonical state);
        HSM period-close attestation (FIPS 140-3 L3); dual co-authorization enforcement (Claim 2,
        verified 208/208); enumeration rejection on all bulk-scan paths; per-participant
        identity-gated reconcile interface.
      </p>

      <h2>International Transfers</h2>
      <p>
        Sub-processor locations and transfer mechanisms are documented per schedule. EU controllers
        must confirm SCCs or adequacy for any non-EEA sub-processor before production.
      </p>
    </LegalDocument>
    </PassphraseGate>
  );
}