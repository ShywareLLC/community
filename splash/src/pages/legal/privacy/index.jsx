import React from 'react';
import LegalDocument, { LegalTable } from '../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy' },
];

const subprocessors = [
  ['Authentication Provider', '/legal/privacy/dpia/dpa/schedule-auth'],
  ['Identity Verification', '/legal/privacy/dpia/dpa/schedule-verification'],
  ['Compute and Signing', '/legal/privacy/dpia/dpa/schedule-compute'],
  ['Off-chain Linkage Database', '/legal/privacy/dpia/dpa/schedule-database'],
  ['Device Attestation', '/legal/privacy/dpia/dpa/schedule-attestation'],
  ['Token Issuer (shywire-v1 only)', '/legal/privacy/dpia/dpa/schedule-token'],
  ['EHR / FHIR Health Records', '/legal/privacy/dpia/dpa/schedule-health'],
];

export default function PrivacyPolicy() {
  return (
    <LegalDocument
      title="Privacy Policy"
      eyebrow="shyware.fyi/legal/privacy"
      effectiveDate="upon publication"
      pdfHref="/legal/privacy/privacy-policy.pdf"
      docxHref="/legal/privacy/privacy-policy.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>
        This Privacy Policy describes how Shyware LLC ("Shyware") processes personal data
        in connection with the shyware SDK, hosted services, and related infrastructure.
        shyware acts as a <strong>data processor</strong> for customer controllers deploying
        the SDK, and as a <strong>data controller</strong> only for limited operational data
        (support, billing, security logs).
      </p>

      <h2>The Structural Anonymity Guarantee</h2>
      <p>
        The shyware protocol writes every submission as two permanently disjoint canonical records:
      </p>
      <ul>
        <li><strong>List 1</strong> — a direction-free submission identifier. No participant identity.</li>
        <li><strong>List 2</strong> — a pseudonymous participant identity hash. No submission payload or direction.</li>
      </ul>
      <p>
        No join key between List 1 and List 2 is ever written to the canonical ledger. Anonymity is
        a structural property of the write path, not a policy applied on top of it. This is verified
        by the unified Stack 4/5/6 DPIA sweep, with 379/379 assertions passing on each stack
        across 13 deployment embodiments plus the SDK protocol invariant suite.{' '}
        <a href="/legal/privacy/dpia/">DPIA evidence →</a>
      </p>

      <h2>What Data shyware Processes</h2>
      <LegalTable
        headers={['Category', 'What is held', 'Where']}
        rows={[
          ['Direction-free submission IDs', 'List 1 canonical records — no identity, no direction', 'Canonical ledger (public)'],
          ['Pseudonymous identity hashes', 'List 2 canonical records — no payload or direction', 'Canonical ledger (public)'],
          ['Off-chain linkage data', 'Per-participant receipts under access control', 'Reconciling authority data store'],
          ['Account credentials', 'Username, session token, account sub claim', 'Account authentication provider'],
          ['Biometric attestation', 'Enrollment and attestation records (if IDV configured)', 'Identity verification provider'],
          ['Operational logs', 'Access logs, security events, support interactions', 'Infrastructure providers'],
        ]}
      />

      <h2>Sub-processors</h2>
      <p>
        shyware uses the following sub-processor categories. Named providers and DPA schedules
        are published at <a href="/legal/privacy/dpia/dpa/">/legal/privacy/dpia/dpa/</a>.
      </p>
      <LegalTable
        headers={['Role', 'Schedule']}
        rows={subprocessors.map(([role, path]) => [
          role,
          <a href={path}>{path}</a>,
        ])}
      />

      <h2>Data Subject Rights</h2>
      <p>
        Data subjects exercise rights (Art. 15–22 GDPR) by contacting the <strong>customer
        controller</strong> who deployed shyware. shyware assists controllers as described in
        the <a href="/legal/privacy/dpia/dpa/">Data Processing Agreement</a>. For shyware's
        own controller processing: <a href="mailto:privacy@shyware.fyi">privacy@shyware.fyi</a>.
      </p>

      <h2>DPIA and Compliance</h2>
      <p>
        A full Data Protection Impact Assessment package, Stack 4/5/6 test evidence
        (379/379 assertions per stack, 14 suites),
        and compliance documentation are at <a href="/legal/privacy/dpia/">/legal/privacy/dpia/</a>.
      </p>

      <h2>Changes</h2>
      <p>
        Material changes are published at least 30 days before taking effect. Controllers with an
        active DPA are notified directly.
      </p>
    </LegalDocument>
  );
}
