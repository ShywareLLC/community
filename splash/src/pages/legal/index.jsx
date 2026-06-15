import React from 'react';
import LegalDocument, { LegalTable } from '../../components/LegalDocument';

const docs = [
  ['Legal index (this page)', '/legal/'],
  ['Privacy Policy', '/legal/privacy/'],
  ['DPIA Package', '/legal/privacy/dpia/'],
  ['Data Processing Agreement', '/legal/privacy/dpia/dpa/'],
  ['Sub-processor: Authentication Provider', '/legal/privacy/dpia/dpa/schedule-auth'],
  ['Sub-processor: Identity Verification', '/legal/privacy/dpia/dpa/schedule-verification'],
  ['Sub-processor: Compute and Signing', '/legal/privacy/dpia/dpa/schedule-compute'],
  ['Sub-processor: Off-chain Database', '/legal/privacy/dpia/dpa/schedule-database'],
  ['Sub-processor: Device Attestation', '/legal/privacy/dpia/dpa/schedule-attestation'],
  ['Sub-processor: Token Issuer (shywire)', '/legal/privacy/dpia/dpa/schedule-token'],
  ['Sub-processor: EHR / FHIR Health Records', '/legal/privacy/dpia/dpa/schedule-health'],
  ['SDK Compliance Guide', '/legal/compliance/'],
];

export default function LegalIndex() {
  return (
    <LegalDocument
      title="Legal"
      eyebrow="Shyware LLC"
      effectiveDate="2026-05-15"
      pdfHref="/legal/shyware-legal.pdf"
    >
      <h2>Terms of Service</h2>
      <p>
        These Terms govern access to and use of the shyware SDK, hosted APIs, and related
        services provided by Shyware LLC ("Shyware", "we"). By integrating the SDK or
        calling any shyware-hosted endpoint you agree to these Terms on behalf of yourself
        and the entity you represent ("you", "operator").
      </p>

      <h3>License</h3>
      <p>
        Subject to these Terms, shyware grants you a limited, non-exclusive, non-transferable
        license to integrate and deploy the SDK to build applications for end users. You may
        not sublicense the SDK independently of an application, resell hosted API access, or
        remove or obscure any attribution or protocol-version identifiers embedded in the SDK.
      </p>

      <h3>Use Restrictions</h3>
      <p>You may not use the SDK or hosted services to:</p>
      <ul>
        <li>Bypass, disable, or circumvent the two-list structural invariant or any validation predicate enforced at the ABCI layer.</li>
        <li>Represent a deployment as CBDC infrastructure without written authorisation from shyware and the applicable central bank.</li>
        <li>Process personal data of EU, UK, EEA, or other regulated-jurisdiction data subjects without first executing the{' '}
          <a href="/legal/privacy/dpia/dpa/">Data Processing Agreement</a> and all applicable sub-processor schedules.</li>
        <li>Process biometric or health special-category data without completing the applicable{' '}
          <a href="/legal/privacy/dpia/">DPIA</a> and obtaining lawful basis under Art. 9 GDPR or equivalent.</li>
        <li>Operate in any jurisdiction where the deployment would violate applicable law, including financial-services, health-privacy, or sanctions law.</li>
      </ul>

      <h3>Data Processing</h3>
      <p>
        shyware acts as a <strong>data processor</strong> on your behalf. You are the controller
        responsible for identifying a lawful basis, providing notices to data subjects, and
        responding to data-subject rights requests. Before processing any personal data in
        production you must execute the <a href="/legal/privacy/dpia/dpa/">Data Processing Agreement</a>.
        Sub-processor schedules are listed there. Our processing practices are described in the{' '}
        <a href="/legal/privacy/">Privacy Policy</a>. Compliance obligations specific to your
        deployment are in the <a href="/legal/compliance/">SDK Compliance Guide</a>.
      </p>

      <h3>Warranties and Liability</h3>
      <p>
        The SDK and hosted services are provided "as is." shyware makes no warranty that the
        SDK is fit for any particular regulated use — operators are responsible for legal
        compliance in their jurisdiction. To the maximum extent permitted by law, shyware's
        aggregate liability arising out of or related to these Terms shall not exceed the
        greater of (a) fees paid by you to shyware in the twelve months preceding the claim or
        (b) USD $100. shyware is not liable for indirect, consequential, or punitive damages.
      </p>

      <h3>Changes</h3>
      <p>
        Material changes to these Terms are published at least 30 days before taking effect and
        notified directly to operators with an active DPA. Continued use after the effective date
        constitutes acceptance.
      </p>

      <h3>Governing Law</h3>
      <p>
        These Terms are governed by the laws of the State of New Jersey, United States, without
        regard to conflict-of-law rules. Disputes are subject to the exclusive jurisdiction of
        the courts of Monmouth County, New Jersey.
      </p>

      <h2>Documents</h2>
      <LegalTable
        headers={['Document', 'Path']}
        rows={docs.map(([label, path]) => [
          <a href={path}>{label}</a>,
          <code style={{ fontSize: '0.8rem', color: '#a78bfa' }}>{path}</code>,
        ])}
      />

      <h2>Contact</h2>
      <p>
        Data protection: <a href="mailto:privacy@shyware.fyi">privacy@shyware.fyi</a><br />
        Legal: <a href="mailto:legal@shyware.fyi">legal@shyware.fyi</a>
      </p>
    </LegalDocument>
  );
}
