import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-attestation' },
];

export default function ScheduleAttestation() {
  return (
    <PassphraseGate>
      <LegalDocument
        title="Device Attestation Provider"
        eyebrow="Sub-processor Schedule"
        effectiveDate="upon publication"
        pdfHref="/legal/privacy/dpia/dpa/schedule-attestation.pdf"
        docxHref="/legal/privacy/dpia/dpa/schedule-attestation.docx"
        breadcrumbs={breadcrumbs}
      >
        <p>
          Governs processing by <strong>Apple App Attest</strong> and{' '}
          <strong>Google Play Integrity</strong> in connection with the shyware write-only posture
          and coercion-resistance guarantee. Activated when{' '}
          <code>deployment.runtime_fallbacks.write_only_on_missing_play_integrity</code> or{' '}
          <code>write_only_on_untrusted_device_attestation</code> is <code>true</code> — the
          default for all non-demo production deployments.
        </p>
        <p>
          Attestation providers are <strong>runtime trust signal providers</strong>, not data
          authorities in the two-list protocol sense. They do not write to or read from the
          canonical ledger, do not hold the off-chain linkage store, and cannot co-sign rescissions.
          Their role is to certify the integrity of the execution environment before the submission
          posture is determined.
        </p>

        <LegalTable
          headers={['Provider', 'Platform', 'Role']}
          rows={[
            ['Google Play Integrity API', 'Android', 'Issues signed integrity verdicts; verifies app identity, installation source, device health'],
            ['Apple App Attest (DCAppAttestService)', 'iOS', 'Issues FIDO2-based attestation assertions; verifies app and device integrity'],
          ]}
        />

        <h2>Role in the Protocol</h2>
        <p>
          The attestation verdict gates whether a submission receives receipt confirmation
          (recoverable posture) or proceeds as write-only (no receipt, no payload retained on
          device). It does <strong>not</strong> gate whether the submission enters canonical state
          — the two-list write proceeds regardless of attestation result. A failed attestation
          triggers the <code>write_only_on_missing_play_integrity</code> fallback: the submission
          enters List 1 and List 2 normally, but the device retains only the direction-free
          submission ID and no receipt data.
        </p>
        <p>
          This is the structural foundation of coercion resistance in hostile-regime deployments
          (SEDA_HAQQ, shyvoting-v1 with <code>coercion_resistant</code> posture): a coercer
          seizing the device after submission gets no evidence of submission direction.
        </p>

        <h2>Data Processed by Attestation Providers</h2>
        <p>
          Neither provider receives submission content, identity hashes, ballot direction, or
          any shyware canonical-state data.
        </p>
        <LegalTable
          headers={['Data element', 'Provider', 'Legal basis']}
          rows={[
            ['Network IP address (implicit in API call)', 'Both', 'Art. 6(1)(f) legitimate interest (app integrity); confirm SCCs for EU-to-US transfer'],
            ['App package name / bundle ID', 'Both', 'Not personal data; operator data only'],
            ['Device model and OS version', 'Google', 'Art. 6(1)(f) legitimate interest (fraud/abuse prevention)'],
            ['Play Store installation status', 'Google', 'Art. 6(1)(f) legitimate interest'],
            ['Integrity verdict (MEETS_DEVICE_INTEGRITY etc.)', 'Google', 'Art. 6(1)(f) legitimate interest'],
            ['Device-bound FIDO2 key material', 'Apple', 'Art. 6(1)(f) legitimate interest; stored on device Secure Enclave only'],
            ['Client data hash (SHA-256 of server challenge)', 'Apple', 'Not personal data; derived from operator-generated nonce'],
          ]}
        />
        <p style={{ fontSize: '0.85rem' }}>
          The IP address is the primary personal data element. In EU deployments, attestation API
          calls constitute transfers of personal data to the US. Operators must confirm SCCs or
          adequacy for both Google and Apple.
        </p>

        <h2>What Attestation Providers Do NOT Receive</h2>
        <ul>
          <li>User identity, account <code>sub</code> claim, or identity hash</li>
          <li>Submission direction, payload content, or scoping ID</li>
          <li>Ballot nonce, secret ID, or any List 1 / List 2 data</li>
          <li>Off-chain linkage store data or reconciling authority credentials</li>
        </ul>
        <p>
          The nonce / client data hash passed to the attestation API must be a server-generated
          random challenge — <strong>never</strong> derived from user identity or submission content.
        </p>

        <h2>Structural Constraints</h2>
        <ul>
          <li><strong>Not part of the two-list invariant</strong> — verdict is a posture input only; not written to canonical state or off-chain linkage store.</li>
          <li><strong>No canonical data access</strong> — cannot query or modify List 1 or List 2.</li>
          <li><strong>No identity linkage</strong> — does not receive <code>sub</code> claim or identity hash.</li>
          <li><strong>Coercion resistance preserved under compromise</strong> — even a false attestation verdict does not break canonical non-derivability; the two-list rejection predicate is unaffected.</li>
          <li><strong>Posture gate only</strong> — a missing or failed verdict triggers write-only fallback; submission still enters canonical state.</li>
        </ul>

        <h2>SEDA_HAQQ / Hostile-Regime Deployments</h2>
        <p>
          In hostile-regime deployments, device attestation is a co-launch requirement. The
          coercion-resistance guarantee depends on: (1) the attestation verdict confirming an
          uncompromised execution environment, (2) the shyware SDK suppressing receipt data after
          submission, and (3) the device OS enforcing the App Attest / Play Integrity sandbox.
          All three must hold. A failure in any layer degrades the coercion-resistance guarantee
          to write-only structural anonymity without receipt-suppression assurance.
        </p>

        <h2>Operator Obligations</h2>
        <ul>
          <li>Register the app with Google Play Integrity API and Apple App Attest before production.</li>
          <li>Include attestation provider data flows in the privacy notice and Art. 30 Records of Processing.</li>
          <li>Confirm SCCs or adequacy for EU personal data transferred to Google (US) and Apple (US).</li>
          <li>Pass only a server-generated random challenge as the nonce / client data hash — never user identity or submission content.</li>
          <li>Set <code>write_only_on_missing_play_integrity: true</code> and <code>write_only_on_untrusted_device_attestation: true</code> for all production deployments requiring coercion resistance.</li>
          <li>Review Google Play Integrity API Terms of Service and Apple App Attest documentation before production.</li>
        </ul>
      </LegalDocument>
    </PassphraseGate>
  );
}
