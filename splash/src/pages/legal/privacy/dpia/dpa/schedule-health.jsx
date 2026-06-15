import React from 'react';
import PassphraseGate from '../../../../../components/PassphraseGate';
import LegalDocument, { LegalTable, Req } from '../../../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'privacy', href: '/legal/privacy/' },
  { label: 'dpia', href: '/legal/privacy/dpia/' },
  { label: 'dpa', href: '/legal/privacy/dpia/dpa/' },
  { label: 'schedule-health' },
];

export default function ScheduleEHR() {
  return (
    <PassphraseGate>
      <LegalDocument
        title="EHR / FHIR Health Records Provider"
        eyebrow="Sub-processor Schedule"
        effectiveDate="upon publication"
        pdfHref="/legal/privacy/dpia/dpa/schedule-health.pdf"
        docxHref="/legal/privacy/dpia/dpa/schedule-health.docx"
        breadcrumbs={breadcrumbs}
      >
        <p>
          Governs the <strong>EHR / FHIR Health Records Provider</strong> — the party providing
          patient-authorised access to electronic health records via SMART on FHIR. Activated when{' '}
          <code>store.ehr_provider</code> is set in shyconfig (e.g.{' '}
          <code>store.ehr_provider: "epic"</code>) and{' '}
          <code>store.secret_categories</code> includes <code>health_record</code> or{' '}
          <code>health_record_era</code>. This schedule applies in addition to — not instead of —
          the Compute, Database, and Verification schedules. All four BAAs must be in place before
          any PHI flows in production.
        </p>

        <LegalTable
          headers={['Field', 'Value']}
          rows={[
            ['Role', 'EHR / FHIR health records data source (patient-authorised)'],
            ['shyconfig trigger', <><code>store.ehr_provider</code> + <code>health_record</code> or <code>health_record_era</code> in <code>secret_categories</code></>],
            ['Named provider', <Req />],
            ['FHIR version', <Req />],
            ['Location', <Req />],
            ['Transfer mechanism (if outside EEA)', <Req />],
            ['HIPAA BAA status', <Req />],
          ]}
        />

        <h2>Role in the Data Flow</h2>
        <p>
          The EHR provider is a <strong>data source</strong>, not a downstream processor. The patient
          authorises access via SMART on FHIR OAuth. The health vault application fetches only the
          FHIR resource types the patient explicitly consented to (scoped OAuth token), encrypts the
          payload client-side before transmission, and stores the sealed blob via the shystore
          two-list invariant. The EHR provider does not receive any shyware canonical-state data and
          does not process data on behalf of the operator after the OAuth handshake.
        </p>
        <p>
          Notwithstanding the above, the EHR provider holds its own copy of the patient record and
          is independently subject to HIPAA and applicable health privacy law. This schedule governs
          the operator's obligations in relation to that access, not the provider's independent
          obligations as a covered entity.
        </p>

        <h2>Data Accessed</h2>
        <LegalTable
          headers={['FHIR Resource Type', 'Content', 'Consent Required']}
          rows={[
            ['Observation', 'Labs, vitals, blood pressure, weight, oxygen', 'Per-resource explicit consent'],
            ['Condition', 'Diagnoses — current and historical', 'Per-resource explicit consent'],
            ['MedicationRequest', 'Active and historical prescriptions', 'Per-resource explicit consent'],
            ['AllergyIntolerance', 'Drug, food, and environmental allergies', 'Per-resource explicit consent'],
            ['Procedure', 'Surgeries, treatments, interventions', 'Per-resource explicit consent'],
            ['Immunization', 'Immunization history', 'Per-resource explicit consent'],
            ['DocumentReference', 'Clinical notes and reports', 'Per-resource explicit consent'],
          ]}
        />
        <p style={{ fontSize: '0.85rem' }}>
          Access is scoped to consented resource types only. The SMART on FHIR OAuth scope is
          generated from the patient's per-resource-type consent selection in the operator's consent
          gate UI (Art. 9(2)(a) explicit consent recorded via <code>POST /api/store/consent</code>{' '}
          before redirect). Unconsented resource types are excluded from the OAuth scope request.
        </p>

        <h2>Special Category (Art. 9) — Health Data</h2>
        <p>
          Health records are special-category personal data under GDPR Art. 9(1). Processing
          requires an Art. 9(2) exemption. The intended basis for shystore EHR deployments is:
        </p>
        <ul>
          <li>
            <strong>Art. 9(2)(a) — Explicit consent.</strong> The patient provides freely given,
            specific, informed, and unambiguous consent to import and vault each FHIR resource type
            before the SMART on FHIR redirect. Consent is recorded as a sealed consent record in the
            shystore ledger. Withdrawal of consent triggers deletion of all associated health records
            and the consent record via the Art. 17 erasure path.
          </li>
          <li>
            Consent must be granular per resource type — a single blanket consent for{' '}
            <code>patient/*.read</code> is not sufficient for Art. 9(2)(a).
          </li>
          <li>
            The operator must maintain a record of each consent act (timestamp, scope, resource
            types, consentId) for accountability under Art. 5(2).
          </li>
        </ul>

        <h2>HIPAA Requirements (US Deployments)</h2>
        <p>
          If the deployment processes Protected Health Information (PHI) of US persons, HIPAA
          applies independently of GDPR. The operator must:
        </p>
        <LegalTable
          headers={['Requirement', 'Status', 'Notes']}
          rows={[
            ['BAA with EHR provider', <Req />, 'Epic and most covered entities provide standard BAAs; confirm scope covers SMART on FHIR access'],
            ['BAA with Compute provider (AWS)', <Req />, 'AWS standard BAA available under AWS Customer Agreement; confirm covers EC2, KMS, S3 Object Lock'],
            ['BAA with Database provider (CockroachDB)', <Req />, 'CockroachDB HIPAA-eligible tier required; standard tier is not covered'],
            ['BAA with IDV provider (Didit)', <Req />, 'Identity context only — no PHI payload; confirm BAA availability with Didit'],
            ['FHIR client registration', <Req />, 'Register VITE_FHIR_CLIENT_ID with each EHR provider; production client must not use demo-client-id'],
            ['Minimum necessary standard', 'Structural', 'Consent gate scopes OAuth to consented resource types only; structural minimum-necessary enforcement'],
            ['Breach notification', <Req />, 'HIPAA 60-day notification obligation; operator must maintain incident response procedure'],
            ['FHIR token revocation on erasure', <Req />, 'Operator must revoke the SMART on FHIR access token and delete the FHIR authorisation when the patient withdraws consent or exercises Art. 17 erasure'],
          ]}
        />

        <h2>Structural Constraints</h2>
        <ul>
          <li>
            <strong>Client-side sealing before storage:</strong> FHIR payloads are encrypted by the
            health vault client using participant-derived keys (HKDF-SHA256) before any data reaches the
            shystore canonical layer. The EHR provider and shyware canonical infrastructure never
            hold plaintext health records simultaneously.
          </li>
          <li>
            <strong>Consent-scoped OAuth token:</strong> The SMART on FHIR access token is scoped
            to the exact resource types the patient consented to. The EHR provider enforces this
            scope at the FHIR API layer independently of the shyware layer.
          </li>
          <li>
            <strong>No cross-participant enumeration:</strong> The shystore API structurally rejects
            bulk health record enumeration (verified: <code>GET /api/store/secrets/all</code> →
            403). The EHR provider's own data is subject to its own access controls.
          </li>
          <li>
            <strong>Art. 17 erasure path:</strong> Canonical deletion of sealed health blobs is
            verified (EHR ERASURE section of the shystore unit test suite). FHIR-side erasure
            requires separate FHIR token revocation by the operator — this is not automated by
            shyware.
          </li>
          <li>
            <strong>Authenticator surface isolation:</strong> The{' '}
            The authenticator surface (<code>shystore-v1</code> credential vault) does not transmit
            or receive EHR payloads. It issues a session credential to the health vault only.
          </li>
        </ul>

        <h2>Operator Obligations</h2>
        <ul>
          <li>Register a production FHIR client ID with each named EHR provider and configure <code>VITE_FHIR_CLIENT_ID</code> in the CI/CD environment before production build.</li>
          <li>Execute a signed DPA or BAA with each EHR provider and each sub-processor handling PHI (compute, database, IDV) before any health data flows.</li>
          <li>Deploy a counsel-reviewed Art. 9(2)(a) consent UI (operator's health vault surface) before enabling EHR import in production.</li>
          <li>Maintain a consent log (timestamp, resource types, consentId, withdrawal timestamp if applicable) under Art. 30(1).</li>
          <li>Implement FHIR access token revocation in the erasure workflow — shyware canonical deletion does not automatically revoke provider-side authorisation.</li>
          <li>Notify Shyware of any change of EHR provider at least 30 days in advance.</li>
          <li>Complete a HIPAA risk analysis if the deployment involves US persons' PHI.</li>
        </ul>

        <h2>Audit and Retention</h2>
        <p>
          Health record consent logs must be retained for the period required by applicable law
          (minimum 6 years under HIPAA; Art. 5(1)(e) storage limitation under GDPR). Consent records
          stored in the shystore ledger are subject to Art. 17 erasure on patient request, with the
          caveat that erasure of the consent record terminates the patient's ability to prove prior
          authorisation — document this tradeoff in the patient-facing consent UI.
        </p>
        <p>
          This schedule is incorporated by reference into the Shyware Data Processing Agreement and
          is published at{' '}
          <code>https://shyware.fyi/legal/privacy/dpia/dpa/schedule-health</code>. Swap the named
          provider by updating <code>store.ehr_provider</code> in <code>shyconfig.json</code> and
          executing a new DPA / BAA with the replacement provider before transitioning.
        </p>
      </LegalDocument>
    </PassphraseGate>
  );
}
