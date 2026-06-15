import React from 'react';
import LegalDocument, { LegalTable } from '../../../components/LegalDocument';

const breadcrumbs = [
  { label: 'legal', href: '/legal/' },
  { label: 'compliance' },
];

export default function ComplianceGuide() {
  return (
    <LegalDocument
      title="SDK Compliance Guide"
      eyebrow="shyware.fyi/legal/compliance"
      effectiveDate="upon publication"
      pdfHref="/legal/compliance/compliance-guide.pdf"
      docxHref="/legal/compliance/compliance-guide.docx"
      breadcrumbs={breadcrumbs}
    >
      <p>
        This guide describes how the shyware SDK supports SaaS customers acting as controllers
        for their users' personal data. shyware processes customer user data only to provide,
        secure, maintain, and support the SDK and related services under the customer's documented
        instructions.
      </p>
      <h2>Operator Obligations</h2>
      <LegalTable
        headers={['Obligation', 'Description']}
        rows={[
          ['Art. 6 lawfulness basis', 'Identify and document the legal basis for each processing purpose before production. Template: privacy policy §Legal Basis.'],
          ['Art. 9 special category consent', 'Required if biometric IDV is invoked — either as the primary identity.provider (didit) or as a break-glass biometric_rederive flow (e.g. shystore-v1 with recovery_mode: operator_sealer). Obtain explicit written consent before enrollment. Some jurisdictions prohibit biometric processing entirely; complete a biometric DPIA before production.'],
          ['Art. 28 sub-processor DPAs', 'Execute signed DPAs with all providers listed in the generated Records of Processing before processing personal data.'],
          ['Art. 30 Records of Processing', 'Generate from shyconfig: node scripts/generate-rop.mjs --config shyconfig.json. Complete REQUIRED_OPERATOR_INPUT fields.'],
          ['Storage limitation (Art. 5(1)(e))', 'Add retention block to shyconfig.json with deletion_cron. Operationally enforce the cron schedule.'],
          ['Key independence', 'Verify eligibility_authority_key ≠ reconciling_authority_key ≠ auth_key at scoping-identifier creation.'],
          ['Quarterly independent audit', 'Engage an independent auditor to verify three-authority operational separation before production and quarterly thereafter.'],
          ['Database backup', 'Cert-tier-dependent — not a blanket SDK mandate. Single-node deployments without BFT consensus cannot prevent operator purge by construction; OTel/CloudWatch logging provides detection only. Backup strategy and redundancy requirements are specified in the per-domain DPIA regulatory annexes for your deployment context.'],
        ]}
      />
      <h2>Records of Processing Generator</h2>
      <p>
        Run <code>node scripts/generate-rop.mjs --config shyconfig.json --format md</code> to
        generate a pre-filled Art. 30 RoP from your deployment's shyconfig. All fields derivable
        from the config are pre-filled; operator-specific fields are marked{' '}
        <code>REQUIRED_OPERATOR_INPUT</code>.
      </p>
      <p>92 assertions verify correct structure for all 13 contract versions.</p>
    </LegalDocument>
  );
}
