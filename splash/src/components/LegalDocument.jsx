import React from 'react';
import Layout from '@theme/Layout';

const styles = {
  page: {
    maxWidth: 800,
    margin: '0 auto',
    padding: '3rem 1.5rem 5rem',
    color: 'var(--ifm-font-color-base)',
    fontFamily: 'var(--ifm-font-family-base)',
    lineHeight: 1.7,
  },
  header: {
    borderBottom: '1px solid var(--ifm-color-emphasis-200)',
    paddingBottom: '1.5rem',
    marginBottom: '2.5rem',
  },
  eyebrow: {
    fontSize: '0.75rem',
    fontWeight: 600,
    letterSpacing: '0.1em',
    textTransform: 'uppercase',
    color: 'var(--ifm-color-primary)',
    marginBottom: '0.4rem',
  },
  title: {
    fontSize: '2rem',
    fontWeight: 700,
    color: 'var(--ifm-heading-color)',
    margin: '0 0 0.4rem',
    letterSpacing: '-0.02em',
  },
  meta: {
    fontSize: '0.8rem',
    color: 'var(--ifm-color-emphasis-600)',
    display: 'flex',
    gap: '1.5rem',
    flexWrap: 'wrap',
    alignItems: 'center',
  },
  pdfBtn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.3rem',
    padding: '0.3rem 0.7rem',
    background: 'transparent',
    border: '1px solid var(--ifm-color-emphasis-300)',
    borderRadius: '5px',
    color: 'var(--ifm-color-emphasis-600)',
    fontSize: '0.75rem',
    textDecoration: 'none',
    transition: 'border-color 0.15s, color 0.15s',
  },
  section: {
    marginBottom: '2.5rem',
  },
  h2: {
    fontSize: '1.15rem',
    fontWeight: 700,
    color: 'var(--ifm-heading-color)',
    margin: '2rem 0 0.6rem',
    paddingBottom: '0.4rem',
    borderBottom: '1px solid var(--ifm-color-emphasis-200)',
  },
  h3: {
    fontSize: '0.95rem',
    fontWeight: 600,
    color: 'var(--ifm-heading-color)',
    margin: '1.4rem 0 0.4rem',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '0.85rem',
    margin: '1rem 0',
  },
  th: {
    padding: '0.5rem 0.75rem',
    textAlign: 'left',
    background: 'var(--ifm-color-emphasis-100)',
    borderBottom: '1px solid var(--ifm-color-emphasis-300)',
    color: 'var(--ifm-color-emphasis-700)',
    fontWeight: 600,
    fontSize: '0.75rem',
  },
  td: {
    padding: '0.5rem 0.75rem',
    borderBottom: '1px solid var(--ifm-color-emphasis-200)',
    verticalAlign: 'top',
  },
  required: {
    fontFamily: 'var(--ifm-font-family-monospace)',
    fontSize: '0.75rem',
    color: '#f59e0b',
    background: 'rgba(245,158,11,0.1)',
    padding: '0.1rem 0.3rem',
    borderRadius: '3px',
  },
  code: {
    fontFamily: 'var(--ifm-font-family-monospace)',
    fontSize: '0.8rem',
    color: 'var(--ifm-color-primary)',
    background: 'var(--ifm-code-background)',
    padding: '0.1rem 0.35rem',
    borderRadius: '3px',
  },
  breadcrumb: {
    fontSize: '0.78rem',
    color: 'var(--ifm-color-emphasis-500)',
    marginBottom: '1.5rem',
    display: 'flex',
    gap: '0.4rem',
    alignItems: 'center',
  },
  breadcrumbLink: {
    color: 'var(--ifm-color-emphasis-600)',
    textDecoration: 'none',
  },
  sep: { color: 'var(--ifm-color-emphasis-300)' },
};

export function Req() {
  return <span style={styles.required}>REQUIRED_OPERATOR_INPUT</span>;
}

export function Code({ children }) {
  return <code style={styles.code}>{children}</code>;
}

export function LegalTable({ headers, rows }) {
  return (
    <table style={styles.table}>
      <thead>
        <tr>{headers.map((h, i) => <th key={i} style={styles.th}>{h}</th>)}</tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>{row.map((cell, j) => <td key={j} style={styles.td}>{cell}</td>)}</tr>
        ))}
      </tbody>
    </table>
  );
}

export function Breadcrumb({ crumbs }) {
  return (
    <div style={styles.breadcrumb}>
      {crumbs.map((c, i) => (
        <React.Fragment key={i}>
          {i > 0 && <span style={styles.sep}>/</span>}
          {c.href
            ? <a href={c.href} style={styles.breadcrumbLink}>{c.label}</a>
            : <span style={{ color: 'var(--ifm-color-emphasis-700)' }}>{c.label}</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

export default function LegalDocument({ title, eyebrow, effectiveDate, pdfHref, docxHref, breadcrumbs, children }) {
  return (
    <Layout title={title} description={`${title} — shyware.fyi/legal`}>
      <div style={styles.page}>
        {breadcrumbs && <Breadcrumb crumbs={breadcrumbs} />}
        <div style={styles.header}>
          {eyebrow && <div style={styles.eyebrow}>{eyebrow}</div>}
          <h1 style={styles.title}>{title}</h1>
          <div style={styles.meta}>
            {effectiveDate && <span>Effective: {effectiveDate}</span>}
            {pdfHref && (
              <a href={pdfHref} style={styles.pdfBtn} download>
                ↓ PDF
              </a>
            )}
            {docxHref && (
              <a href={docxHref} style={{...styles.pdfBtn, marginLeft: '0.4rem'}} download>
                ↓ DOCX
              </a>
            )}
          </div>
        </div>
        {children}
      </div>
    </Layout>
  );
}

export { styles };
