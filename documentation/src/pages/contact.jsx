import React, { useState } from 'react';
import Layout from '@theme/Layout';
import styles from './index.module.css';

const EMAIL = 'inquiries@shyware.fyi';

export default function Contact() {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard?.writeText(EMAIL).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <Layout title="Contact" description="Get in touch with the shyware team.">
      <div className={styles.page} style={{ gap: 32, paddingTop: 120 }}>
        <header className={styles.hero} style={{ gap: 12 }}>
          <p className={styles.tagline}>Contact</p>
          <p className={styles.sub}>
            Licensing, legal review, or deployment questions — reach the Shyware team directly.
          </p>
        </header>

        <section className={styles.section} style={{ maxWidth: 480, margin: '0 auto' }}>
          <div className={styles.propertyList}>
            <div className={styles.propertyRow}>
              <span className={styles.propertyLabel}>Legal &amp; licensing</span>
              <span className={styles.propertyValue}>
                <a href={`mailto:${EMAIL}`}>{EMAIL}</a>
                <button
                  onClick={copy}
                  style={{
                    marginLeft: 10,
                    padding: '2px 8px',
                    fontSize: 11,
                    background: 'transparent',
                    border: '1px solid var(--ifm-color-emphasis-300)',
                    borderRadius: 4,
                    cursor: 'pointer',
                    color: 'var(--ifm-color-emphasis-600)',
                  }}
                >
                  {copied ? 'copied' : 'copy'}
                </button>
              </span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyLabel}>Company</span>
              <span className={styles.propertyValue}>
                <a href="https://shyware.fyi" target="_blank" rel="noopener noreferrer">shyware.fyi</a>
              </span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyLabel}>DPIA / privacy</span>
              <span className={styles.propertyValue}>
                <a href="/legal/privacy/">shyware.fyi/legal/privacy/</a>
              </span>
            </div>
          </div>

          <p style={{ fontSize: 13, color: 'var(--ifm-color-emphasis-500)', marginTop: 20, lineHeight: 1.6 }}>
            If your email client doesn't open automatically, copy the address above or find it at{' '}
            <a href="/legal/">shyware.fyi/legal/</a>.
          </p>
        </section>
      </div>
    </Layout>
  );
}
