import React, { useState } from 'react';
import Layout from '@theme/Layout';
import styles from './license.module.css';

const PORTAL_OPEN = false; // set true when Stripe + Found accounts are live

// ─── Stripe Payment Link URLs ─────────────────────────────────────────────────
// Create a Product + Price in your Stripe dashboard, then paste the Payment
// Link URL here.  Format: https://buy.stripe.com/XXXX
// Leave as null to show "Request pricing" instead of a buy button.
const STRIPE_LINKS = {
  'shychat-v1':      null, // TODO: add Stripe Payment Link
  'shybrowser-v1':   null,
  'shyrest-v1':      null,
  'shystream-v1':    null,
  'shybets-v1':      null,
  'shyshares-v1':    null,
  'shylots-v1':      null,
  'shycontracts-v1': null,
};

// Enterprise only — always requires Commercial License Agreement
// shyvoting-v1: government contracts
// shywire-v1:   AML/stablecoin regulation
// shycustody-v1: warehouse/financial regulation
// shystore-v1:  HIPAA BAA required

const DOMAINS = [
  {
    contract: 'shyvoting-v1',
    label: 'Elections & Referenda',
    unit: 'per election',
    tier: 'enterprise',
    anchor: 'Electoral fraud liability; election administration contract value',
  },
  {
    contract: 'shywire-v1',
    label: 'Private Value Transfer',
    unit: 'basis points on transaction volume',
    tier: 'enterprise',
    anchor: 'AML/OFAC exposure; transaction fraud',
  },
  {
    contract: 'shycustody-v1',
    label: 'Commodity Custody',
    unit: 'basis points on AUM',
    tier: 'enterprise',
    anchor: 'Redemption fraud; custody liability',
  },
  {
    contract: 'shystore-v1',
    label: 'Health Vault',
    unit: 'per patient / year',
    tier: 'enterprise',
    anchor: 'HIPAA BAA required; 42 CFR Part 2 enforcement active (OCR delegation Feb 2026); OCR penalty up to $2M; breach class action',
  },
  {
    contract: 'shycontracts-v1',
    label: 'Revenue Financing',
    unit: 'per contract or % of financed volume',
    tier: 'self-serve',
    anchor: 'Default/fraud exposure; lender liability',
  },
  {
    contract: 'shyshares-v1',
    label: 'DAO Governance',
    unit: 'per member / year',
    tier: 'self-serve',
    anchor: 'Governance manipulation; securities liability',
  },
  {
    contract: 'shylots-v1',
    label: 'Sealed-Bid Auction',
    unit: 'per lot or per auction',
    tier: 'self-serve',
    anchor: 'Allocation fraud; fair housing liability',
  },
  {
    contract: 'shybets-v1',
    label: 'Betting & Prediction Markets',
    unit: 'per active user / year',
    tier: 'self-serve',
    anchor: 'Gambling regulatory fines; responsible gaming liability',
  },
  {
    contract: 'shychat-v1',
    label: 'Private Chat (Scytale)',
    unit: 'per active user / year',
    tier: 'self-serve',
    anchor: 'Metadata exposure; communications interception liability',
  },
  {
    contract: 'shystream-v1',
    label: 'Private Streaming',
    unit: 'per viewer / year',
    tier: 'self-serve',
    anchor: 'CDN correlation liability; GDPR fines',
  },
  {
    contract: 'shybrowser-v1',
    label: 'Anonymous Browser Analytics',
    unit: 'per deployment / year',
    tier: 'self-serve',
    anchor: 'GDPR fines; cookie consent liability',
  },
  {
    contract: 'shyrest-v1',
    label: 'Anonymous Submissions / Whistleblowing',
    unit: 'per submission or per deployment',
    tier: 'self-serve',
    anchor: 'EU Whistleblower Directive penalties; retaliation liability',
  },
];

function DomainCard({ domain }) {
  const link = STRIPE_LINKS[domain.contract];
  const isSelf = domain.tier === 'self-serve';

  return (
    <div className={`${styles.card} ${isSelf ? styles.cardSelf : styles.cardEnterprise}`}>
      <div className={styles.cardHeader}>
        <span className={styles.contract}>{domain.contract}</span>
        {isSelf
          ? <span className={styles.badge}>Self-serve</span>
          : <span className={`${styles.badge} ${styles.badgeEnterprise}`}>Enterprise</span>
        }
      </div>
      <h3 className={styles.cardLabel}>{domain.label}</h3>
      <p className={styles.unit}>{domain.unit}</p>
      <p className={styles.anchor}>{domain.anchor}</p>
      <div className={styles.cardAction}>
        {isSelf && link && PORTAL_OPEN
          ? <a href={link} className={styles.btnBuy} target="_blank" rel="noreferrer">License now →</a>
          : isSelf && !PORTAL_OPEN
          ? <span className={styles.btnDisabled}>Coming soon</span>
          : <a href="mailto:inquiries@shyware.fyi" className={styles.btnContact}>Request pricing</a>
        }
      </div>
    </div>
  );
}

export default function License() {
  const [filter, setFilter] = useState('all');
  const visible = DOMAINS.filter(d =>
    filter === 'all' ? true : d.tier === filter
  );

  return (
    <Layout title="Licensing — shyware" description="Commercial licenses for the Shyware SDK.">
      <main className={styles.main}>
        {!PORTAL_OPEN && (
          <div className={styles.banner}>
            Self-serve licensing portal opening shortly.
            Enterprise inquiries: <a href="mailto:inquiries@shyware.fyi">inquiries@shyware.fyi</a>
          </div>
        )}
        <header className={styles.hero}>
          <h1 className={styles.title}>Commercial License</h1>
          <p className={styles.sub}>
            Evaluation use is free. Production deployment requires a Commercial License Agreement
            with Shyware LLC. Self-serve licenses are available for smaller deployments.
            Enterprise pricing is custom — contact us.
          </p>
          <p className={styles.patent}>
            Patent Pending, U.S. App. No. 64/074,348 ·{' '}
            <a href="/legal">License terms</a> ·{' '}
            <a href="mailto:inquiries@shyware.fyi">inquiries@shyware.fyi</a>
          </p>
        </header>

        <div className={styles.filterRow}>
          {['all', 'self-serve', 'enterprise'].map(f => (
            <button
              key={f}
              className={`${styles.filterBtn} ${filter === f ? styles.filterBtnActive : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? 'All domains' : f === 'self-serve' ? 'Self-serve' : 'Enterprise'}
            </button>
          ))}
        </div>

        <div className={styles.grid}>
          {visible.map(d => <DomainCard key={d.contract} domain={d} />)}
        </div>

        <section className={styles.noteSection}>
          <h2 className={styles.noteTitle}>How licensing works</h2>
          <div className={styles.noteGrid}>
            <div className={styles.noteCard}>
              <span className={styles.noteHeading}>Evaluation</span>
              <p className={styles.noteBody}>
                Free. Download, integrate, and test. No production traffic.
                No end users. See <a href="/legal">LICENSE</a>.
              </p>
            </div>
            <div className={styles.noteCard}>
              <span className={styles.noteHeading}>Self-serve</span>
              <p className={styles.noteBody}>
                Stripe checkout. Annual license, single domain. Covers one
                production deployment up to the stated unit limit.
              </p>
            </div>
            <div className={styles.noteCard}>
              <span className={styles.noteHeading}>Enterprise</span>
              <p className={styles.noteBody}>
                Custom Commercial License Agreement. Volume pricing, SLA,
                BAA (HIPAA), and pilot structure available.
                Email <a href="mailto:inquiries@shyware.fyi">inquiries@shyware.fyi</a>.
              </p>
            </div>
            <div className={styles.noteCard}>
              <span className={styles.noteHeading}>Patent rights</span>
              <p className={styles.noteBody}>
                No patent license is granted by the SDK license alone.
                Patent rights (App. No. 64/074,348) are available separately
                under the Commercial License Agreement.
              </p>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
