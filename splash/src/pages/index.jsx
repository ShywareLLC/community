import React, { useState } from 'react';
import Layout from '@theme/Layout';
import styles from './index.module.css';

const FOLD_AFTER = 'shychat-v1';

const EMBODIMENTS = [
  { id: 'shyvoting-hostile', contract: 'shyvoting-v1',   label: 'Elections',              description: 'Coercion-resistant anonymous ballots. Write-only posture on attested device. Hostile-regime ready.' },
  { id: 'shyvoting-civic',   contract: 'shyvoting-v1',   label: 'Civic Referenda',         description: 'Anonymous civic votes with operator-independent HSM-attested tally.' },
  { id: 'shywire',           contract: 'shywire-v1',     label: 'Private Value Transfer',  description: 'Conservation-auditable stablecoin transfers. Amount and sender unlinked in canonical state.' },
  { id: 'shycustody',        contract: 'shycustody-v1',  label: 'Commodity Custody',       description: 'Warehouse receipt system. Holder identity absent from canonical lot records.' },
  { id: 'shycontracts',      contract: 'shycontracts-v1', label: 'Anonymous Smart Contracts', description: 'Arbitrary anonymous bilateral contracts. Party identity non-derivable from canonical state. RBF is one contractType.' },
  { id: 'shyshares',         contract: 'shyshares-v1',   label: 'DAO Governance',          description: 'Wallet-weighted anonymous proposals. Delegation mapping structurally non-enumerable.' },
  { id: 'shychat',           contract: 'shychat-v1',     label: 'Private Messaging',       description: 'Anonymous dispatch. Sender identity structurally absent from canonical payload records.' },
  { id: 'shybrowser',        contract: 'shybrowser-v1',  label: 'Browser Analytics',       description: 'No sessionId–identity–activity triple derivable from canonical API. Structural, not policy.' },
  { id: 'shyrest',           contract: 'shyrest-v1',     label: 'Anonymous Submissions',   description: 'Sealed anonymous submission pipeline. Admin mailbox non-enumerable by submitters.' },
  { id: 'shylots',           contract: 'shylots-v1',     label: 'Sealed-Bid Auction',      description: 'Bid-to-bidder linkage non-derivable before close. Oracle-resistant settlement.' },
  { id: 'shystream',         contract: 'shystream-v1',   label: 'Private Streaming',       description: 'Viewer identity absent from canonical clip view records. Aggregate counts only.' },
  { id: 'shystore',          contract: 'shystore-v1',    label: 'Credential Vault',        description: 'Biometric key re-derivation. No seed phrase, no password. Art. 17 erasure tested.' },
  { id: 'shybets',           contract: 'shybets-v1',     label: 'Anonymous Betting',       description: 'Bettor identity non-enumerable by oracle. Settlement requires Merkle proof.' },
];

const PROPERTIES = [
  { label: 'Non-linkability',   value: 'structural — no join key between List 1 (payload) and List 2 (identity hash)' },
  { label: 'Verifiability',     value: 'operator-independent — count-match + HSM-signed disjoint Merkle roots' },
  { label: 'Recovery',          value: 'credential-free — biometric re-derivation, no seed phrase or password' },
  { label: 'Authority model',   value: '3–4 structurally separated parties; dual co-authorization enforced at validation layer' },
  { label: 'Latency',           value: '1–6 s block finality (Hyperledger Fabric / CometBFT BFT, no proof overhead)' },
  { label: 'GDPR',              value: '379/379 assertions pass on web, iOS, and Android stacks' },
];


export default function Home() {
  const [expanded, setExpanded] = useState(false);
  const foldIdx = EMBODIMENTS.findIndex(e => e.contract === FOLD_AFTER);
  const visible = expanded ? EMBODIMENTS : EMBODIMENTS.slice(0, foldIdx + 1);
  const hiddenCount = EMBODIMENTS.length - (foldIdx + 1);

  return (
    <Layout title="shyware" description="anonymous by design. auditable by law.">
      <main className={styles.main}>

        <header className={styles.hero}>
          <p className={styles.tagline}>anonymous by design. auditable by law.</p>
          <p className={styles.sub}>
            Anonymous distributed-ledger protocol. Structural non-linkability across
            voting, wire transfer, custody, contracts, and governance — one invariant, thirteen embodiments.
          </p>
          <div className={styles.ctaRow}>
            <a href="https://docs.shyware.fyi/introduction/" className={styles.btnPrimary}>Read the docs</a>
            <a href="/license" className={styles.btnSecondary}>Get a license</a>
          </div>
        </header>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Protocol properties</h2>
          <div className={styles.propertyList}>
            {PROPERTIES.map(p => (
              <div className={styles.propertyRow} key={p.label}>
                <span className={styles.propertyLabel}>{p.label}</span>
                <span className={styles.propertyValue}>{p.value}</span>
              </div>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Embodiment examples</h2>
          <p className={styles.sectionSub}>
            13 contract variants. Each is a reference implementation — build your own on any variant.
          </p>
          <div className={styles.deployGrid}>
            {visible.map(d => (
              <div key={d.id} className={styles.deployCard}>
                <span className={styles.deployContract}>{d.contract}</span>
                <span className={styles.deployLabel}>{d.label}</span>
                <p className={styles.deployDesc}>{d.description}</p>
              </div>
            ))}
          </div>
          <button
            className={styles.toggleBtn}
            onClick={() => setExpanded(e => !e)}
            aria-expanded={expanded}
          >
            <span className={styles.toggleKey}>"show_all_embodiments"</span>
            <span className={styles.toggleColon}>:</span>
            <span className={`${styles.toggleVal}${expanded ? ` ${styles.toggleValTrue}` : ''}`}>
              {expanded ? 'true' : 'false'}
            </span>
            {!expanded && <span className={styles.toggleHint}>// +{hiddenCount} more</span>}
          </button>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Install</h2>
          <pre className={styles.codeBlock}><code>npm install @shyware/sdk</code></pre>
          <div className={styles.repoRow}>
            <a href="https://github.com/ShywareLLC/sdk" className={styles.repoLink} target="_blank" rel="noreferrer">
              <span className={styles.repoIcon}>⬡</span> ShywareLLC/sdk <span className={styles.repoTag}>JavaScript</span>
            </a>
            <a href="https://github.com/ShywareLLC/sdk-ios" className={styles.repoLink} target="_blank" rel="noreferrer">
              <span className={styles.repoIcon}>⬡</span> ShywareLLC/sdk-ios <span className={styles.repoTag}>Swift</span>
            </a>
            <a href="https://github.com/ShywareLLC/sdk-android" className={styles.repoLink} target="_blank" rel="noreferrer">
              <span className={styles.repoIcon}>⬡</span> ShywareLLC/sdk-android <span className={styles.repoTag}>Kotlin</span>
            </a>
          </div>
        </section>

        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>How it works</h2>
          <pre className={styles.codeBlock}><code>{`// Submission: two unlinked atomic writes
//   List 1 (payload record)     — no identity
//   List 2 (participant record) — no payload, no submission ID
//
// Count-match invariant at period close:
//   |L1(S)| === |L2(S)|   ← verifiable by arithmetic
//
// HSM-backed period-close attestation:
//   σ = Sign_KMS( H(root_L1 ‖ root_L2 ‖ N ‖ domain_aggregate) )
//   Verifiable by any party with the HSM public key`}</code></pre>
        </section>


      </main>
    </Layout>
  );
}
