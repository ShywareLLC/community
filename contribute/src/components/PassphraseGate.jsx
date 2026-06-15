import React, { useState, useEffect } from 'react';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

const SESSION_KEY = 'shyware_docs_access';

export default function PassphraseGate({ children }) {
  const { siteConfig: { customFields } } = useDocusaurusContext();
  const passphrase = customFields?.docsPassphrase;

  // Start false on server (avoids SSR/CSR hydration mismatch that breaks form events).
  // useEffect runs only on the client after hydration completes.
  const [granted, setGranted] = useState(false);

  useEffect(() => {
    if (!passphrase) { setGranted(true); return; }
    try { if (sessionStorage.getItem(SESSION_KEY) === '1') setGranted(true); } catch {}
  }, [passphrase]);
  const [input, setInput] = useState('');
  const [error, setError] = useState(false);

  if (granted) return children;

  function handleSubmit(e) {
    e.preventDefault();
    if (input === passphrase) {
      try { sessionStorage.setItem(SESSION_KEY, '1'); } catch {}
      setGranted(true);
    } else {
      setError(true);
      setInput('');
    }
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      minHeight: '100vh', background: '#09090b',
    }}>
      <div style={{
        background: '#18181b', border: '1px solid #27272a', borderRadius: '12px',
        padding: '2.5rem 2rem', width: '100%', maxWidth: '360px', textAlign: 'center',
      }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={{
            fontSize: '1.4rem', fontWeight: 700, color: '#a78bfa', letterSpacing: '-0.02em',
          }}>shyware</div>
          <div style={{ color: '#71717a', fontSize: '0.85rem', marginTop: '0.25rem' }}>
            pre-provisional access only
          </div>
        </div>
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            autoFocus
            autoComplete="off"
            placeholder="passphrase"
            value={input}
            onChange={e => { setInput(e.target.value); setError(false); }}
            style={{
              width: '100%', padding: '0.6rem 0.8rem', marginBottom: '0.75rem',
              background: '#09090b', border: `1px solid ${error ? '#ef4444' : '#3f3f46'}`,
              borderRadius: '6px', color: '#fafafa', fontSize: '0.95rem',
              outline: 'none', boxSizing: 'border-box',
            }}
          />
          <button
            type="submit"
            style={{
              width: '100%', padding: '0.6rem', background: '#7c3aed',
              border: 'none', borderRadius: '6px', color: '#fff',
              fontSize: '0.95rem', fontWeight: 600, cursor: 'pointer',
            }}
          >
            Enter
          </button>
        </form>
        {error && (
          <p style={{ color: '#ef4444', fontSize: '0.8rem', marginTop: '0.75rem' }}>
            incorrect passphrase
          </p>
        )}
      </div>
    </div>
  );
}
