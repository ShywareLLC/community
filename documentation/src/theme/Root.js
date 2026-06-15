import React from 'react';
import { useLocation } from '@docusaurus/router';
import PassphraseGate from '../components/PassphraseGate';

const PUBLIC_PREFIXES = ['/', '/contact', '/introduction'];

function isPublic(pathname) {
  if (pathname === '/') return true;
  return PUBLIC_PREFIXES.some(p => p !== '/' && pathname.startsWith(p));
}

export default function Root({ children }) {
  const { pathname } = useLocation();
  if (isPublic(pathname)) return <>{children}</>;
  return <PassphraseGate>{children}</PassphraseGate>;
}
