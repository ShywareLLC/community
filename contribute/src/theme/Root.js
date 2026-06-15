import React from 'react';
import PassphraseGate from '../components/PassphraseGate';

export default function Root({ children }) {
  return <PassphraseGate>{children}</PassphraseGate>;
}
