import { useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import { api } from '../lib/api.js';
import Krypto from './Krypto.jsx';

export default function Login({ onSignedIn }) {
  const { t, lang, setLang } = useI18n();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api.login(password);
      onSignedIn();
    } catch (err) {
      setError(err.message);
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="grid min-h-full place-items-center px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-end gap-4">
          <Krypto className="h-24 w-20" mood={error ? 'alert' : 'calm'} />
          <h1 className="font-display text-2xl font-bold">{t('login.title')}</h1>
        </div>
        <p className="mb-6 text-mist">{t('login.body')}</p>
        <form onSubmit={submit} className="space-y-3">
          <label htmlFor="password" className="block text-sm text-mist">{t('login.password')}</label>
          <input id="password" type="password" className="field" autoComplete="current-password" autoFocus
                 value={password} onChange={(e) => setPassword(e.target.value)} />
          {error && <p role="alert" className="text-sm text-coral">{error}</p>}
          <div className="flex items-center justify-between gap-3 pt-2">
            <button type="button" className="text-sm text-cyan" onClick={() => setLang(lang === 'en' ? 'hi' : 'en')}>
              {t('top.language')}
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy || !password}>
              {busy ? t('login.busy') : t('login.submit')}
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}
