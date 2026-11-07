import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, Mail, ShieldCheck } from 'lucide-react';

import { login, TwoFaRequiredError } from '../api';

export interface LoginProps {
  onSuccess: (email: string) => void;
  onUseApiKey?: () => void;
}

export default function Login({ onSuccess, onUseApiKey }: LoginProps): JSX.Element {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [needsCode, setNeedsCode] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!email.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    login(email.trim(), needsCode && code.trim() ? code.trim() : undefined)
      .then(() => onSuccess(email.trim()))
      .catch((err: unknown) => {
        setSubmitting(false);
        if (err instanceof TwoFaRequiredError) {
          setNeedsCode(true);
          return;
        }
        setError(t('login.error'));
      });
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <svg viewBox="0 0 32 32" width="44" height="44" aria-hidden="true" className="login-logo">
          <rect width="32" height="32" rx="9" fill="var(--accent)" />
          <path d="M7 18c4-7 9-9 15-8l-4 4c3 0 5 1 7 3-5-1-8 0-10 2-3 2-6 2-8-1z" fill="#fff" />
        </svg>
        <h1>{t('login.title')}</h1>
        <p className="login-card__hint">{t('login.hint')}</p>

        <label className="field field--plain">
          <span className="field__label">{t('login.email')}</span>
          <input
            className="input"
            type="email"
            autoComplete="username"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('login.emailPlaceholder')}
            required
          />
        </label>

        {needsCode ? (
          <label className="field field--plain">
            <span className="field__label">
              <ShieldCheck size={13} aria-hidden="true" /> {t('login.code')}
            </span>
            <input
              className="input"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={t('login.codePlaceholder')}
              autoFocus
            />
          </label>
        ) : null}

        {error !== null ? (
          <p className="login-card__error" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="btn btn--primary" disabled={submitting || !email.trim()}>
          {submitting ? <Loader2 size={16} className="spin" aria-hidden="true" /> : <Mail size={16} aria-hidden="true" />}
          {needsCode ? t('login.confirm') : t('login.continue')}
        </button>

        {onUseApiKey ? (
          <button
            type="button"
            className="login-card__api-key-link"
            onClick={onUseApiKey}
          >
            {t('login.useApiKey')}
          </button>
        ) : null}
      </form>
    </div>
  );
}
