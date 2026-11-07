import { useTranslation } from 'react-i18next';
import { ArrowRight, KeyRound, LogIn, ShieldCheck } from 'lucide-react';

export interface LandingProps {
  onLogin: () => void;
  onApiKey: () => void;
}

/** Public landing screen — what a fresh visitor sees before signing in. */
export default function Landing({ onLogin, onApiKey }: LandingProps): JSX.Element {
  const { t } = useTranslation();

  return (
    <div className="landing">
      <header className="landing__nav">
        <span className="landing__brand">
          <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true">
            <rect width="32" height="32" rx="9" fill="var(--accent)" />
            <path d="M7 18c4-7 9-9 15-8l-4 4c3 0 5 1 7 3-5-1-8 0-10 2-3 2-6 2-8-1z" fill="#fff" />
          </svg>
          Pigeon Mail
        </span>
        <span className="landing__badge">
          <ShieldCheck size={14} aria-hidden="true" /> {t('landing.badge')}
        </span>
      </header>

      <main className="landing__hero">
        <h1>{t('landing.title')}</h1>
        <p className="landing__subtitle">{t('landing.subtitle')}</p>

        <div className="landing__actions">
          <button type="button" className="btn btn--primary btn--large" onClick={onLogin}>
            <LogIn size={18} aria-hidden="true" /> {t('landing.signIn')}
            <ArrowRight size={16} aria-hidden="true" />
          </button>
          <button type="button" className="btn btn--ghost btn--large" onClick={onApiKey}>
            <KeyRound size={18} aria-hidden="true" /> {t('landing.apiKey')}
          </button>
        </div>

        <ul className="landing__points">
          <li>{t('landing.pointEncrypted')}</li>
          <li>{t('landing.pointAgents')}</li>
          <li>{t('landing.pointSelfHosted')}</li>
        </ul>
      </main>

      <footer className="landing__footer">
        <span>{t('landing.footerTagline')}</span>
      </footer>
    </div>
  );
}
