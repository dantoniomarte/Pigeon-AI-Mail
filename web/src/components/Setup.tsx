import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowRight, Inbox, KeyRound, Lock, Moon, Send, ShieldCheck, Sun } from 'lucide-react';

import type { Theme } from '../api';
import { LanguageSelect, MotionSwitch, PigeonLogo } from './TopBar';

export interface SetupProps {
  onReady: (key: string) => void;
  lang: string;
  onLangChange: (code: string) => void;
  theme: Theme;
  onToggleTheme: () => void;
  motion: boolean;
  onToggleMotion: () => void;
}

export default function Setup({
  onReady,
  lang,
  onLangChange,
  theme,
  onToggleTheme,
  motion,
  onToggleMotion,
}: SetupProps): JSX.Element {
  const { t } = useTranslation();
  const inputId = useId();
  const errorId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [key, setKey] = useState('');
  const [error, setError] = useState(false);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const submit = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const candidate = key.trim();
      if (!candidate.startsWith('pk_') || candidate.length < 8) {
        setError(true);
        inputRef.current?.focus();
        return;
      }
      setError(false);
      onReady(candidate);
    },
    [key, onReady],
  );

  return (
    <div className="setup">
      <div className="setup__aurora" aria-hidden="true">
        <span className="setup__orb setup__orb--one" />
        <span className="setup__orb setup__orb--two" />
      </div>

      <header className="setup__top">
        <div className="brand">
          <PigeonLogo size={30} />
          <span className="brand__name">
            Pigeon<span className="brand__accent">Mail</span>
          </span>
        </div>
        <div className="setup__controls">
          <LanguageSelect lang={lang} onChange={onLangChange} />
          <button
            type="button"
            className="icon-btn"
            onClick={onToggleTheme}
            aria-label={`${t('common.theme')}: ${theme === 'dark' ? t('common.light') : t('common.dark')}`}
          >
            {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <MotionSwitch motion={motion} onToggle={onToggleMotion} compact />
        </div>
      </header>

      <main className="setup__grid">
        <section className="setup__pitch">
          <span className="eyebrow">{t('setup.eyebrow')}</span>
          <h1 className="setup__title">
            {t('setup.title')}
            <span className="setup__title-mark" aria-hidden="true" />
          </h1>
          <p className="setup__subtitle">{t('setup.subtitle')}</p>

          <ul className="setup__steps">
            <li className="setup__step">
              <span className="setup__step-icon">
                <Inbox size={17} aria-hidden="true" />
              </span>
              <div>
                <h2>{t('setup.step1Title')}</h2>
                <p>{t('setup.step1Body')}</p>
              </div>
            </li>
            <li className="setup__step">
              <span className="setup__step-icon">
                <Lock size={17} aria-hidden="true" />
              </span>
              <div>
                <h2>{t('setup.step2Title')}</h2>
                <p>{t('setup.step2Body')}</p>
              </div>
            </li>
            <li className="setup__step">
              <span className="setup__step-icon">
                <Send size={17} aria-hidden="true" />
              </span>
              <div>
                <h2>{t('setup.step3Title')}</h2>
                <p>{t('setup.step3Body')}</p>
              </div>
            </li>
          </ul>
        </section>

        <section className="setup__card" aria-labelledby={`${inputId}-title`}>
          <div className="setup__card-top">
            <span className="setup__lock" aria-hidden="true">
              <Lock size={20} />
            </span>
            <span className="pill pill--secure">
              <ShieldCheck size={13} aria-hidden="true" />
              {t('app.secure')}
            </span>
          </div>

          <h2 className="setup__card-title" id={`${inputId}-title`}>
            {t('setup.label')}
          </h2>
          <p className="setup__card-body">{t('setup.hint')}</p>

          <form className="setup__form" onSubmit={submit} noValidate>
            <label className="field" htmlFor={inputId}>
              <span className="field__label">
                <KeyRound size={14} aria-hidden="true" />
                {t('setup.label')}
              </span>
              <div className={`field__input${error ? ' has-error' : ''}`}>
                <Lock size={16} aria-hidden="true" className="field__icon" />
                <input
                  id={inputId}
                  ref={inputRef}
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={t('setup.placeholder')}
                  value={key}
                  aria-describedby={error ? errorId : undefined}
                  aria-invalid={error}
                  onChange={(event) => {
                    setKey(event.target.value);
                    if (error) {
                      setError(false);
                    }
                  }}
                />
              </div>
            </label>

            {error ? (
              <p className="field__error" id={errorId} role="alert">
                {t('setup.invalid')}
              </p>
            ) : null}

            <button type="submit" className="btn btn--primary btn--lg btn--block">
              {t('setup.submit')}
              <ArrowRight size={16} aria-hidden="true" />
            </button>
          </form>

          <div className="setup__note">
            <ShieldCheck size={16} aria-hidden="true" />
            <div>
              <strong>{t('setup.securityTitle')}</strong>
              <p>{t('setup.securityBody')}</p>
            </div>
          </div>
        </section>
      </main>

      <footer className="setup__footer">
        <span>{t('app.tagline')}</span>
        <span className="setup__footer-dot" aria-hidden="true" />
        <span>{t('auth.storedLocally')}</span>
      </footer>
    </div>
  );
}
