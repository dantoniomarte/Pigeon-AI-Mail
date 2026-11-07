import { ChevronDown, Globe, Menu, Moon, PenLine, ShieldCheck, Sun, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import type { Theme } from '../api';
import { LANGUAGES } from '../i18n';

export interface TopBarProps {
  lang: string;
  onLangChange: (code: string) => void;
  theme: Theme;
  onToggleTheme: () => void;
  motion: boolean;
  onToggleMotion: () => void;
  onOpenSidebar: () => void;
  sidebarOpen: boolean;
  onCompose: () => void;
}

/** Inline pigeon mark — no external assets, colours come from tokens. */
export function PigeonLogo({ size = 28 }: { size?: number }): JSX.Element {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="9" fill="var(--accent)" />
      <path d="M7 18c4-7 9-9 15-8l-4 4c3 0 5 1 7 3-5-1-8 0-10 2-3 2-6 2-8-1z" fill="#fff" />
    </svg>
  );
}

export function LanguageSelect({
  lang,
  onChange,
  id,
}: {
  lang: string;
  onChange: (code: string) => void;
  id?: string;
}): JSX.Element {
  const { t } = useTranslation();
  return (
    <div className="select">
      <Globe size={15} aria-hidden="true" className="select__icon" />
      <select
        id={id}
        className="select__input"
        value={lang}
        aria-label={t('common.language')}
        onChange={(event) => onChange(event.target.value)}
      >
        {LANGUAGES.map((language) => (
          <option key={language.code} value={language.code}>
            {language.label}
          </option>
        ))}
      </select>
      <ChevronDown size={14} aria-hidden="true" className="select__chevron" />
    </div>
  );
}

export function MotionSwitch({
  motion,
  onToggle,
  compact = false,
}: {
  motion: boolean;
  onToggle: () => void;
  compact?: boolean;
}): JSX.Element {
  const { t } = useTranslation();
  return (
    <button
      type="button"
      className={`motion-switch${motion ? ' is-on' : ''}${compact ? ' motion-switch--compact' : ''}`}
      onClick={onToggle}
      role="switch"
      aria-checked={motion}
      aria-label={t('common.motion')}
      title={`${t('common.motion')}: ${motion ? t('common.on') : t('common.off')}`}
    >
      <span className="motion-switch__label">{t('common.motion')}</span>
      <span className="motion-switch__track" aria-hidden="true">
        <span className="motion-switch__thumb" />
      </span>
      <span className="motion-switch__state" aria-hidden="true">
        {motion ? t('common.on') : t('common.off')}
      </span>
    </button>
  );
}

export default function TopBar({
  lang,
  onLangChange,
  theme,
  onToggleTheme,
  motion,
  onToggleMotion,
  onOpenSidebar,
  sidebarOpen,
  onCompose,
}: TopBarProps): JSX.Element {
  const { t } = useTranslation();

  return (
    <header className="topbar">
      <div className="topbar__left">
        <button
          type="button"
          className="icon-btn topbar__menu"
          onClick={onOpenSidebar}
          aria-label={sidebarOpen ? t('common.closeMenu') : t('common.openMenu')}
          aria-expanded={sidebarOpen}
        >
          {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
        <div className="brand">
          <PigeonLogo />
          <span className="brand__name">
            Pigeon<span className="brand__accent">Mail</span>
          </span>
        </div>
      </div>

      <div className="topbar__center">
        <span className="pill pill--secure">
          <ShieldCheck size={14} aria-hidden="true" />
          {t('app.secure')}
        </span>
      </div>

      <div className="topbar__right">
        <LanguageSelect lang={lang} onChange={onLangChange} />
        <button
          type="button"
          className="lang-cycle"
          aria-label={t('common.language')}
          title={t('common.language')}
          onClick={() => {
            const index = LANGUAGES.findIndex((language) => language.code === lang);
            const next = LANGUAGES[(index + 1) % LANGUAGES.length];
            if (next !== undefined) {
              onLangChange(next.code);
            }
          }}
        >
          {lang.toUpperCase()}
        </button>
        <button
          type="button"
          className="icon-btn topbar__theme"
          onClick={onToggleTheme}
          aria-label={`${t('common.theme')}: ${theme === 'dark' ? t('common.light') : t('common.dark')}`}
          title={`${t('common.theme')}: ${theme === 'dark' ? t('common.light') : t('common.dark')}`}
        >
          {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
        </button>
        <MotionSwitch motion={motion} onToggle={onToggleMotion} />
        <button type="button" className="btn btn--primary topbar__compose" onClick={onCompose}>
          <PenLine size={16} aria-hidden="true" />
          <span>{t('nav.compose')}</span>
        </button>
      </div>
    </header>
  );
}
