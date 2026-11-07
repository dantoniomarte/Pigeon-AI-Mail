import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import de from './i18n/de.json';
import en from './i18n/en.json';
import es from './i18n/es.json';
import fr from './i18n/fr.json';
import pt from './i18n/pt.json';

export type LanguageCode = 'en' | 'es' | 'pt' | 'fr' | 'de';

export interface LanguageOption {
  code: LanguageCode;
  label: string;
}

export const LANGUAGES: readonly LanguageOption[] = [
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Español' },
  { code: 'pt', label: 'Português' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
];

export const LANGUAGE_STORAGE_KEY = 'pigeon_lang';

const SUPPORTED: readonly string[] = LANGUAGES.map((language) => language.code);

export function isLanguageCode(value: string): value is LanguageCode {
  return SUPPORTED.includes(value);
}

export function detectLanguage(): LanguageCode {
  try {
    const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (stored !== null && isLanguageCode(stored)) {
      return stored;
    }
    const navigatorLanguages = navigator.languages.length > 0 ? navigator.languages : [navigator.language];
    for (const tag of navigatorLanguages) {
      const base = tag.toLowerCase().split('-')[0] ?? '';
      if (isLanguageCode(base)) {
        return base;
      }
    }
  } catch {
    // Storage or navigator access can throw in private modes; fall back to English.
  }
  return 'en';
}

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    es: { translation: es },
    pt: { translation: pt },
    fr: { translation: fr },
    de: { translation: de },
  },
  lng: detectLanguage(),
  fallbackLng: 'en',
  supportedLngs: SUPPORTED,
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
