import '@testing-library/jest-dom/vitest';

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import de from '../i18n/de.json';
import en from '../i18n/en.json';
import es from '../i18n/es.json';
import fr from '../i18n/fr.json';
import pt from '../i18n/pt.json';

// A test-local i18n instance: importing `../i18n` would read localStorage and
// navigator at module load. English is the reference locale for assertions.
if (!i18n.isInitialized) {
  void i18n.use(initReactI18next).init({
    resources: {
      en: { translation: en },
      es: { translation: es },
      pt: { translation: pt },
      fr: { translation: fr },
      de: { translation: de },
    },
    lng: 'en',
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
    returnNull: false,
  });
}
