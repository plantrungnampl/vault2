import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import enTranslations from '../locales/en.json';
import viTranslations from '../locales/vi.json';

const resources = {
  en: {
    translation: enTranslations
  },
  vi: {
    translation: viTranslations
  }
};

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    defaultNS: 'translation',
    debug: import.meta.env.DEV,

    // Language detection options
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      caches: ['localStorage'],
      lookupLocalStorage: 'securevault_language'
    },

    interpolation: {
      escapeValue: false, // React already does escaping
    },

    // Vietnamese as priority based on env config
    lng: import.meta.env.VITE_SECUREVAULT_DEFAULT_LANGUAGE || 'vi',
  });

export default i18n;