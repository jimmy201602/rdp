import i18n from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import 'dayjs/locale/en';
import zh from './locales/zh';
import en from './locales/en';

export const LANGUAGES = [
  { code: 'zh', label: '简体中文' },
  { code: 'en', label: 'English' },
] as const;
export type Language = (typeof LANGUAGES)[number]['code'];

export const LANG_KEY = 'rdpmon.lang';

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { zh, en },
    fallbackLng: 'zh',
    supportedLngs: ['zh', 'en'],
    nonExplicitSupportedLngs: true, // zh-CN, en-US, ... map to zh / en
    load: 'languageOnly',
    defaultNS: 'common',
    interpolation: { escapeValue: false }, // React escapes already
    detection: { order: ['localStorage', 'navigator'], lookupLocalStorage: LANG_KEY, caches: ['localStorage'] },
    returnNull: false,
  });

export const currentLanguage = (): Language => (i18n.resolvedLanguage === 'en' ? 'en' : 'zh');

const applyDocument = () => {
  const lang = currentLanguage();
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  dayjs.locale(lang === 'zh' ? 'zh-cn' : 'en');
  document.title = i18n.t('common:app.title');
};
applyDocument();
i18n.on('languageChanged', applyDocument);

export default i18n;
