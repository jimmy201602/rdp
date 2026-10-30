import 'i18next';
import type zh from './locales/zh/index';

// Typed keys: t('ns:key') must exist in the Chinese resources, and each
// English namespace is typed as its Chinese counterpart.
declare module 'i18next' {
  interface CustomTypeOptions {
    defaultNS: 'common';
    resources: typeof zh;
    returnNull: false;
  }
}
