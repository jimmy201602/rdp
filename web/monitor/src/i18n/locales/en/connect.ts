import type zh from '../zh/connect';

const en: typeof zh = {
  title: 'Connect to Remote Desktop',
  colorDepth: { c32: 'True Color (32-bit)', c24: 'True Color (24-bit)', c16: 'High Color (16-bit)', c15: 'High Color (15-bit)' },
  experience: {
    full: 'Best quality: wallpaper, themes, animations, font smoothing',
    balanced: 'Balanced: everything except wallpaper',
    fast: 'Smooth (default): no wallpaper, themes or animations',
    minimal: 'Low bandwidth: also no cursor shadow',
  },
  keyboard: {
    zhCN: 'Chinese (Simplified)',
    enUS: 'English (US)',
    zhTW: 'Chinese (Traditional)',
    ja: 'Japanese',
    ko: 'Korean',
    enGB: 'English (UK)',
    de: 'German',
    fr: 'French',
  },
  fitWindow: 'Fit window ({{w}}×{{h}})',
  needLogin: {
    message: 'Please sign in with an account first',
    description: 'You entered with an access token, which only allows watching and co-control. Opening a connection from the browser requires signing in with an account from -web-users; the session is recorded under that account.',
    goLogin: 'Sign in',
  },
  webDisabled: {
    message: 'Web connections are not enabled on the gateway',
    description: 'Start rdpgw with -web-users (account file) and -allow-target (allowed servers), and open the monitor over HTTPS.',
  },
  insecure: 'This page is not served over HTTPS, so remote desktop passwords and screen content travel the network in clear text. Ask your administrator to enable -monitor-cert or -monitor-autocert on the gateway.',
  form: {
    address: 'Server address',
    addressRequired: 'Please enter the server address',
    addressPlaceholder: '192.0.2.30 or 192.0.2.30:3389',
    user: 'Username',
    userRequired: 'Please enter the username',
    domain: 'Domain (optional)',
    password: 'Password',
    passwordRequired: 'Please enter the password',
    resolution: 'Resolution',
    color: 'Colors',
    more: 'More options (experience, keyboard)',
    experience: 'Visual experience',
    experienceTip: 'More effects use more bandwidth and refresh the screen more slowly',
    keyboard: 'Keyboard layout',
    keyboardTip: 'Tells remote Windows which input language to use; affects IMEs and symbol keys',
    submit: 'Connect',
  },
  note: 'The gateway opens the connection. Credentials are kept only in gateway memory for automatic reconnection, cleared when the session ends, and never written to disk or logs. The session is also recorded and audited; servers that support display control (Server 2016 and later) follow the browser window size, while older systems (such as Windows 7) keep the initial resolution.',
};

export default en;
