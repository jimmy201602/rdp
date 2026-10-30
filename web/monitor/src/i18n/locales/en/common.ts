import type zh from '../zh/common';

const en: typeof zh = {
  app: { title: 'RDP Session Monitor' },
  nav: { sessions: 'Live sessions', connect: 'Remote desktop', recordings: 'Recordings' },
  shell: {
    controlOn: 'Co-control enabled',
    recordingOff: 'Recording off',
    logout: 'Sign out',
    login: 'Sign in',
    token: 'Access token',
    tokenHelp: 'Same as rdpgw <code>-monitor-token</code>; leave empty when the gateway has no token.',
  },
  action: { save: 'Save', cancel: 'Cancel', ok: 'OK', back: 'Back', refresh: 'Refresh', delete: 'Delete', download: 'Download', close: 'Close' },
};

export default en;
