import type zh from '../zh/sessions';

const en: typeof zh = {
  title: 'Active sessions',
  empty: 'No sessions',
  col: {
    user: 'User',
    client: 'Client',
    target: 'Target',
    resolution: 'Resolution',
    started: 'Started',
    duration: 'Duration',
    traffic: 'Traffic',
    viewers: 'Viewers',
    actions: 'Actions',
  },
  tag: {
    viewers: '{{count}} watching',
    controllers: '{{count}} co-controlling',
    recording: 'Recording',
    decodeErrors: 'Decode errors {{count}}',
  },
  watch: 'Monitor',
  disconnectConfirm: 'Disconnect this session?',
  disconnect: 'Disconnect',
  disconnected: 'Disconnected',
};

export default en;
