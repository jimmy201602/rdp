import type zh from '../zh/api';

const en: typeof zh = {
  authRequired: 'Access token required',
  notRdpv: 'Not an RDPV v1 recording file',
  end: {
    clientClosed: 'Client disconnected',
    targetClosed: 'Target disconnected',
    monitorDisconnect: 'Disconnected by monitor',
    canceled: 'Gateway stopped',
    error: 'Error',
    interrupted: 'Recording interrupted',
    recording: 'Recording',
  },
};

export default en;
