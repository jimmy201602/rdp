import type zh from '../zh/events';

const en: typeof zh = {
  kind: { keyboard: 'Keyboard', mouse: 'Mouse', clipboard: 'Clipboard', file: 'File', device: 'Mapped device', system: 'System' },
  source: { client: 'User', target: 'Target', admin: 'Monitor', gateway: 'Gateway' },
  action: {
    input: 'Key press (content hidden)', move: 'Move', button_down: 'Mouse down', button_up: 'Mouse up', wheel: 'Wheel',
    formats: 'Copy / format list', data: 'Clipboard data transfer', file_data: 'Clipboard file data',
    open: 'Open', close: 'Close', read_upload: 'Read mapped file → target', write_download: 'Write mapped file ← target',
    delete: 'Mark for deletion', rename: 'Rename', set_info: 'Change attributes', announce: 'Map device', remove: 'Unmap device',
    browse: 'Monitor browse', admin_download: 'Mapped drive → monitor download', admin_upload: 'Monitor → mapped drive upload', admin_delete: 'Monitor delete',
    events_dropped: 'Events dropped',
  },
  device: 'Device {{id}}',
  allKinds: 'All types',
  timeline: 'Activity timeline',
  following: 'Following playback',
  followPaused: 'Following paused; browse freely',
  followTooltip: 'Automatically scrolls to and highlights the event at the playback position; scrolling or changing pages pauses following',
  follow: 'Follow',
  followAria: 'Follow playback in events',
  kindAria: 'Event type',
  searchAria: 'Search events',
  searchPlaceholder: 'File path / event',
  seekTo: 'Jump to {{time}}',
  title: 'Activity events',
  count_one: '{{count}} event',
  count_other: '{{count}} events',
  recent: ' (latest 500)',
  empty: { noMatch: 'No matching events', noEvents: 'No activity events in this recording', waitingLive: 'Waiting for new events (switching control mode reconnects)', noRecordingEvents: 'No events in this recording' },
  privacy: {
    summary: 'About event logging',
    sidebar: 'Typed text and clipboard contents are not stored; mouse movement is sampled every 200 ms. File reads/writes indicate data direction, not a completed copy. Older recordings have no activity events.',
    table: 'Typed text and clipboard contents are not stored; mouse movement is sampled every 200 ms. Mapped file reads/writes indicate data direction, not a completed file copy. Older recordings have no activity events.',
  },
  column: { time: 'Time', kindSource: 'Type / source', action: 'Action', detail: 'Details' },
};

export default en;
