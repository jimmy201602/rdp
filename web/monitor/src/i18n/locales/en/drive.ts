import type zh from '../zh/drive';

const en: typeof zh = {
  root: 'Mapped root',
  title: 'Mapped drives',
  sessionEnded: 'Session ended',
  disks_one: '{{count}} drive',
  disks_other: '{{count}} drives',
  location: 'Location',
  refreshDevices: 'Refresh devices',
  noDevices: 'No devices',
  device: { notAcceptedParen: ' (not accepted)', notDiskParen: ' (not a drive)', disk: 'Drive {{id}}', notDisk: 'Not a drive', notAccepted: 'Not accepted', device: 'Device {{id}}' },
  empty: {
    noMatch: 'No matching files',
    noDevicesWeb: 'The session user has not mapped a local folder from the web toolbar yet (refresh after mapping)',
    noDevices: 'Map a folder or drive in the RDP client, then reconnect',
    disabled: 'File operations are disabled',
    selectDevice: 'Select a mapped drive on the left',
    emptyFolder: 'This folder is empty',
    waiting: 'Waiting to browse the mapped folder',
  },
  aria: { browser: 'Mapped drive browser', devices: 'Mapped devices', toolbar: 'File operations', views: 'File view', path: 'Mapped folder path', iconList: 'File list as icons', columnList: 'File list in columns', breadcrumbs: 'Folder hierarchy' },
  tool: { back: 'Back', forward: 'Forward', up: 'Up', refresh: 'Refresh folder', upload: 'Upload new file', download: 'Download selected file', delete: 'Delete selected file' },
  deleteConfirm: { title: 'Permanently delete {{name}}?', content: 'This deletes {{path}} in the user\'s mapped folder. It will not go to the Recycle Bin.', ok: 'Delete permanently' },
  upload: { tooLarge: 'Files cannot exceed 64 MiB', title: 'Upload to {{path}}?', content: 'Creates a new file in the user\'s mapped folder without overwriting files of the same name; an interruption may leave a partial file.', ok: 'Upload' },
  view: { list: 'List', icons: 'Icons', columns: 'Columns' },
  viewAria: { list: 'List view', icons: 'Icon view', columns: 'Column view' },
  search: 'Search current folder',
  go: 'Go to folder',
  deviceGone: 'This mapped device was removed or not accepted',
  column: { name: 'Name', size: 'Size', noMatch: 'No matching files', empty: 'Empty folder' },
  folder: 'Folder',
  status: { items_one: '{{n}} item', items_other: '{{n}} items', selected: ' · 1 selected', reading: 'Loading…', columnsHint: 'Click a folder to expand it into a new column', openHint: 'Double-click to open a folder' },
  note: { strong: 'Operations act directly on the user\'s mapped files. ', rest: 'Uploads only create new files; deletes skip the Recycle Bin and are not recursive; 64 MiB per file. Symbolic links cannot be modified.', disabled: 'File operations are disabled: requires -monitor-drive-control and an access token. Only announced mapped devices are shown.' },
};

export default en;
