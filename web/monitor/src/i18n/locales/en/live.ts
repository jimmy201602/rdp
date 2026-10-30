import type zh from '../zh/live';

const en: typeof zh = {
  msg: {
    controlDisabled: 'The gateway has -monitor-control disabled; view only',
    targetReconnecting: 'Connection to the remote host lost, reconnecting (attempt {{n}})…',
    targetReconnected: 'Reconnected to the remote host',
    mapFailed: 'Mapping failed: {{error}}',
    gatewayReconnectFailed: 'Connection to the gateway was lost and reconnecting failed',
    clipImageTooLarge: 'Clipboard image exceeds 2.9 MB; only text was synced',
    folderPermissionDenied: 'The browser did not grant read/write access to this folder',
    pickFolderFailed: 'Failed to select folder: {{error}}',
    disconnected: 'Disconnected',
  },
  tag: {
    live: 'Live',
    reconnecting: 'Reconnecting…',
    ended: 'Session ended',
    controlling: 'Co-controlling',
  },
  control: {
    tooltip: 'When enabled, your keyboard and mouse operate the session together with the original user',
    on: 'Control',
    off: 'View',
  },
  toolbar: {
    fullscreen: 'Fullscreen',
    exitFullscreen: 'Exit fullscreen',
    disconnect: 'Disconnect',
    shortcutsTooltip: 'Keyboard shortcuts (in fullscreen you can press Win, Alt+Tab, etc. directly)',
    ctrlAltDel: 'Send Ctrl+Alt+Del',
  },
  alert: {
    gatewayReconnecting: 'Connection to the gateway lost, reconnecting.',
    controlActive: "Co-control is on: your input acts directly on the user's desktop.",
  },
  info: {
    client: 'Client',
    resolution: 'Resolution',
    traffic: 'Traffic',
    viewers: 'Viewers',
    viewerCount: '{{n}}',
    controllerCount: ' ({{n}} controlling)',
    frames: 'Frames',
    injected: 'Injected events',
    decodeErrors: 'Decode errors',
    recording: 'Recording',
    recordingOn: 'Recording',
    recordingOff: 'Off',
  },
  aside: {
    userDrive: "User's mapped drive",
    dragHint: 'Drag to move up or down',
    gatewayReconnecting: 'Connection to the gateway lost, reconnecting',
  },
  clipboard: {
    title: 'Clipboard',
    placeholder: 'Text copied remotely appears here; type or paste, then click "Send" to paste remotely',
    imageAlt: 'Clipboard image',
    sent: 'Sent to the remote clipboard',
    send: 'Send to remote',
    hint: 'The local clipboard (text, HTML, images) syncs automatically when you return to this page; content copied remotely is written to the local clipboard.',
  },
  drive: {
    mapped: 'Mapped: {{drive}}',
    change: 'Change folder',
    unmap: 'Unmap',
    mapTooltip: 'Map folder to the remote (reselect after reloading the page)',
    unsupported: 'Mapping a folder requires Chrome / Edge over HTTPS or localhost',
  },
  audio: {
    mute: 'Mute',
    unmute: 'Unmute',
    clickToPlay: 'Click anywhere on the page to play remote audio',
  },
  ended: {
    connectionLost: 'Connection lost',
    backToConnect: 'Back to connect page',
  },
  shortcuts: {
    win: 'Win (Start menu)',
    alttab: 'Alt+Tab (switch windows)',
    winr: 'Win+R (Run)',
    wine: 'Win+E (File Explorer)',
    wind: 'Win+D (show desktop)',
    winl: 'Win+L (lock)',
    ctrlshiftesc: 'Ctrl+Shift+Esc (Task Manager)',
    altf4: 'Alt+F4 (close window)',
    prtsc: 'PrintScreen (screenshot)',
  },
};

export default en;
