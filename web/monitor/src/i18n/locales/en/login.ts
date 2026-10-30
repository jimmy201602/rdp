import type zh from '../zh/login';

const en: typeof zh = {
  title: 'RDP Session Monitor',
  mode: { user: 'Account', token: 'Access token' },
  user: 'Username',
  userRequired: 'Please enter the username',
  password: 'Password',
  passwordRequired: 'Please enter the password',
  submit: 'Sign in',
  userHelp: 'Accounts come from the gateway\'s <code>-web-users</code> file. After signing in you can connect to remote desktops directly in the browser.',
  token: 'Access token',
  tokenPlaceholder: 'Same as -monitor-token; leave empty if not set',
  enter: 'Enter',
  tokenHelp: 'A token only allows watching and co-control; opening connections from the browser requires an account sign-in.',
  tokenInvalid: 'Invalid token or gateway unreachable',
};

export default en;
