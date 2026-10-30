import { useState } from 'react';
import { Alert, Button, Card, Form, Input, Segmented, Typography } from 'antd';
import { KeyOutlined, LockOutlined, UserOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { Trans, useTranslation } from 'react-i18next';
import LanguageSwitch from '../components/LanguageSwitch';
import { api, setToken } from '../api';

type Mode = 'user' | 'token';

// Login authenticates the browser: either against the gateway's -web-users
// accounts (a cookie session, required for the web RDP client) or with the
// shared -monitor-token for watch-only deployments.
export default function Login() {
  const { t } = useTranslation('login');
  const nav = useNavigate();
  const [mode, setMode] = useState<Mode>('user');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const done = () => {
    setError('');
    nav('/', { replace: true });
  };

  const submitLogin = async ({ user, password }: { user: string; password: string }) => {
    setBusy(true);
    try {
      await api.login(user, password);
      setToken('');
      done();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submitToken = async ({ token }: { token?: string }) => {
    setBusy(true);
    try {
      setToken((token ?? '').trim());
      await api.info();
      done();
    } catch (e) {
      setError(t('tokenInvalid'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <div style={{ position: 'fixed', top: 16, right: 16 }}>
        <LanguageSwitch />
      </div>
      <Card className="login-card" title={t('title')}>
        <Segmented<Mode>
          block
          value={mode}
          options={[
            { value: 'user', label: t('mode.user') },
            { value: 'token', label: t('mode.token') },
          ]}
          onChange={(v) => {
            setMode(v);
            setError('');
          }}
          style={{ marginBottom: 16 }}
        />
        {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
        {mode === 'user' ? (
          <Form layout="vertical" onFinish={submitLogin} requiredMark={false} autoComplete="off">
            <Form.Item name="user" label={t('user')} rules={[{ required: true, message: t('userRequired') }]}>
              <Input prefix={<UserOutlined />} autoFocus autoComplete="username" />
            </Form.Item>
            <Form.Item name="password" label={t('password')} rules={[{ required: true, message: t('passwordRequired') }]}>
              <Input.Password prefix={<LockOutlined />} autoComplete="current-password" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={busy}>
              {t('submit')}
            </Button>
            <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
              <Trans t={t} i18nKey="userHelp" components={{ code: <code /> }} />
            </Typography.Paragraph>
          </Form>
        ) : (
          <Form layout="vertical" onFinish={submitToken} requiredMark={false}>
            <Form.Item name="token" label={t('token')}>
              <Input.Password prefix={<KeyOutlined />} autoFocus placeholder={t('tokenPlaceholder')} />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={busy}>
              {t('enter')}
            </Button>
            <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
              {t('tokenHelp')}
            </Typography.Paragraph>
          </Form>
        )}
      </Card>
    </div>
  );
}
