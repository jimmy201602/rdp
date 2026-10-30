import { useState } from 'react';
import { Alert, Button, Card, Form, Input, Segmented, Typography } from 'antd';
import { KeyOutlined, LockOutlined, UserOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { api, setToken } from '../api';

type Mode = '用户登录' | '访问令牌';

// Login authenticates the browser: either against the gateway's -web-users
// accounts (a cookie session, required for the web RDP client) or with the
// shared -monitor-token for watch-only deployments.
export default function Login() {
  const nav = useNavigate();
  const [mode, setMode] = useState<Mode>('用户登录');
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
      setError('令牌无效或网关不可达');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <Card className="login-card" title="RDP 会话监控">
        <Segmented<Mode>
          block
          value={mode}
          options={['用户登录', '访问令牌']}
          onChange={(v) => {
            setMode(v);
            setError('');
          }}
          style={{ marginBottom: 16 }}
        />
        {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
        {mode === '用户登录' ? (
          <Form layout="vertical" onFinish={submitLogin} requiredMark={false} autoComplete="off">
            <Form.Item name="user" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}>
              <Input prefix={<UserOutlined />} autoFocus autoComplete="username" />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password prefix={<LockOutlined />} autoComplete="current-password" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={busy}>
              登录
            </Button>
            <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
              账号来自网关的 <code>-web-users</code> 文件。登录后可在浏览器里直接连接远程桌面。
            </Typography.Paragraph>
          </Form>
        ) : (
          <Form layout="vertical" onFinish={submitToken} requiredMark={false}>
            <Form.Item name="token" label="访问令牌">
              <Input.Password prefix={<KeyOutlined />} autoFocus placeholder="与 -monitor-token 一致，未设置时留空" />
            </Form.Item>
            <Button type="primary" htmlType="submit" block loading={busy}>
              进入
            </Button>
            <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
              令牌仅用于查看与协同；浏览器发起连接需要用户登录。
            </Typography.Paragraph>
          </Form>
        )}
      </Card>
    </div>
  );
}
