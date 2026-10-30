import { useEffect, useState } from 'react';
import { Layout, Menu, Typography, Button, Modal, Input, Space, Tag } from 'antd';
import { DesktopOutlined, PlaySquareOutlined, KeyOutlined, LinkOutlined, LoginOutlined, LogoutOutlined } from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation, Trans } from 'react-i18next';
import { api, getToken, setToken, type MonitorInfo } from './api';
import LanguageSwitch from './components/LanguageSwitch';

const { Header, Content } = Layout;

export default function Shell() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const loc = useLocation();
  const [info, setInfo] = useState<MonitorInfo | null>(null);
  const [askToken, setAskToken] = useState(false);
  const [token, setTokenValue] = useState(getToken());

  const load = () =>
    api
      .info()
      .then(setInfo)
      .catch(() => nav('/login', { replace: true }));

  useEffect(() => {
    void load();
  }, []);

  const selected = loc.pathname.startsWith('/recordings') ? 'recordings' : loc.pathname.startsWith('/connect') ? 'connect' : 'sessions';
  const paths: Record<string, string> = { sessions: '/', connect: '/connect', recordings: '/recordings' };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
        <Typography.Title level={5} style={{ color: '#fff', margin: 0, whiteSpace: 'nowrap' }}>
          {t('app.title')}
        </Typography.Title>
        <Menu
          theme="dark"
          mode="horizontal"
          selectedKeys={[selected]}
          style={{ flex: 1, minWidth: 0 }}
          onClick={({ key }) => nav(paths[key] ?? '/')}
          items={[
            { key: 'sessions', icon: <DesktopOutlined />, label: t('nav.sessions') },
            ...(info?.web ? [{ key: 'connect', icon: <LinkOutlined />, label: t('nav.connect') }] : []),
            { key: 'recordings', icon: <PlaySquareOutlined />, label: t('nav.recordings') },
          ]}
        />
        <Space>
          {info?.control && <Tag color="gold">{t('shell.controlOn')}</Tag>}
          {info && !info.recording && <Tag>{t('shell.recordingOff')}</Tag>}
          {info?.user ? (
            <>
              <Tag color="blue">{info.user}</Tag>
              <Button
                size="small"
                icon={<LogoutOutlined />}
                onClick={async () => {
                  await api.logout();
                  setToken('');
                  nav('/login', { replace: true });
                }}
              >
                {t('shell.logout')}
              </Button>
            </>
          ) : (
            <>
              {info?.login && (
                <Button size="small" type="primary" icon={<LoginOutlined />} onClick={() => nav('/login')}>
                  {t('shell.login')}
                </Button>
              )}
              <Button size="small" icon={<KeyOutlined />} onClick={() => setAskToken(true)}>
                {t('shell.token')}
              </Button>
            </>
          )}
          <LanguageSwitch dark />
        </Space>
      </Header>
      <Content style={{ padding: 24 }}>
        <Outlet context={info} />
      </Content>
      <Modal
        open={askToken}
        title={t('shell.token')}
        okText={t('action.save')}
        cancelText={t('action.cancel')}
        onCancel={() => setAskToken(false)}
        onOk={() => {
          setToken(token.trim());
          setAskToken(false);
          void load();
          nav(0);
        }}
      >
        <Typography.Paragraph type="secondary">
          <Trans i18nKey="shell.tokenHelp" components={{ code: <code /> }} />
        </Typography.Paragraph>
        <Input.Password value={token} onChange={(e) => setTokenValue(e.target.value)} placeholder="monitor token" />
      </Modal>
    </Layout>
  );
}
