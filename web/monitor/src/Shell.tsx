import { useEffect, useState } from 'react';
import { Layout, Menu, Typography, Button, Modal, Input, Space, Tag } from 'antd';
import { DesktopOutlined, PlaySquareOutlined, KeyOutlined, LinkOutlined, LoginOutlined, LogoutOutlined } from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { api, getToken, setToken, type MonitorInfo } from './api';

const { Header, Content } = Layout;

export default function Shell() {
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
          RDP 会话监控
        </Typography.Title>
        <Menu
          theme="dark"
          mode="horizontal"
          selectedKeys={[selected]}
          style={{ flex: 1, minWidth: 0 }}
          onClick={({ key }) => nav(paths[key] ?? '/')}
          items={[
            { key: 'sessions', icon: <DesktopOutlined />, label: '实时监控' },
            ...(info?.web ? [{ key: 'connect', icon: <LinkOutlined />, label: '连接远程桌面' }] : []),
            { key: 'recordings', icon: <PlaySquareOutlined />, label: '录像回放' },
          ]}
        />
        <Space>
          {info?.control && <Tag color="gold">协同已开启</Tag>}
          {info && !info.recording && <Tag>未开启录像</Tag>}
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
                退出
              </Button>
            </>
          ) : (
            <>
              {info?.login && (
                <Button size="small" type="primary" icon={<LoginOutlined />} onClick={() => nav('/login')}>
                  账号登录
                </Button>
              )}
              <Button size="small" icon={<KeyOutlined />} onClick={() => setAskToken(true)}>
                访问令牌
              </Button>
            </>
          )}
        </Space>
      </Header>
      <Content style={{ padding: 24 }}>
        <Outlet context={info} />
      </Content>
      <Modal
        open={askToken}
        title="访问令牌"
        okText="保存"
        cancelText="取消"
        onCancel={() => setAskToken(false)}
        onOk={() => {
          setToken(token.trim());
          setAskToken(false);
          void load();
          nav(0);
        }}
      >
        <Typography.Paragraph type="secondary">
          与 rdpgw 的 <code>-monitor-token</code> 一致；网关未设置令牌时留空。
        </Typography.Paragraph>
        <Input.Password value={token} onChange={(e) => setTokenValue(e.target.value)} placeholder="monitor token" />
      </Modal>
    </Layout>
  );
}
