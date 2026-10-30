import { useEffect, useState } from 'react';
import { App, Button, Card, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { EyeOutlined, DisconnectOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import { useTranslation } from 'react-i18next';
import { account, api, fmtBytes, fmtDuration, type SessionInfo } from '../api';

export default function Sessions() {
  const { t } = useTranslation(['sessions', 'common']);
  const { message } = App.useApp();
  const nav = useNavigate();
  const [rows, setRows] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [now, setNow] = useState(Date.now());

  const load = async () => {
    try {
      setRows(await api.sessions());
      setError('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const timer = setInterval(() => {
      setNow(Date.now());
      void load();
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <Card
      title={t('title')}
      extra={
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>
          {t('common:action.refresh')}
        </Button>
      }
    >
      {error && <Typography.Text type="danger">{error}</Typography.Text>}
      <Table<SessionInfo>
        rowKey="id"
        loading={loading}
        dataSource={rows}
        pagination={false}
        locale={{ emptyText: t('empty') }}
        columns={[
          { title: t('col.user'), render: (_, s) => account(s) },
          { title: t('col.client'), dataIndex: 'remote_addr', render: (v, s) => (s.client_name ? `${v} (${s.client_name})` : v) },
          { title: t('col.target'), dataIndex: 'target' },
          { title: t('col.resolution'), render: (_, s) => (s.width ? `${s.width}×${s.height}` : '-') },
          { title: t('col.started'), dataIndex: 'started', render: (v) => dayjs(v).format('HH:mm:ss') },
          { title: t('col.duration'), render: (_, s) => fmtDuration(now - dayjs(s.started).valueOf()) },
          { title: t('col.traffic'), dataIndex: 'server_bytes', render: fmtBytes },
          {
            title: t('col.viewers'),
            render: (_, s) => (
              <Space size={4}>
                <Tag>{t('tag.viewers', { count: s.viewers })}</Tag>
                {s.controllers > 0 && <Tag color="gold">{t('tag.controllers', { count: s.controllers })}</Tag>}
                {s.recording && <Tag color="red">{t('tag.recording')}</Tag>}
                {s.decode_errors > 0 && <Tag color="orange">{t('tag.decodeErrors', { count: s.decode_errors })}</Tag>}
              </Space>
            ),
          },
          {
            title: t('col.actions'),
            render: (_, s) => (
              <Space>
                <Button type="primary" icon={<EyeOutlined />} onClick={() => nav(`/live/${s.id}`)}>
                  {t('watch')}
                </Button>
                <Popconfirm
                  title={t('disconnectConfirm')}
                  okText={t('disconnect')}
                  cancelText={t('common:action.cancel')}
                  onConfirm={async () => {
                    await api.disconnect(s.id);
                    message.success(t('disconnected'));
                    void load();
                  }}
                >
                  <Button danger icon={<DisconnectOutlined />} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
    </Card>
  );
}
