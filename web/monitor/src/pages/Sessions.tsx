import { useEffect, useState } from 'react';
import { App, Button, Card, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { EyeOutlined, DisconnectOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import { account, api, fmtBytes, fmtDuration, type SessionInfo } from '../api';

export default function Sessions() {
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
    const t = setInterval(() => {
      setNow(Date.now());
      void load();
    }, 2000);
    return () => clearInterval(t);
  }, []);

  return (
    <Card
      title="活动会话"
      extra={
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>
          刷新
        </Button>
      }
    >
      {error && <Typography.Text type="danger">{error}</Typography.Text>}
      <Table<SessionInfo>
        rowKey="id"
        loading={loading}
        dataSource={rows}
        pagination={false}
        locale={{ emptyText: '当前没有会话' }}
        columns={[
          { title: '用户', render: (_, s) => account(s) },
          { title: '客户端', dataIndex: 'remote_addr', render: (v, s) => (s.client_name ? `${v} (${s.client_name})` : v) },
          { title: '目标', dataIndex: 'target' },
          { title: '分辨率', render: (_, s) => (s.width ? `${s.width}×${s.height}` : '-') },
          { title: '开始时间', dataIndex: 'started', render: (v) => dayjs(v).format('HH:mm:ss') },
          { title: '时长', render: (_, s) => fmtDuration(now - dayjs(s.started).valueOf()) },
          { title: '流量', dataIndex: 'server_bytes', render: fmtBytes },
          {
            title: '观看',
            render: (_, s) => (
              <Space size={4}>
                <Tag>{s.viewers} 人</Tag>
                {s.controllers > 0 && <Tag color="gold">{s.controllers} 人协同</Tag>}
                {s.recording && <Tag color="red">录制中</Tag>}
                {s.decode_errors > 0 && <Tag color="orange">解码异常 {s.decode_errors}</Tag>}
              </Space>
            ),
          },
          {
            title: '操作',
            render: (_, s) => (
              <Space>
                <Button type="primary" icon={<EyeOutlined />} onClick={() => nav(`/live/${s.id}`)}>
                  监控
                </Button>
                <Popconfirm
                  title="断开该会话？"
                  okText="断开"
                  cancelText="取消"
                  onConfirm={async () => {
                    await api.disconnect(s.id);
                    message.success('已断开');
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
