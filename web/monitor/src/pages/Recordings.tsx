import { useEffect, useState } from 'react';
import { App, Button, Card, Input, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, DownloadOutlined, PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import { account, api, downloadURL, endLabels, fmtBytes, fmtDuration, type RecordingMeta } from '../api';

export default function Recordings() {
  const nav = useNavigate();
  const { message } = App.useApp();
  const [rows, setRows] = useState<RecordingMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      setRows(await api.recordings());
      setError('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const needle = q.trim().toLowerCase();
  const data = needle
    ? rows.filter((r) => [r.user, r.domain, r.target, r.remote_addr, r.client_name, r.id].some((v) => v?.toLowerCase().includes(needle)))
    : rows;

  return (
    <Card
      title="录像列表"
      extra={
        <Space>
          <Input.Search placeholder="用户 / 目标 / 客户端" allowClear value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} />
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            刷新
          </Button>
        </Space>
      }
    >
      {error && <Typography.Text type="danger">{error}</Typography.Text>}
      <Table<RecordingMeta>
        rowKey="id"
        loading={loading}
        dataSource={data}
        locale={{ emptyText: '没有录像（网关需加 -record-dir）' }}
        columns={[
          { title: '开始时间', dataIndex: 'started', render: (v) => dayjs(v).format('YYYY-MM-DD HH:mm:ss'), defaultSortOrder: 'descend', sorter: (a, b) => dayjs(a.started).valueOf() - dayjs(b.started).valueOf() },
          { title: '用户', render: (_, r) => account(r) },
          { title: '目标', dataIndex: 'target' },
          { title: '客户端', dataIndex: 'remote_addr' },
          { title: '分辨率', render: (_, r) => (r.width ? `${r.width}×${r.height}` : '-') },
          { title: '时长', dataIndex: 'duration_ms', render: fmtDuration, sorter: (a, b) => a.duration_ms - b.duration_ms },
          { title: '大小', dataIndex: 'size', render: fmtBytes, sorter: (a, b) => a.size - b.size },
          {
            title: '结束',
            dataIndex: 'end',
            render: (v: string, r) => (
              <Space size={4}>
                <Tag color={v === 'recording' ? 'red' : r.complete ? 'default' : 'orange'}>{endLabels[v] ?? v ?? '-'}</Tag>
                {r.error && <Tooltipish text={r.error} />}
              </Space>
            ),
          },
          {
            title: '操作',
            render: (_, r) => (
              <Space>
                <Button type="primary" icon={<PlayCircleOutlined />} onClick={() => nav(`/recordings/${r.id}`)}>
                  回放
                </Button>
                <Button icon={<DownloadOutlined />} href={downloadURL(r.id)} />
                <Popconfirm
                  title="删除该录像？"
                  okText="删除"
                  cancelText="取消"
                  onConfirm={async () => {
                    await api.deleteRecording(r.id);
                    message.success('已删除');
                    void load();
                  }}
                >
                  <Button danger icon={<DeleteOutlined />} disabled={r.end === 'recording'} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
    </Card>
  );
}

const Tooltipish = ({ text }: { text: string }) => (
  <Typography.Text type="danger" ellipsis={{ tooltip: text }} style={{ maxWidth: 160 }}>
    {text}
  </Typography.Text>
);
