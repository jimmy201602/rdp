import { useEffect, useState } from 'react';
import { App, Button, Card, Input, Popconfirm, Space, Table, Tag, Typography } from 'antd';
import { DeleteOutlined, DownloadOutlined, PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import { useTranslation } from 'react-i18next';
import { account, api, downloadURL, endLabels, fmtBytes, fmtDuration, type RecordingMeta } from '../api';

export default function Recordings() {
  const { t } = useTranslation(['recordings', 'common']);
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
      title={t('title')}
      extra={
        <Space>
          <Input.Search placeholder={t('searchPlaceholder')} allowClear value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} />
          <Button icon={<ReloadOutlined />} onClick={() => void load()}>
            {t('common:action.refresh')}
          </Button>
        </Space>
      }
    >
      {error && <Typography.Text type="danger">{error}</Typography.Text>}
      <Table<RecordingMeta>
        rowKey="id"
        loading={loading}
        dataSource={data}
        locale={{ emptyText: t('empty') }}
        columns={[
          { title: t('column.started'), dataIndex: 'started', render: (v) => dayjs(v).format('YYYY-MM-DD HH:mm:ss'), defaultSortOrder: 'descend', sorter: (a, b) => dayjs(a.started).valueOf() - dayjs(b.started).valueOf() },
          { title: t('column.user'), render: (_, r) => account(r) },
          { title: t('column.target'), dataIndex: 'target' },
          { title: t('column.client'), dataIndex: 'remote_addr' },
          { title: t('column.resolution'), render: (_, r) => (r.width ? `${r.width}×${r.height}` : '-') },
          { title: t('column.duration'), dataIndex: 'duration_ms', render: fmtDuration, sorter: (a, b) => a.duration_ms - b.duration_ms },
          { title: t('column.size'), dataIndex: 'size', render: fmtBytes, sorter: (a, b) => a.size - b.size },
          {
            title: t('column.end'),
            dataIndex: 'end',
            render: (v: string, r) => (
              <Space size={4}>
                <Tag color={v === 'recording' ? 'red' : r.complete ? 'default' : 'orange'}>{endLabels[v] ?? v ?? '-'}</Tag>
                {r.error && <Tooltipish text={r.error} />}
              </Space>
            ),
          },
          {
            title: t('column.actions'),
            render: (_, r) => (
              <Space>
                <Button type="primary" icon={<PlayCircleOutlined />} onClick={() => nav(`/recordings/${r.id}`)}>
                  {t('play')}
                </Button>
                <Button icon={<DownloadOutlined />} href={downloadURL(r.id)} />
                <Popconfirm
                  title={t('deleteConfirm')}
                  okText={t('common:action.delete')}
                  cancelText={t('common:action.cancel')}
                  onConfirm={async () => {
                    await api.deleteRecording(r.id);
                    message.success(t('deleted'));
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
