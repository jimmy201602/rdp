import { useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Form,
  Input,
  Row,
  Select,
  Typography,
} from "antd";
import type { ReactNode } from "react";

// insecurePage is true for plain HTTP from anything but this machine.
const insecurePage = () =>
  location.protocol === "http:" && !/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(location.hostname);
import { DesktopOutlined, LockOutlined, UserOutlined } from "@ant-design/icons";
import { useNavigate, useOutletContext } from "react-router-dom";
import { api, setOwnerKey, type MonitorInfo } from "../api";

interface FormValues {
  address: string;
  user: string;
  domain?: string;
  password: string;
  resolution: string;
  colorDepth: number;
  experience: string;
  keyboard: number;
}

const colorDepths = [
  { value: 32, label: "真彩色（32 位）" },
  { value: 24, label: "真彩色（24 位）" },
  { value: 16, label: "增强色（16 位）" },
  { value: 15, label: "增强色（15 位）" },
];

// Presets map to TS_INFO_PACKET performance flags in monitor/web.go.
const experiences = [
  { value: "full", label: "最佳效果：壁纸、主题、动画、字体平滑" },
  { value: "balanced", label: "均衡：除壁纸外全部开启" },
  { value: "fast", label: "流畅（默认）：关闭壁纸、主题、动画" },
  { value: "minimal", label: "低带宽：再关闭光标阴影" },
];

const keyboards = [
  { value: 0x0804, label: "中文（简体）" },
  { value: 0x0409, label: "英语（美国）" },
  { value: 0x0404, label: "中文（繁体）" },
  { value: 0x0411, label: "日语" },
  { value: 0x0412, label: "韩语" },
  { value: 0x0809, label: "英语（英国）" },
  { value: 0x0407, label: "德语" },
  { value: 0x040c, label: "法语" },
];

const PREFS_KEY = "rdpmon.connect";

type Prefs = Partial<
  Pick<
    FormValues,
    | "address"
    | "user"
    | "domain"
    | "resolution"
    | "colorDepth"
    | "experience"
    | "keyboard"
  >
>;

function loadPrefs(): Prefs {
  try {
    return JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}") as Prefs;
  } catch {
    return {};
  }
}

const Centered = ({ children }: { children: ReactNode }) => (
  <div
    style={{
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      minHeight: "calc(100vh - 160px)",
    }}
  >
    <div style={{ width: "100%", maxWidth: 720 }}>{children}</div>
  </div>
);

// screenSizes offers the browser's own viewport first; the gateway clamps
// anything out of range.
function screenSizes(): { value: string; label: string }[] {
  const w = Math.max(640, Math.min(4096, Math.round(window.innerWidth)) & ~3);
  const h = Math.max(480, Math.min(4096, Math.round(window.innerHeight)) & ~3);
  return [
    { value: `${w}x${h}`, label: `适应窗口（${w}×${h}）` },
    { value: "1280x800", label: "1280 × 800" },
    { value: "1600x900", label: "1600 × 900" },
    { value: "1920x1080", label: "1920 × 1080" },
  ];
}

// Connect opens a browser-initiated RDP session: the gateway dials the
// server, so the credentials are used once and never stored here.
export default function Connect() {
  const nav = useNavigate();
  const info = useOutletContext<MonitorInfo | null>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const sizes = screenSizes();
  const prefs = loadPrefs();
  // A remembered fixed size is kept; the window-sized option follows the
  // current window.
  const resolution =
    prefs.resolution && sizes.slice(1).some((o) => o.value === prefs.resolution)
      ? prefs.resolution
      : sizes[0].value;

  const submit = async (v: FormValues) => {
    setBusy(true);
    setError("");
    const [width, height] = v.resolution.split("x").map(Number);
    const keep: Prefs = {
      address: v.address.trim(),
      user: v.user.trim(),
      domain: v.domain?.trim(),
      resolution: v.resolution,
      colorDepth: v.colorDepth,
      experience: v.experience,
      keyboard: v.keyboard,
    };
    localStorage.setItem(PREFS_KEY, JSON.stringify(keep));
    try {
      const s = await api.connect({
        address: v.address.trim(),
        user: v.user.trim(),
        domain: v.domain?.trim() || undefined,
        password: v.password,
        width,
        height,
        color_depth: v.colorDepth,
        keyboard_layout: v.keyboard,
        experience: v.experience,
      });
      setOwnerKey(s.id, s.owner_key);
      nav(`/connect/${encodeURIComponent(s.id)}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // A shared token may watch sessions, but opening one needs a per-user
  // login (the session is audited under that account).
  if (info?.login && !info.user) {
    return (
      <Centered>
        <Card title="连接远程桌面">
          <Alert
            type="warning"
            showIcon
            message="请先用账号登录"
            description="你当前是用访问令牌进入的，令牌只能查看与协同。浏览器发起连接需要 -web-users 中的账号登录，会话会记录在该账号名下。"
            action={
              <Button type="primary" onClick={() => nav("/login")}>
                去登录
              </Button>
            }
          />
        </Card>
      </Centered>
    );
  }

  if (info && !info.web) {
    return (
      <Centered>
        <Card title="连接远程桌面">
          <Alert
            type="info"
            showIcon
            message="网关未开启网页连接"
            description="启动 rdpgw 时加上 -web-users（账号文件）与 -allow-target（允许连接的服务器），并通过 HTTPS 访问监控界面。"
          />
        </Card>
      </Centered>
    );
  }

  return (
    <Centered>
      <Card title="连接远程桌面">
        {insecurePage() && (
          <Alert
            type="warning"
            showIcon
            message="当前页面未使用 HTTPS，远程桌面密码和画面会以明文经过网络。请让管理员为网关启用 -monitor-cert 或 -monitor-autocert。"
            style={{ marginBottom: 16 }}
          />
        )}
        {error && (
          <Alert
            type="error"
            showIcon
            message={error}
            style={{ marginBottom: 16 }}
          />
        )}
        <Form<FormValues>
          layout="vertical"
          requiredMark={false}
          initialValues={{
            address: prefs.address,
            user: prefs.user,
            domain: prefs.domain,
            resolution,
            colorDepth: prefs.colorDepth ?? 32,
            experience: prefs.experience ?? "fast",
            keyboard: prefs.keyboard ?? 0x0804,
          }}
          onFinish={submit}
          autoComplete="off"
        >
          <Form.Item
            name="address"
            label="服务器地址"
            rules={[{ required: true, message: "请输入服务器地址" }]}
          >
            <Input
              prefix={<DesktopOutlined />}
              placeholder="192.0.2.30 或 192.0.2.30:3389"
              autoFocus={!prefs.address}
            />
          </Form.Item>
          <Row gutter={16}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="user"
                label="用户名"
                rules={[{ required: true, message: "请输入用户名" }]}
              >
                <Input prefix={<UserOutlined />} autoComplete="off" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item name="domain" label="域（可选）">
                <Input autoComplete="off" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="password"
            label="密码"
            rules={[{ required: true, message: "请输入密码" }]}
          >
            <Input.Password
              prefix={<LockOutlined />}
              autoComplete="new-password"
              autoFocus={!!prefs.address}
            />
          </Form.Item>
          <Row gutter={16}>
            <Col xs={24} sm={12}>
              <Form.Item name="resolution" label="分辨率">
                <Select options={sizes} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item name="colorDepth" label="颜色">
                <Select options={colorDepths} />
              </Form.Item>
            </Col>
          </Row>
          <Collapse
            ghost
            size="small"
            style={{ margin: "-8px -16px 16px" }}
            items={[
              {
                key: "more",
                label: "更多选项（体验、键盘）",
                forceRender: true,
                children: (
                  <Row gutter={16}>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name="experience"
                        label="视觉体验"
                        tooltip="效果越多，占用带宽越大，画面刷新越慢"
                      >
                        <Select
                          options={experiences}
                          popupMatchSelectWidth={false}
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name="keyboard"
                        label="键盘布局"
                        tooltip="告诉远程 Windows 使用的输入语言，影响输入法与符号键"
                      >
                        <Select options={keyboards} />
                      </Form.Item>
                    </Col>
                  </Row>
                ),
              },
            ]}
          />
          <Button type="primary" htmlType="submit" loading={busy}>
            连接
          </Button>
          <Typography.Paragraph
            type="secondary"
            style={{ marginTop: 16, marginBottom: 0 }}
          >
            连接由网关发起，凭据只保存在网关内存中用于断线自动重连，会话结束即清除，不会写入磁盘或日志。会话同样会被录像和审计；支持显示控制的服务器（如 Server 2016 及以上）会随浏览器窗口自动调整分辨率，旧系统（如 Win7）保持初始分辨率。
          </Typography.Paragraph>
        </Form>
      </Card>
    </Centered>
  );
}
