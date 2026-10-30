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
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
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
  { value: 32, key: "c32" },
  { value: 24, key: "c24" },
  { value: 16, key: "c16" },
  { value: 15, key: "c15" },
] as const;

// Presets map to TS_INFO_PACKET performance flags in monitor/web.go.
const experiences = [
  "full",
  "balanced",
  "fast",
  "minimal",
] as const;

const keyboards = [
  { value: 0x0804, key: "zhCN" },
  { value: 0x0409, key: "enUS" },
  { value: 0x0404, key: "zhTW" },
  { value: 0x0411, key: "ja" },
  { value: 0x0412, key: "ko" },
  { value: 0x0809, key: "enGB" },
  { value: 0x0407, key: "de" },
  { value: 0x040c, key: "fr" },
] as const;

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
function screenSizes(t: TFunction<"connect">): { value: string; label: string }[] {
  const w = Math.max(640, Math.min(4096, Math.round(window.innerWidth)) & ~3);
  const h = Math.max(480, Math.min(4096, Math.round(window.innerHeight)) & ~3);
  return [
    { value: `${w}x${h}`, label: t("fitWindow", { w, h }) },
    { value: "1280x800", label: "1280 × 800" },
    { value: "1600x900", label: "1600 × 900" },
    { value: "1920x1080", label: "1920 × 1080" },
  ];
}

// Connect opens a browser-initiated RDP session: the gateway dials the
// server, so the credentials are used once and never stored here.
export default function Connect() {
  const { t } = useTranslation("connect");
  const nav = useNavigate();
  const info = useOutletContext<MonitorInfo | null>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const sizes = screenSizes(t);
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
        <Card title={t("title")}>
          <Alert
            type="warning"
            showIcon
            message={t("needLogin.message")}
            description={t("needLogin.description")}
            action={
              <Button type="primary" onClick={() => nav("/login")}>
                {t("needLogin.goLogin")}
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
        <Card title={t("title")}>
          <Alert
            type="info"
            showIcon
            message={t("webDisabled.message")}
            description={t("webDisabled.description")}
          />
        </Card>
      </Centered>
    );
  }

  return (
    <Centered>
      <Card title={t("title")}>
        {insecurePage() && (
          <Alert
            type="warning"
            showIcon
            message={t("insecure")}
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
            label={t("form.address")}
            rules={[{ required: true, message: t("form.addressRequired") }]}
          >
            <Input
              prefix={<DesktopOutlined />}
              placeholder={t("form.addressPlaceholder")}
              autoFocus={!prefs.address}
            />
          </Form.Item>
          <Row gutter={16}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="user"
                label={t("form.user")}
                rules={[{ required: true, message: t("form.userRequired") }]}
              >
                <Input prefix={<UserOutlined />} autoComplete="off" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item name="domain" label={t("form.domain")}>
                <Input autoComplete="off" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="password"
            label={t("form.password")}
            rules={[{ required: true, message: t("form.passwordRequired") }]}
          >
            <Input.Password
              prefix={<LockOutlined />}
              autoComplete="new-password"
              autoFocus={!!prefs.address}
            />
          </Form.Item>
          <Row gutter={16}>
            <Col xs={24} sm={12}>
              <Form.Item name="resolution" label={t("form.resolution")}>
                <Select options={sizes} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item name="colorDepth" label={t("form.color")}>
                <Select
                  options={colorDepths.map((o) => ({
                    value: o.value,
                    label: t(`colorDepth.${o.key}`),
                  }))}
                />
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
                label: t("form.more"),
                forceRender: true,
                children: (
                  <Row gutter={16}>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name="experience"
                        label={t("form.experience")}
                        tooltip={t("form.experienceTip")}
                      >
                        <Select
                          options={experiences.map((v) => ({
                            value: v,
                            label: t(`experience.${v}`),
                          }))}
                          popupMatchSelectWidth={false}
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name="keyboard"
                        label={t("form.keyboard")}
                        tooltip={t("form.keyboardTip")}
                      >
                        <Select
                          options={keyboards.map((o) => ({
                            value: o.value,
                            label: t(`keyboard.${o.key}`),
                          }))}
                        />
                      </Form.Item>
                    </Col>
                  </Row>
                ),
              },
            ]}
          />
          <Button type="primary" htmlType="submit" loading={busy}>
            {t("form.submit")}
          </Button>
          <Typography.Paragraph
            type="secondary"
            style={{ marginTop: 16, marginBottom: 0 }}
          >
            {t("note")}
          </Typography.Paragraph>
        </Form>
      </Card>
    </Centered>
  );
}
