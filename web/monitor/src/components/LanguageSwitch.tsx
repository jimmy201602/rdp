import { Dropdown, Button } from 'antd';
import { GlobalOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { LANGUAGES, currentLanguage } from '../i18n';

// LanguageSwitch changes the UI language; the choice is kept in localStorage.
export default function LanguageSwitch({ dark = false }: { dark?: boolean }) {
  const { i18n } = useTranslation();
  const cur = currentLanguage();
  return (
    <Dropdown
      trigger={['click']}
      menu={{
        selectable: true,
        selectedKeys: [cur],
        items: LANGUAGES.map((l) => ({ key: l.code, label: l.label })),
        onClick: ({ key }) => void i18n.changeLanguage(key),
      }}
    >
      <Button size="small" type={dark ? 'text' : 'default'} icon={<GlobalOutlined />} style={dark ? { color: '#fff' } : undefined}>
        {LANGUAGES.find((l) => l.code === cur)?.label}
      </Button>
    </Dropdown>
  );
}
