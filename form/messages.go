package form

// User-visible strings. Every rune used here must have a glyph in
// glyphs_unifont.go; TestMessagesHaveGlyphs enforces that, and
// internal/genfont/strings.txt is the list the glyph subset is built from.
const (
	Title        = "RDP 网关登录"
	LabelAddress = "服务器地址"
	LabelUser    = "用户名"
	LabelPass    = "密码"
	LabelDomain  = "域"
	LabelButton  = "登录"
	Hint         = "Tab 切换字段，Enter 登录，Esc 断开"
	HintOptional = "（可选）"

	MsgNeedAddress   = "请输入服务器地址"
	MsgNeedUser      = "请输入用户名"
	MsgNeedPassword  = "请输入密码"
	MsgConnecting    = "正在连接 "
	MsgBadCredential = "用户名或密码错误"
	MsgRefused       = "无法连接到服务器：连接被拒绝"
	MsgUnresolved    = "无法连接到服务器：地址无法解析"
	MsgUnreachable   = "无法连接到服务器"
	MsgTimeout       = "连接超时"
	MsgBadCert       = "服务器证书校验失败"
	MsgNotAllowed    = "目标不在允许范围内"
	MsgNegotiation   = "协议协商失败"
	MsgRejected      = "服务器拒绝连接"
	MsgDisconnected  = "服务器已断开"
	MsgFailed        = "连接失败，请重试"
	MsgConnected     = "连接已建立"
)

var allMessages = []string{
	Title, LabelAddress, LabelUser, LabelPass, LabelDomain, LabelButton, Hint, HintOptional,
	MsgNeedAddress, MsgNeedUser, MsgConnecting, MsgBadCredential, MsgRefused, MsgUnresolved,
	MsgUnreachable, MsgTimeout, MsgBadCert, MsgNotAllowed, MsgNegotiation, MsgRejected,
	MsgDisconnected, MsgFailed, MsgConnected,
}
