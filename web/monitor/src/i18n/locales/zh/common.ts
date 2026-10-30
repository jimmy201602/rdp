export default {
  app: { title: 'RDP 会话监控' },
  nav: { sessions: '实时监控', connect: '连接远程桌面', recordings: '录像回放' },
  shell: {
    controlOn: '协同已开启',
    recordingOff: '未开启录像',
    logout: '退出',
    login: '账号登录',
    token: '访问令牌',
    tokenHelp: '与 rdpgw 的 <code>-monitor-token</code> 一致；网关未设置令牌时留空。',
  },
  action: { save: '保存', cancel: '取消', ok: '确定', back: '返回', refresh: '刷新', delete: '删除', download: '下载', close: '关闭' },
};
