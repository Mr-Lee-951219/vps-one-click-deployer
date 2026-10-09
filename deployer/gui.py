import io
import json
import secrets
import threading
import time
from datetime import datetime
import webbrowser
from pathlib import Path
import qrcode
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSize
from PySide6.QtGui import QFont, QPixmap, QIcon, QFontDatabase, QPalette, QColor
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QSpinBox, QCheckBox, QComboBox, QFormLayout, QFrame, QScrollArea, QStackedWidget, QPlainTextEdit, QProgressBar, QMessageBox, QDialog, QFileDialog, QTabBar, QSplitter, QTableWidget, QTableWidgetItem, QListView, QGraphicsDropShadowEffect)
from .models import Settings, random_panel_password
from .engine import Engine, ASSETS
from .domain_certificate import check_domain
from .ssh import ConnectionCancelled
from .storage import save_public, load_public, load_secret, clear_saved_ssh_credentials, remember_server, saved_servers, server_id, save_server_limits, LIMIT_KEYS, migrate_saved_servers, load_login_password, forget_login_password
from .maintenance_ui import MaintenanceUi, LimitsEditor
from .maintenance import date_text
from .public_panel import public_url
from .guide import STEPS

from .theme import apply_theme, themed_icon
from .widgets import CollapsibleCard,PortEdit,RandomPortField,CertificateSelector
from . import __version__
from .errors import friendly_error

def label(text, name=None):
    w = QLabel(text)
    w.setWordWrap(True)
    if name: w.setObjectName(name)
    return w

def button(text, fn, primary=False):
    w = QPushButton(text)
    if primary: w.setObjectName('primary')
    w.setCursor(Qt.PointingHandCursor)
    w.clicked.connect(fn)
    return w

def card(title, description=''):
    frame = QFrame()
    frame.setObjectName('card')
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22,22,22,22)
    layout.setSpacing(14)
    shadow=QGraphicsDropShadowEffect(frame);shadow.setBlurRadius(20);shadow.setOffset(0,4);shadow.setColor(QColor(30,30,50,14));frame.setGraphicsEffect(shadow)
    layout.addWidget(label(title,'section'))
    if description: layout.addWidget(label(description,'subtitle'))
    return frame,layout

class Worker(QThread):
    log = Signal(str)
    progress = Signal(int,str)
    result = Signal(object)
    failed = Signal(str)
    cancelled = Signal(str)
    verify = Signal(str,str,object)
    def __init__(self, settings, action, payload=None):
        super().__init__()
        self.settings, self.action = settings, action
        self.payload = payload
        self.engine = None
        self.keep = False
    def ask_trust(self, host, fp, previous=''):
        reply = {'event':threading.Event(),'accepted':False,'previous':previous}
        self.verify.emit(host,fp,reply)
        reply['event'].wait()
        return reply['accepted']
    def trust(self, host, fp):
        return self.ask_trust(host, fp)
    def trust_changed(self, host, previous, fp):
        return self.ask_trust(host, fp, previous)
    def run(self):
        self.engine = Engine(self.settings,self.log.emit,self.progress.emit,self.trust,self.trust_changed)
        self.engine.ssh.cancel_requested = self.isInterruptionRequested
        original_progress = self.engine.progress
        def checkpoint(percent, message):
            if self.isInterruptionRequested():
                raise ConnectionCancelled('已在安全步骤之间停止等待。请查看后台任务，再继续未完成部署。')
            original_progress(percent, message)
        self.engine.progress = checkpoint
        if self.payload and 'password' in self.payload:
            self.engine.redact.add(self.payload['password'])
        if self.payload and 'cf_token' in self.payload:
            self.engine.redact.add(self.payload['cf_token'])
        try:
            if self.action == 'cloudflare':
                result = check_domain(self.settings.domain,self.settings.host)
            elif self.action == 'open':
                record = self.engine.load_remote()
                generated=not bool(public_url(record))
                if generated:record=self.engine.enable_automatic_panel()
                url=public_url(record)
                if not url:
                    self.engine.panel(record);self.keep=True
                    url=f"http://127.0.0.1:{self.engine.tunnel.port}{record['identity']['panel_path']}"
                result = {'url':url,'record':record,'generated':generated}
            elif self.action == 'test':
                from .testing import test_nodes
                record = self.engine.load_remote()
                actual=Settings(**record['settings']);actual.host=self.settings.host
                result = test_nodes(actual,record,self.log.emit)
            elif self.action.startswith('restore:'):
                result = self.engine.restore(self.action.split(':',1)[1])
            elif self.action in ('restart_core','restart_panel','reboot'):
                result = self.engine.service_action(self.action)
            elif self.payload is not None:
                result = getattr(self.engine, self.action)(self.payload)
            else:
                result = getattr(self.engine, self.action)()
        except ConnectionCancelled as ex:
            self.cancelled.emit(str(ex))
            return
        except Exception as ex:
            self.failed.emit(self.engine.redact(friendly_error(ex)))
            return
        finally:
            if not self.keep: self.engine.close()
        self.settings = self.engine.settings
        self.result.emit(result)

class HostIdentityDialog(QDialog):
    def __init__(self,parent,host,fingerprint,previous=''):
        super().__init__(parent)
        self.setObjectName('hostIdentityPrompt');self.setWindowTitle('确认服务器身份');self.setFixedWidth(690)
        layout=QVBoxLayout(self);layout.setContentsMargins(26,24,26,24);layout.setSpacing(16)
        layout.addWidget(label('服务器指纹发生变化' if previous else '首次连接这台服务器','brand'))
        layout.addWidget(label('服务器：'+host,'subtitle'))
        layout.addWidget(label('严格核对模式：请与服务商控制台核对指纹。确认后软件会记住当前身份，并继续本次操作。','subtitle'))
        form=QFormLayout();form.setSpacing(12)
        for title,value in ([('原指纹',previous)] if previous else [])+[('当前指纹',fingerprint)]:
            field=QLineEdit(value);field.setReadOnly(True);form.addRow(title,field)
        layout.addLayout(form)
        details=QFrame();details.setObjectName('card');area=QVBoxLayout(details);area.setContentsMargins(16,14,16,14)
        area.addWidget(label('在 RakSmart 的这台服务器网页控制台（VNC / KVM）登录 root，然后执行：','subtitle'))
        command=QLineEdit('for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key" -E sha256; done');command.setReadOnly(True);area.addWidget(command)
        area.addWidget(label('输出会列出各类型公钥的 SHA256 指纹；找到与上方当前指纹完全相同的一条。此命令不修改系统。','subtitle'))
        details.hide()
        help_button=button('如何核对？',lambda:details.setVisible(not details.isVisible()))
        layout.addWidget(help_button);layout.addWidget(details)
        row=QHBoxLayout();row.addStretch()
        cancel=button('取消',self.reject);cancel.setDefault(True);cancel.setAutoDefault(True)
        accept=button('信任并继续',self.accept,True);accept.setAutoDefault(False)
        row.addWidget(cancel);row.addWidget(accept);layout.addLayout(row);cancel.setFocus()

class Guide(QDialog):
    def __init__(self,parent):
        super().__init__(parent)
        self.setWindowTitle('从注册域名到证书验证')
        self.resize(850,740)
        outer = QVBoxLayout(self)
        outer.addWidget(label('Cloudflare 配置向导','title'))
        outer.addWidget(label('按步骤完成；进度自动保存在这台电脑。','subtitle'))
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(16)
        done = load_public('guide-progress-http',{})
        for i,(title,text,url) in enumerate(STEPS):
            frame,area = card(title,text)
            row = QHBoxLayout()
            check = QCheckBox('我已完成这一步'); check.setChecked(done.get(str(i),False))
            check.toggled.connect(lambda value,n=i:self.save(n,value))
            row.addWidget(check); row.addStretch(); row.addWidget(button('打开相关页面',lambda checked=False,u=url:webbrowser.open(u)))
            area.addLayout(row); layout.addWidget(frame)
        scroll.setWidget(body); outer.addWidget(scroll)
        outer.addWidget(button('返回软件',self.accept,True))
    def save(self,n,value):
        data=load_public('guide-progress-http',{}); data[str(n)]=value; save_public('guide-progress-http',data)

class Window(MaintenanceUi, QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('NodePilot · 节点部署助手 v'+__version__)
        self.setWindowIcon(QIcon(str(ASSETS/'branding/nodepilot.ico')))
        self.setMinimumSize(760,420)
        screen=QApplication.primaryScreen().availableGeometry()
        self.resize(min(1260,screen.width()-24),min(860,screen.height()-40))
        self.workers=[]; self.tunnels=[]; self.active=None; self.record=None
        self.inputs={}
        self.port_random_buttons={}
        self.certificate_confirmation=None
        self.started_at=None
        self.limits_endpoint=None
        self.login_signature=None
        shell=QWidget(); self.setCentralWidget(shell); outer=QVBoxLayout(shell); outer.setContentsMargins(0,0,0,0); outer.setSpacing(0)
        header=QFrame(); header.setObjectName('header'); hl=QHBoxLayout(header); hl.setContentsMargins(26,16,26,16); hl.setSpacing(12)
        logo=label('','logo'); logo.setAlignment(Qt.AlignCenter); logo.setFixedSize(40,40)
        logo.setPixmap(QIcon(str(ASSETS/'branding/nodepilot.ico')).pixmap(QSize(40,40),self.devicePixelRatioF()))
        logo.setAccessibleName('NodePilot 图标');hl.addWidget(logo)
        hl.addWidget(label('NodePilot','brand')); hl.addWidget(label('节点部署助手','subtitle')); hl.addStretch()
        self.theme_switcher=QFrame();self.theme_switcher.setObjectName('themeSwitcher')
        appearance_row=QHBoxLayout(self.theme_switcher);appearance_row.setContentsMargins(3,3,3,3);appearance_row.setSpacing(2)
        for mode,title in (('light','明亮'),('dark','暗色')):
            toggle=QPushButton(title,self.theme_switcher);toggle.setObjectName(mode+'Theme');toggle.setCheckable(True);toggle.setAutoExclusive(True)
            toggle.setChecked(QApplication.instance().property('appearance')==mode);toggle.setCursor(Qt.PointingHandCursor)
            toggle.setAccessibleName('切换'+title+'主题');toggle.setToolTip('切换'+title+'主题并记住选择')
            toggle.clicked.connect(lambda checked=False,m=mode:self.set_appearance(m));appearance_row.addWidget(toggle)
        hl.addWidget(self.theme_switcher)
        self.saved_btn=button('已保存服务器',self.saved_servers_dialog);hl.addWidget(self.saved_btn);outer.addWidget(header)
        navrow=QHBoxLayout(); navrow.setContentsMargins(24,14,24,14); navrow.addStretch()
        navframe=QFrame(); navframe.setObjectName('nav'); nl=QHBoxLayout(navframe); nl.setContentsMargins(0,0,0,0)
        self.nav=QTabBar(); self.nav.setDrawBase(False); self.nav.setExpanding(False)
        for title in ('一键部署','节点与端口','服务器维护','域名配置教程'):self.nav.addTab(title)
        nl.addWidget(self.nav); navrow.addWidget(navframe); navrow.addStretch(); outer.addLayout(navrow)
        self.splitter=QSplitter(Qt.Horizontal); self.splitter.setChildrenCollapsible(False)
        self.config_panel=QWidget(); self.config_panel.setMinimumWidth(300)
        cl=QVBoxLayout(self.config_panel); cl.setContentsMargins(0,0,0,0); cl.setSpacing(10)
        self.heading=label('连接与部署参数','section'); cl.addWidget(self.heading)
        self.sub=label('设置服务器、协议和证书，然后开始部署。','subtitle'); cl.addWidget(self.sub)
        self.stack=QStackedWidget(); cl.addWidget(self.stack,1)
        self.deploy_footer=QWidget(); footer=QVBoxLayout(self.deploy_footer); footer.setContentsMargins(0,0,8,0);footer.setSpacing(8)
        self.deploy_btn=button('开始一键部署',lambda:self.start('deploy'),True); footer.addWidget(self.deploy_btn)
        cl.addWidget(self.deploy_footer)
        self.splitter.addWidget(self.config_panel)
        monitor=QWidget(); monitor.setMinimumWidth(360); ml=QVBoxLayout(monitor); ml.setContentsMargins(0,0,0,0); ml.setSpacing(12)
        status=QFrame(); status.setObjectName('status'); st=QVBoxLayout(status);st.setContentsMargins(18,14,18,14); st.setSpacing(10)
        sr=QHBoxLayout();self.state=label('准备就绪 · 填写左侧参数后开始','statusText');sr.addWidget(self.state,1)
        self.elapsed=label('00:00','elapsed');sr.addWidget(self.elapsed);st.addLayout(sr)
        self.progress=QProgressBar();self.progress.setRange(0,100);self.progress.setValue(0);self.progress.setTextVisible(False);self.progress.setFixedHeight(7);st.addWidget(self.progress);ml.addWidget(status)
        self.build_logs(ml);self.splitter.addWidget(monitor);self.splitter.setSizes([450,740]);self.splitter.setStretchFactor(0,0);self.splitter.setStretchFactor(1,1)
        content=QHBoxLayout();content.setContentsMargins(24,0,24,22);content.addWidget(self.splitter);outer.addLayout(content,1)
        self.build_deploy(); self.build_results(); self.build_manage(); self.build_guide()
        self.nav.currentChanged.connect(self.navigate); self.navigate(0)
        self.timer=QTimer(self);self.timer.setInterval(1000);self.timer.timeout.connect(self.tick)
        self.limit_save_timer=QTimer(self);self.limit_save_timer.setSingleShot(True);self.limit_save_timer.setInterval(350)
        self.limit_save_timer.timeout.connect(self.save_limit_reference)
        self.limits.changed.connect(lambda:self.limit_save_timer.start())
        try:
            cleared=clear_saved_ssh_credentials()
            if cleared:self.append_log('已清理旧格式登录缓存。勾选“记住密码”后，新版使用独立加密文件保存。')
        except (OSError,RuntimeError) as ex:
            self.append_log('旧格式缓存清理未完成：'+str(ex))
        migrated=migrate_saved_servers()
        if migrated:self.append_log('已从本机旧部署记录导入 '+str(migrated)+' 台服务器到顶部列表。登录密码未导入。')
        saved=load_public('last-server',{})
        self.tls.setCurrentIndex(max(0,self.tls.findData(saved.get('tls_mode',''))))
        for k,w in self.inputs.items():
            if k in saved and k not in ('host','ssh_port','password','panel_user','panel_password','private_key','cf_token','panel_port','vless_port','hy2_port','name','remember_password') + LIMIT_KEYS:
                if isinstance(w,QLineEdit): w.setText(str(saved[k]))
                elif isinstance(w,QSpinBox): w.setValue(saved[k])
                elif isinstance(w,QCheckBox): w.setChecked(saved[k])
        for key in ('panel_port','vless_port','hy2_port'):self.randomize_port(key)
        self.inputs['host'].editingFinished.connect(self.load_server_record)
        self.inputs['ssh_port'].editingFinished.connect(self.load_server_record)
        self.inputs['username'].editingFinished.connect(self.load_saved_login)
    def set_appearance(self,mode):
        selected=apply_theme(QApplication.instance(),mode)
        try:save_public('appearance',{'mode':selected})
        except OSError as ex:self.append_log('主题已切换，但保存选择未完成：'+str(ex))
    def page(self):
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        body=QWidget(); layout=QVBoxLayout(body); layout.setContentsMargins(4,4,12,12); layout.setSpacing(20)
        scroll.setWidget(body); self.stack.addWidget(scroll)
        return layout
    def line(self,k,value='',password=False):
        w=QLineEdit(value)
        if password:w.setEchoMode(QLineEdit.Password)
        self.inputs[k]=w; return w
    def port(self,k,title,random=False):
        edit=PortEdit();self.inputs[k]=edit
        if not random:return edit
        field=RandomPortField(edit,title,lambda:self.randomize_port(k));self.port_random_buttons[k]=field.random
        return field
    def randomize_port(self,k):
        if self.active and self.active.isRunning():return
        excluded={w.value() for key,w in self.inputs.items() if isinstance(w,PortEdit)}
        candidates=[p for p in range(10000,30001) if p not in excluded]
        self.inputs[k].setValue(secrets.choice(candidates))
    def load_server_record(self):
        host=self.inputs['host'].text().strip();port=self.inputs['ssh_port'].value()
        endpoint=server_id(host,port) if host and port else None
        if endpoint!=self.limits_endpoint:
            if self.limits_endpoint is not None:
                self.inputs['password'].clear();self.inputs['private_key'].clear()
                self.inputs['panel_user'].clear();self.inputs['panel_password'].setText(random_panel_password())
            self.limits_endpoint=endpoint
            item=next((x for x in saved_servers() if x.get('id')==endpoint),{})
            self.limits.set_values(item.get('limits',{}))
            self.client_data=[];self.client_table.setRowCount(0);self.backup_data=[];self.backup_table.setRowCount(0)
            self.bbr_summary.setText('尚未读取当前 BBR 状态')
            self.security_data={};self.security_rows=[];self.security_table.setRowCount(0)
            self.security_summary.setText('尚未读取当前服务器的防护状态');self.security_metrics.setText('请刷新当前服务器的统计');self.security_times.setText('封禁与解封时间：刷新后显示')
            self.security_totals.setText('Fail2ban 累计计数：刷新后显示')
        self.maintenance_target.setText('目标服务器：'+(self.target_text() if host and port else '尚未选择'))
        self.load_saved_login()
        self.record=load_secret(host.replace(':','_')+'_'+str(port)) if host and port else None
        if self.record:
            for key,value in self.record['ports'].items():self.inputs[key+'_port'].setValue(value)
            self.inputs['panel_user'].setText(self.record['identity']['panel_user'])
            self.inputs['panel_password'].setText(self.record['identity']['panel_password'])
            self.show_record(self.record)
        else:
            self.summary.setText('还没有当前服务器的部署记录。');self.credentials.clear();self.public_link.clear();self.linkbox.clear();self.table.setRowCount(0)
            self.result_user.clear();self.result_password.clear()
    def check(self,k,text,value=True):
        w=QCheckBox(text); w.setChecked(value); self.inputs[k]=w; return w
    def build_deploy(self):
        page=self.page(); frame=CollapsibleCard('服务器连接','填写你的服务器 SSH 地址和端口。重装系统后，填写当前端口和密码即可重新连接。');area=frame.area;self.server_card=frame
        form=QFormLayout(); form.setSpacing(12)
        form.addRow('服务器名称',self.line('name','我的服务器'))
        form.addRow('服务器地址',self.line('host'))
        form.addRow('SSH 端口',self.port('ssh_port','SSH 端口')); form.addRow('用户名',self.line('username','root'))
        form.addRow('SSH 密码',self.line('password',password=True)); form.addRow('私钥路径（可选）',self.line('private_key'))
        area.addLayout(form)
        area.addWidget(self.check('remember_password','记住密码 · 本机加密保存',True))
        area.addWidget(label('连接成功后按服务器加密保存；下次选择这台服务器可直接连接。','subtitle'))
        strict=self.check('strict_host_key','连接前核对服务器身份（可选）',False)
        strict.setToolTip('默认自动更新服务器身份记录。勾选后，首次连接和指纹变化时需确认，才会发送登录凭据。')
        area.addWidget(strict)
        row=QHBoxLayout();row.addWidget(button('测试连接',lambda:self.start('inspect')))
        self.clear_connection_btn=button('清空连接信息',self.clear_connection);row.addWidget(self.clear_connection_btn)
        area.addLayout(row)
        self.forget_password_btn=button('清除这台服务器保存的密码',self.forget_password);area.addWidget(self.forget_password_btn)
        page.addWidget(frame)
        frame=CollapsibleCard('节点与端口','已生成面板和节点端口；点击右侧随机图标可重新生成，也可直接输入端口。');area=frame.area;self.ports_card=frame
        row=QHBoxLayout(); row.addWidget(self.check('vless','VLESS · REALITY')); row.addWidget(self.check('hy2','HY2 · QUIC')); row.addStretch(); area.addLayout(row)
        form=QFormLayout(); form.addRow('面板端口',self.port('panel_port','面板端口',True)); form.addRow('VLESS · TCP 端口',self.port('vless_port','VLESS 端口',True)); form.addRow('HY2 · UDP 端口',self.port('hy2_port','HY2 端口',True)); area.addLayout(form)
        area.addWidget(label('3x-ui 面板账号与密码','section'))
        form=QFormLayout();form.addRow('面板账号',self.line('panel_user'))
        self.inputs['panel_user'].setPlaceholderText('手动填写你的面板账号')
        password_row=QHBoxLayout();password_row.addWidget(self.line('panel_password',random_panel_password(),password=True),1)
        self.panel_password_random=button('随机',lambda:self.inputs['panel_password'].setText(random_panel_password()))
        self.panel_password_show=button('显示',self.toggle_panel_password)
        password_row.addWidget(self.panel_password_show);password_row.addWidget(self.panel_password_random)
        form.addRow('面板密码',password_row);area.addLayout(form)
        area.addWidget(label('密码可直接输入，也可点击随机生成；与 SSH 登录密码分别设置。已有面板请在服务器维护中修改。','subtitle'))
        from PySide6.QtWidgets import QRadioButton,QButtonGroup
        area.addWidget(label('TCP BBR 模式','subtitle'));self.bbr_group=QButtonGroup(self);self.bbr_modes={}
        for key,text in (('keep','保持当前设置'),('native','启用系统内核 BBR（原版 Debian 12 为 v1）'),('v3','安装 byJoey BBRv3')):
            radio=QRadioButton(text);self.bbr_group.addButton(radio);self.bbr_modes[key]=radio;area.addWidget(radio)
        self.bbr_modes['keep'].setChecked(True)
        area.addWidget(self.check('firewall','配置本机端口规则'))
        area.addWidget(label('系统内核选项启用正在运行的内核自带 BBR，不更换内核。原版 Debian 12 的 6.1 内核提供 BBRv1；BBRv3 使用 byJoey 内核，安装后需重启。HY2 QUIC 由协议核心管理。','subtitle'))
        area.addWidget(label('VLESS REALITY 直接连接 VPS，无需自己的域名证书。配置域名证书可为面板启用 HTTPS；灰云解析不改变 VPS 的线路。','subtitle'))
        area.addWidget(label('日期与流量','section'));self.limits=LimitsEditor();area.addWidget(self.limits)
        def protocols_changed():
            self.limits.protocols=(self.inputs['vless'].isChecked(),self.inputs['hy2'].isChecked());self.limits.refresh()
        self.inputs['vless'].toggled.connect(protocols_changed);self.inputs['hy2'].toggled.connect(protocols_changed)
        page.addWidget(frame)
        frame=CollapsibleCard('域名与证书','部署前在此设置证书；已部署服务器用下面的“给现有面板 / HY2 应用域名证书”。仅 VLESS 也可启用面板 HTTPS。域名先设置灰云 A 记录，并放行 TCP 80。');area=frame.area
        self.certificate_card=frame
        self.tls=CertificateSelector();area.addWidget(self.tls)
        form=QFormLayout(); form.addRow('访问域名',self.line('domain')); self.inputs['domain'].setPlaceholderText('例如 node.example.com，请填写你的域名');area.addLayout(form)
        self.certificate_status=label('尚未确认部署证书设置','subtitle'); area.addWidget(self.certificate_status)
        self.certificate_confirm_btn=button('确认部署证书设置',self.confirm_certificate); area.addWidget(self.certificate_confirm_btn)
        self.tls.currentIndexChanged.connect(self.reset_certificate_confirmation)
        self.inputs['domain'].textChanged.connect(self.reset_certificate_confirmation)
        row=QHBoxLayout(); row.addWidget(button('从添加域名开始',self.guide)); row.addWidget(button('检查域名解析',lambda:self.start('cloudflare'))); area.addLayout(row)
        area.addWidget(button('给现有面板 / HY2 应用域名证书',lambda:self.start('apply_certificate'))); page.addWidget(frame); page.addStretch()
    def build_results(self):
        page=self.page(); frame,area=card('部署结果','部署后可导入 Windows v2rayN，或打开管理面板继续管理用户。')
        self.summary=label('还没有部署记录。'); area.addWidget(self.summary)
        row=QHBoxLayout(); row.addWidget(button('打开面板',lambda:self.start('open'),True)); row.addWidget(button('测试两种节点',lambda:self.start('test'))); area.addLayout(row)
        area.addWidget(label('面板登录信息','section'))
        form=QFormLayout();self.result_copy_buttons={}
        self.public_link=self.result_copy_field(form,'面板链接','link')
        self.public_link.setPlaceholderText('部署后自动生成；已有服务器点击“打开面板”')
        self.result_user=self.result_copy_field(form,'面板账号','username')
        self.result_password=self.result_copy_field(form,'面板密码','password')
        area.addLayout(form)
        self.credentials=label('','subtitle');area.addWidget(self.credentials)
        self.linkbox=QPlainTextEdit(); self.linkbox.setReadOnly(True); self.linkbox.setMinimumHeight(160); area.addWidget(self.linkbox)
        row=QHBoxLayout(); row.addWidget(button('复制链接',lambda:QApplication.clipboard().setText(self.linkbox.toPlainText()))); row.addWidget(button('二维码',self.qr)); row.addWidget(button('导出链接',self.export)); area.addLayout(row); page.addWidget(frame)
        frame,area=card('RakSmart 安全组','服务器本机规则会自动配置。云安全组请按下方实际端口放行；启用公网面板后也需放行面板 TCP 端口。')
        self.table=QTableWidget(0,4); self.table.setHorizontalHeaderLabels(['用途','端口','协议','来源']); self.table.horizontalHeader().setStretchLastSection(True); self.table.setMinimumHeight(160); area.addWidget(self.table)
        row=QHBoxLayout(); row.addWidget(button('查看放行步骤',self.guide)); row.addWidget(button('复制端口清单',self.copy_rules)); area.addLayout(row); area.addWidget(button('同步面板现有端口',lambda:self.start('sync'))); page.addWidget(frame); page.addStretch()
    def result_copy_field(self,form,title,key):
        from PySide6.QtWidgets import QToolButton
        field=QLineEdit();field.setReadOnly(True)
        btn=QToolButton();btn.setObjectName('copyResult');btn.setFixedSize(36,36);btn.setIconSize(QSize(18,18))
        btn.setIcon(themed_icon('copy.svg','icons'));btn.setToolTip('复制'+title);btn.setAccessibleName('复制'+title)
        btn.setCursor(Qt.PointingHandCursor);btn.setEnabled(False)
        def copy():
            if not field.text():return
            QApplication.clipboard().setText(field.text());btn.setProperty('copySuccess',True);btn.setIcon(themed_icon('copied.svg','icons'));btn.setToolTip('已复制')
            QTimer.singleShot(1400,lambda:(btn.setProperty('copySuccess',False),btn.setIcon(themed_icon('copy.svg','icons')),btn.setToolTip('复制'+title)))
        btn.clicked.connect(copy);field.textChanged.connect(lambda value:btn.setEnabled(bool(value)))
        row=QHBoxLayout();row.setSpacing(8);row.addWidget(field,1);row.addWidget(btn);form.addRow(title,row)
        self.result_copy_buttons[key]=btn;return field
    def build_guide(self):
        page=self.page(); frame,area=card('从域名注册到证书验证','完整的分步指引，包含 Spaceship、Cloudflare 激活、灰云解析及 TCP 80 验证端口。')
        area.addWidget(button('打开完整配置向导',self.guide,True)); area.addWidget(label('HY2 使用 UDP；Cloudflare 普通橙云不能代理它。若域名同时用于邮箱，保留所有邮箱相关 DNS 记录。','subtitle')); page.addWidget(frame); page.addStretch()
    def build_logs(self,layout):
        terminal=QFrame();terminal.setObjectName('terminal'); area=QVBoxLayout(terminal);area.setContentsMargins(8,0,8,8);area.setSpacing(0)
        header=QFrame();header.setObjectName('terminalHeader'); row=QHBoxLayout(header);row.setContentsMargins(10,12,10,12);row.setSpacing(8)
        row.addStretch()
        self.stop_wait_btn=button('停止等待',self.stop_waiting);self.stop_wait_btn.setEnabled(False);row.addWidget(self.stop_wait_btn)
        row.addWidget(button('清空',self.clear_logs));row.addWidget(button('复制',lambda:QApplication.clipboard().setText(self.logs.toPlainText())));row.addWidget(button('导出',self.export_logs));area.addWidget(header)
        self.logs=QPlainTextEdit();self.logs.setObjectName('liveLog');self.logs.setReadOnly(True);self.logs.setLineWrapMode(QPlainTextEdit.NoWrap);self.logs.document().setMaximumBlockCount(10000);area.addWidget(self.logs,1)
        tail=QHBoxLayout();tail.setContentsMargins(10,8,10,0)
        self.log_meta=label('等待任务 · 输出会实时更新','terminalMeta');tail.addWidget(self.log_meta,1)
        self.follow=QCheckBox('自动滚动');self.follow.setChecked(True);self.follow.toggled.connect(self.follow_latest);tail.addWidget(self.follow);area.addLayout(tail);layout.addWidget(terminal,1)
        self.append_log('准备就绪。填写左侧服务器信息，可先测试连接，再开始部署。')
    def append_log(self,text):
        text=str(text).replace('\r','\n').strip()
        if not text:return
        bar=self.logs.verticalScrollBar();position=bar.value()
        self.logs.appendPlainText('['+datetime.now().strftime('%H:%M:%S')+'] '+text)
        if self.follow.isChecked():bar.setValue(bar.maximum())
        else:bar.setValue(position)
        self.log_meta.setText('最新输出 '+datetime.now().strftime('%H:%M:%S')+' · '+('跟随输出' if self.follow.isChecked() else '已暂停滚动'))
    def follow_latest(self,enabled):
        if enabled:self.logs.verticalScrollBar().setValue(self.logs.verticalScrollBar().maximum())
    def clear_logs(self):self.logs.clear();self.log_meta.setText('窗口已清空 · 后续输出继续显示')
    def export_logs(self):
        path,_=QFileDialog.getSaveFileName(self,'导出执行记录','NodePilot-log.txt','文本文件 (*.txt)')
        if path:Path(path).write_text(self.logs.toPlainText(),encoding='utf-8')
    def tick(self):
        if self.started_at is not None:
            seconds=int(time.monotonic()-self.started_at);self.elapsed.setText(f'{seconds//60:02d}:{seconds%60:02d}')
    def set_busy(self,busy):
        for widget in list(self.inputs.values())+list(self.port_random_buttons.values())+[self.tls,self.clear_connection_btn,self.forget_password_btn,self.certificate_confirm_btn,self.panel_password_random,self.panel_password_show]:widget.setEnabled(not busy)
        self.deploy_btn.setEnabled(not busy)
        self.saved_btn.setEnabled(not busy);self.limits.setEnabled(not busy)
        for radio in self.bbr_modes.values():radio.setEnabled(not busy)
        self.security_card.setEnabled(not busy)
        self.stop_wait_btn.setEnabled(busy)

    def stop_waiting(self):
        if self.active and self.active.isRunning():
            self.active.requestInterruption();self.stop_wait_btn.setEnabled(False)
            self.state.setText('正在停止等待 · 当前安全步骤完成后退出')
            self.append_log('停止等待不会强行结束 apt、证书申请或服务器后台任务。可稍后查看后台任务并继续部署。')

    def release_worker(self,worker):
        worker.settings.password=''
        if worker in self.workers:self.workers.remove(worker)
        if self.active is worker:self.active=None
        worker.deleteLater()
    def navigate(self,n):
        self.stack.setCurrentIndex(n)
        self.deploy_footer.setVisible(n==0)
        headings=[('连接与部署参数','设置服务器、协议和证书，然后开始部署。'),('节点与端口','导入客户端，核对实际放行端口。'),('服务器维护','查看状态，管理节点、证书与备份。'),('Cloudflare 配置','从注册域名到证书验证的分步教程。')]
        self.heading.setText(headings[n][0]); self.sub.setText(headings[n][1])
    def toggle_panel_password(self):
        edit=self.inputs['panel_password'];show=edit.echoMode()==QLineEdit.Password
        edit.setEchoMode(QLineEdit.Normal if show else QLineEdit.Password)
        self.panel_password_show.setText('隐藏' if show else '显示')
    def guide(self):Guide(self).exec()
    def clear_connection(self):
        if self.active and self.active.isRunning():return
        for key in ('host','ssh_port','password','private_key'):self.inputs[key].clear()
        self.load_server_record()
        try:
            clear_saved_ssh_credentials()
            self.append_log('已清空当前连接信息。加密保存的密码可用“清除这台服务器保存的密码”删除。')
        except (OSError,RuntimeError) as ex:
            QMessageBox.warning(self,'缓存清理未完成',str(ex))
    def load_saved_login(self):
        host=self.inputs['host'].text().strip();port=self.inputs['ssh_port'].value();username=self.inputs['username'].text().strip()
        signature=(server_id(host,port),username) if host and port and username else None
        if signature==self.login_signature:return
        if self.login_signature is not None:self.inputs['password'].clear()
        self.login_signature=signature
        if signature:
            try:
                password=load_login_password(host,port,username)
                if password and not self.inputs['password'].text():
                    self.inputs['password'].setText(password);self.inputs['remember_password'].setChecked(True)
            except (OSError,ValueError,RuntimeError):self.append_log('这台服务器保存的密码暂无法读取，请重新输入。')
    def forget_password(self):
        if self.active and self.active.isRunning():return
        host=self.inputs['host'].text().strip();port=self.inputs['ssh_port'].value()
        if not host or not port:
            QMessageBox.information(self,'先选择服务器','请先选择服务器或填写服务器地址和 SSH 端口。');return
        try:
            forget_login_password(host,port);self.inputs['password'].clear();self.inputs['remember_password'].setChecked(False)
            self.append_log('已清除 '+self.target_text()+' 在本机加密保存的登录密码。')
        except (OSError,RuntimeError) as ex:QMessageBox.warning(self,'清除未完成',str(ex))
    def save_limit_reference(self):
        if self.active and self.active.isRunning():return
        host=self.inputs['host'].text().strip();port=self.inputs['ssh_port'].value()
        if not host or not port or self.limits_endpoint!=server_id(host,port):return
        try:save_server_limits(self.settings(False))
        except (ValueError,OSError):pass
    def reset_certificate_confirmation(self,*args):
        self.certificate_confirmation=None
        self.certificate_status.setText('尚未确认部署证书设置')
    def certificate_selection(self):
        s=self.settings(False)
        return (s.tls_mode,s.domain) if s.tls_mode in ('domain','cloudflare') else (s.tls_mode,)
    def focus_certificate(self):
        self.nav.setCurrentIndex(0)
        self.certificate_card.setExpanded(True)
        QTimer.singleShot(0,lambda:self.stack.widget(0).ensureWidgetVisible(self.tls,0,24))
        self.tls.setFocus()
    def confirm_certificate(self):
        if self.active and self.active.isRunning():return
        try:
            s=self.settings(False);s.validate_hy2_certificate()
            self.certificate_confirmation=self.certificate_selection()
            text='自签证书 · 固定指纹，无需填写域名' if s.tls_mode=='selfsigned' else '域名证书 · '+s.domain+'（部署时签发；先放行 TCP 80）'
            self.certificate_status.setText('已确认：'+text)
        except ValueError as ex:
            self.reset_certificate_confirmation()
            QMessageBox.information(self,'请先设置 HY2 证书',str(ex));self.focus_certificate()
    def system_notice(self):
        dialog=QDialog(self);dialog.setWindowTitle('服务器系统提示');dialog.setObjectName('systemPrompt');dialog.setFixedWidth(560)
        layout=QVBoxLayout(dialog);layout.setContentsMargins(28,26,28,26);layout.setSpacing(18)
        layout.addWidget(label('开始前，请确认服务器系统','brand'))
        layout.addWidget(label('请先在服务器上安装 Debian 12\n64 位 · x86_64','section'))
        layout.addWidget(label('当前版本的部署软件支持并已测试 Debian 12。\n如果服务器已经安装 Debian 12，可以直接继续。','subtitle'))
        frame,area=card('系统范围说明','3x-ui 本身支持多种操作系统。Debian 12 是本部署软件当前支持的服务器系统；其他版本需要完成适配和测试后再开放。')
        layout.addWidget(frame)
        row=QHBoxLayout();row.addStretch();row.addWidget(button('退出软件',dialog.reject));row.addWidget(button('已确认，继续',dialog.accept,True));layout.addLayout(row)
        accepted=dialog.exec()==QDialog.Accepted
        if not accepted:QApplication.instance().quit()
        return accepted
    def settings(self,validate=True):
        s=Settings()
        for k,w in self.inputs.items():
            value=w.value() if isinstance(w,PortEdit) else w.text().strip() if isinstance(w,QLineEdit) and k not in ('password','panel_password','cf_token') else w.text() if isinstance(w,QLineEdit) else w.isChecked() if isinstance(w,QCheckBox) else w.value()
            setattr(s,k,value)
        s.tls_mode=self.tls.currentData()
        s.bbr_mode=next(k for k,w in self.bbr_modes.items() if w.isChecked());s.bbr=s.bbr_mode=='v3'
        for key,value in self.limits.read().items():setattr(s,key,value)
        if validate:s.validate()
        return s
    def start(self,action,payload=None):
        if getattr(self,'bbr_dialog',None) is not None:
            return  # Pause maintenance timers while the modal owns its SSH operation.
        if self.active and self.active.isRunning():
            QMessageBox.information(self,'任务进行中','请等待当前任务结束。'); return
        try:
            s=self.settings(False)
            if action=='deploy' and s.hy2 and self.certificate_confirmation!=self.certificate_selection():
                QMessageBox.information(self,'请先设置 HY2 证书','你已勾选 HY2，请先选择证书方式，并点击“确认部署证书设置”。\n\n自签证书：无需域名。\n域名证书：只填域名，确保灰云解析指向 VPS，并在安全组放行 TCP 80。\n\n确认后再开始部署。')
                self.focus_certificate();return
            if not s.host or not s.ssh_port:
                self.nav.setCurrentIndex(0);self.server_card.setExpanded(True)
                target=self.inputs['host'] if not s.host else self.inputs['ssh_port'];target.setFocus()
                raise ValueError('请填写服务器地址和 SSH 端口')
            if action=='deploy':
                try:s.validate_panel_login()
                except ValueError:
                    self.nav.setCurrentIndex(0);self.ports_card.setExpanded(True)
                    (self.inputs['panel_user'] if not s.panel_user else self.inputs['panel_password']).setFocus()
                    raise
                required=['panel_port']+(['vless_port'] if s.vless else [])+(['hy2_port'] if s.hy2 else [])
                missing=next((key for key in required if not self.inputs[key].value()),None)
                if missing:
                    self.nav.setCurrentIndex(0);self.ports_card.setExpanded(True);self.inputs[missing].setFocus()
                    raise ValueError('请填写面板和已启用节点的端口，或点击随机图标生成')
            if action!='cloudflare' and not s.password and not s.private_key:raise ValueError('请在开始部署页输入 SSH 密码或私钥')
            if action=='deploy':s.validate()
            if action=='deploy' and (s.quota_gb or s.expiry or s.split_quota):
                if QMessageBox.question(self,'确认节点配额','目标服务器：'+self.target_text()+'\n\n'+self.limits.preview.text()+'\n\n将写入本次新建节点的客户端。已有节点请使用维护中的修改功能。',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
            if action=='deploy' and s.tls_mode=='domain' and not load_public('guide-progress-http',{}).get('6'):self.guide()
            worker=Worker(s,action,payload); self.active=worker; self.workers.append(worker)
            worker.log.connect(self.append_log); worker.progress.connect(self.update_progress); worker.verify.connect(self.verify_host)
            worker.result.connect(lambda r,a=action,w=worker:self.finished(a,r,w)); worker.failed.connect(self.failure)
            worker.cancelled.connect(self.connection_cancelled)
            worker.finished.connect(lambda w=worker:self.release_worker(w))
            names={'deploy':'一键部署','inspect':'SSH 连接检查','cloudflare':'域名解析检查','open':'打开管理面板','test':'节点连通性测试','sync':'同步节点端口','diagnose':'服务器诊断','backup':'创建备份','restore_bbr':'恢复 BBR 参数','apply_certificate':'应用域名证书','verify_bbr':'验证 BBRv3 状态','reboot_bbr':'重启服务器'}
            names.update({'overview':'刷新服务器状态','current_bbr':'查看当前 BBR','native_bbr':'启用内核 BBR','install_bbr':'安装 BBRv3','clients':'读取节点用户','change_client':'修改节点用户','service_logs':'读取服务日志','restart_core':'重启核心','restart_panel':'重启面板','reboot':'重启服务器','certificate_status':'查看证书','renew_certificate':'更新证书','backups':'读取备份列表','download_backup':'下载加密备份','import_backup':'恢复加密备份','cleanup_preview':'预览缓存','cleanup':'清理缓存','clean_old_logs':'清理旧日志'})
            names['change_panel_login']='修改面板账号密码'
            names.update(security_status='查看防爆破统计',security_apply='启用 SSH 防爆破',security_disable='停用 SSH 防爆破',security_unban='解除 SSH 封禁',security_restore='恢复防爆破规则',resume_deploy='继续未完成部署',network_diagnosis='限量测速与重传诊断')
            names.update(configure_public_panel='配置公网 HTTPS 面板',disable_public_panel='关闭公网面板',renew_public_panel_certificate='更新公网面板证书')
            if action.startswith('security_') and payload:
                name='3x-ui 面板' if payload.get('scope')=='panel' else 'SSH'
                names.update(security_apply='启用 '+name+' 防爆破',security_disable='停用 '+name+' 防爆破',security_unban='解除 '+name+' 封禁',security_status='查看 '+name+' 防护统计',security_restore='恢复 '+name+' 防护规则')
            self.action_name=names.get(action,'恢复备份');self.started_at=time.monotonic();self.elapsed.setText('00:00');self.timer.start()
            self.progress.setRange(0,100 if action=='deploy' else 0);self.progress.setValue(0)
            self.append_log('开始'+self.action_name+' · 服务器 '+s.host+' · SSH '+str(s.ssh_port))
            self.state.setText('执行中 · '+self.action_name); self.set_busy(True); worker.start()
        except Exception as ex:QMessageBox.warning(self,'请检查设置',str(ex))
    def verify_host(self,host,fp,reply):
        try:
            dialog=HostIdentityDialog(self,host,fp,reply.get('previous',''))
            reply['accepted']=dialog.exec()==QDialog.Accepted
        finally:reply['event'].set()
    def connection_cancelled(self,text):
        self.tick();self.timer.stop();self.progress.setRange(0,100);self.set_busy(False)
        self.state.setText('已取消连接');self.append_log(text)
    def update_progress(self,p,text):
        self.progress.setRange(0,100);self.progress.setValue(p);self.state.setText(f'{p}% · {text}');self.append_log(text)
    def failure(self,text):
        self.tick();self.timer.stop();self.progress.setRange(0,100);self.set_busy(False); self.state.setText('操作未完成 · 查看下方实时输出'); self.append_log(text); QMessageBox.warning(self,'操作未完成',text[-1600:])
    def finished(self,action,result,worker):
        self.tick();self.timer.stop();self.progress.setRange(0,100);self.progress.setValue(100);self.set_busy(False); self.state.setText('操作完成');self.append_log(getattr(self,'action_name','操作')+'已完成')
        if action!='cloudflare':
            remember_server(worker.settings)
            if action in ('deploy','inspect'):save_server_limits(worker.settings)
            self.maintenance_target.setText('目标服务器：'+self.target_text()+' · 最近连接 '+datetime.now().strftime('%H:%M'))
        if action.startswith('security_'):
            self.render_security(result)
        elif action in ('deploy','resume_deploy','sync','apply_certificate','verify_bbr','install_bbr','renew_certificate','import_backup','change_panel_login','configure_public_panel','disable_public_panel','renew_public_panel_certificate') or action.startswith('restore:'):
            self.record=result; self.show_record(result); self.nav.setCurrentIndex(1)
            if action=='resume_deploy':
                for key,value in result['ports'].items():self.inputs[key+'_port'].setValue(value)
            if action in ('configure_public_panel','disable_public_panel'):
                self.inputs['panel_port'].setValue(result['ports']['panel'])
            if result.get('bbr_status'):
                self.render_bbr_status(result['bbr_status'])
            if action=='change_panel_login':
                self.inputs['panel_user'].setText(result['identity']['panel_user']);self.inputs['panel_password'].setText(result['identity']['panel_password'])
            if action in ('deploy','sync','apply_certificate','configure_public_panel','enable_automatic_panel'):self.security_group_notice()
            if action=='import_backup' or action.startswith('restore:'):
                checks=result.get('restore_test',{})
                if any(v.get('status')=='未通过' for v in checks.values()):
                    self.state.setText('配置已恢复 · 节点测试未全部通过')
                    QMessageBox.information(self,'请核对节点连接','配置与证书已恢复；部分节点未连通，请查看右侧日志并核对实际端口的云安全组规则。')
            status=result.get('bbrv3',{})
            if action in ('deploy','verify_bbr','install_bbr') and status:
                if status.get('active'):
                    self.append_log('已确认 byJoey BBRv3 生效：'+status['kernel']+'；实际队列：'+(status.get('actual_qdisc') or '未确认'))
                    if action=='verify_bbr':QMessageBox.information(self,'BBRv3 已生效','当前内核：'+status['kernel']+'\nBBR 模块版本：3\nTCP 算法：bbr\n实际队列：'+(status.get('actual_qdisc') or '未确认'))
                else:
                    self.state.setText('节点已配置 · BBRv3 尚未生效')
                    QMessageBox.information(self,'BBRv3 等待验证','当前内核：'+status['kernel']+'\n目标内核：'+status['target_kernel']+'\n\n请在“服务器维护”中重启服务器，稍后点击“验证 BBRv3 状态”。如果已经重启仍未生效，请从服务商控制台核对启动项。')
        elif action in ('clients','change_client'):
            self.render_clients(result);self.append_log('已读取 '+str(len(result))+' 个节点用户。')
        elif action=='backups':self.render_backups(result);self.append_log('已读取 '+str(len(result))+' 个备份。')
        elif action in ('current_bbr','native_bbr'):
            self.render_bbr_status(result)
        elif action=='cleanup_preview':
            text='\n'.join(x['path']+' · %.2f MB'%(x['size']/1024**2) for x in result)
            if result:QTimer.singleShot(0,lambda:self.confirm_action('cleanup','将删除以下安装缓存：\n'+text,result))
            else:self.append_log('没有可清理的安装缓存。')
        elif action=='open':
            if worker.keep:self.tunnels.append(worker.engine)
            self.record=result['record']; self.show_record(self.record); webbrowser.open(result['url'])
            if result.get('generated'):self.security_group_notice()
        elif action=='inspect':
            details=f"系统：{result['os'].splitlines()[0]}\n架构：{result['arch']}\n可用磁盘：{result['free_gb']} GB\nTCP 算法：{result['bbr']}\n已有面板：{'是' if result['panel_installed'] else '否'}"
            self.append_log(details);QMessageBox.information(self,'连接正常',details)
        elif action=='cloudflare':QMessageBox.information(self,'域名解析检查通过',f"域名：{result['domain']}\n解析指向：{result['address']}\n与当前 VPS 匹配。\n证书签发还需云安全组和本机防火墙放行 TCP 80。")
        else:
            text=result if isinstance(result,str) else json.dumps(result,ensure_ascii=False,indent=2)
            self.append_log(text)
            if action=='test' and any(item.get('status')=='未通过' for item in result.values()):self.state.setText('节点测试未通过 · 查看下方输出')
            if action=='backup':QMessageBox.information(self,'备份完成','服务器备份位置：\n'+text)
            if action=='reboot_bbr':self.state.setText('服务器正在重启 · 稍后验证 BBRv3');QMessageBox.information(self,'已安排重启',text)
    def render_bbr_status(self,result):
        quic='；'.join(str(x['node'])+'：'+str(x['congestion']).upper() for x in result.get('hy2',[])) or '没有读取到 HY2 配置'
        self.bbr_summary.setText(result['label']+'\nBBR 版本：'+('BBRv'+result['bbr_version'] if result.get('bbr_version') else '未确认')+'\n识别依据：'+result.get('version_evidence','未读取')+'\n运行内核：'+result['kernel']+'\nTCP：'+result['algorithm']+' · 默认队列：'+result['qdisc']+'\n实际网卡：'+(result.get('interface') or '未读取')+' · 实际队列：'+(result.get('actual_qdisc') or '未确认')+'\n指定 byJoey 内核：'+result.get('target_kernel','未读取')+'\n指定版本已安装：'+('是' if result.get('installed') else '否')+'；此版本待重启：'+('是' if result.get('reboot_required') else '否')+('\n其他版本需另行核对；当前生效版本以运行内核检查为准。' if not result.get('installed') else '')+'\nHY2 QUIC：'+quic)
    def show_record(self,r):
        ports=r['ports']; self.summary.setText(r['settings']['host']+' · 已部署 · 3x-ui v3.9.0  |  TCP '+r.get('bbr','待检查')+'\n'+ '   ·   '.join(k.upper()+': '+str(v) for k,v in ports.items()))
        if r.get('bbrv3'):self.summary.setText(self.summary.text()+'\nbyJoey BBRv3：'+('已验证生效' if r['bbrv3'].get('active') else '尚未生效，请重启后验证'))
        self.linkbox.setPlainText('\n'.join(r.get('links',{}).values()))
        url=public_url(r);self.public_link.setText(url)
        note=('此链接可在其他电脑登录，关闭软件也能访问；请放行面板 TCP 端口。'+(' IP 使用 HTTP，浏览器登录信息不加密；配置域名证书可使用 HTTPS。' if url.startswith('http://') else '')) if url else '点击“打开面板”自动生成可跨电脑访问的链接。'
        self.result_user.setText(r['identity']['panel_user']);self.result_password.setText(r['identity']['panel_password'])
        self.credentials.setText(note)
        rules=r.get('rules',[]); self.table.setRowCount(len(rules))
        for i,rule in enumerate(rules):
            for j,key in enumerate(('service','port','protocol','source')):self.table.setItem(i,j,QTableWidgetItem(str(rule[key])))
        self.table.resizeColumnsToContents()
    def copy_rules(self):
        if self.record:QApplication.clipboard().setText('\n'.join(f"{r['service']}：{r['protocol']} {r['port']}，入站来源 {r['source']}" for r in self.record.get('rules',[])))
    def security_group_notice(self):
        if not self.record:return
        dialog=QDialog(self);dialog.setWindowTitle('下一步：放行 RakSmart 云安全组');dialog.resize(640,460)
        layout=QVBoxLayout(dialog);layout.setContentsMargins(26,24,26,24);layout.setSpacing(16)
        layout.addWidget(label('服务器已配置，请核对云安全组','section'))
        layout.addWidget(label('服务器本机防火墙与 RakSmart 云安全组是两层。SSH 只能配置本机规则；云安全组需要在服务商后台保存并绑定到这台 VPS。','subtitle'))
        rules='\n'.join(f"入站 {r['protocol']}  {r['port']}  ·  {r['service']}\n来源 {r['source']}，最小和最大端口都填 {r['port']}" for r in self.record.get('rules',[]))
        layout.addWidget(label(rules))
        ssh_port=self.record.get('settings',{}).get('ssh_port',self.settings(False).ssh_port)
        note='公网面板还需放行上方管理面板 TCP 端口；Cloudflare 解析使用仅 DNS（灰云）。' if public_url(self.record) else '面板使用 SSH 隧道，不需要开放面板公网端口。'
        layout.addWidget(label(f"保留 SSH TCP {ssh_port} 规则。\n"+note,'subtitle'))
        layout.addWidget(label('完成后点击“测试两种节点”，通过测试后再导入 v2rayN。','subtitle'))
        row=QHBoxLayout();row.addWidget(button('复制放行清单',self.copy_rules));row.addWidget(button('打开详细教程',self.guide));layout.addLayout(row)
        layout.addWidget(button('我知道了，查看节点',dialog.accept,True));dialog.exec()
    def export(self):
        if not self.record:return
        path,_=QFileDialog.getSaveFileName(self,'导出节点链接','NodePilot-nodes.txt','文本文件 (*.txt)')
        if path:Path(path).write_text(self.linkbox.toPlainText(),encoding='utf-8')
    def qr(self):
        if not self.record:return
        dialog=QDialog(self); dialog.setWindowTitle('导入 v2rayN'); layout=QHBoxLayout(dialog)
        for name,link in self.record.get('links',{}).items():
            col=QVBoxLayout(); col.addWidget(label(name,'section')); data=io.BytesIO(); qrcode.make(link).save(data,format='PNG'); pix=QPixmap(); pix.loadFromData(data.getvalue()); image=QLabel(); image.setPixmap(pix.scaled(280,280,Qt.KeepAspectRatio,Qt.SmoothTransformation)); col.addWidget(image); layout.addLayout(col)
        dialog.exec()
    def restore_dialog(self):
        from PySide6.QtWidgets import QInputDialog
        name,ok=QInputDialog.getText(self,'恢复备份','输入备份时间编号，例如 20261008-103000：')
        if ok and name:self.confirm_action('restore:'+name,f'将恢复 {name} 的数据库、证书和续期配置。恢复前创建当前完整备份，期间节点会中断。')
    def reboot_bbr_dialog(self):
        if self.active and self.active.isRunning():
            QMessageBox.information(self,'任务进行中','请等待当前任务结束。');return
        self.confirm_action('reboot_bbr','重启会短暂中断 SSH、管理面板和节点。重启后请刷新当前 BBR 状态；必要时可通过服务商控制台选择旧内核启动。')
    def closeEvent(self,event):
        if getattr(self,'bbr_dialog',None) is not None and self.bbr_dialog.running():
            event.ignore();return
        if self.active and self.active.isRunning():
            QMessageBox.information(self,'任务进行中','请等待当前操作结束后再关闭。服务器安装任务可在连接断开后继续运行。'); event.ignore(); return
        for engine in self.tunnels:engine.close()
        self.save_limit_reference()
        event.accept()

def main():
    app=QApplication([]); configure(app)
    window=Window(); window.show()
    import os
    if not os.environ.get('NODEPILOT_SMOKE_TEST'):QTimer.singleShot(0,window.system_notice)
    if os.environ.get('NODEPILOT_SMOKE_TEST'):
        def smoke():
            from .engine import ASSETS,INSTALL_HASH
            import hashlib
            assert hashlib.sha256((ASSETS/'official-install.sh').read_bytes()).hexdigest()==INSTALL_HASH
            assert (ASSETS/'core'/'xray.exe').exists()
            def confirm_startup():
                dialog=next(w for w in app.topLevelWidgets() if isinstance(w,QDialog) and w.objectName()=='systemPrompt' and w.isVisible())
                dialog.grab().save(str(Path(os.environ['NODEPILOT_SMOKE_TEST']).with_suffix('.startup.png')))
                next(b for b in dialog.findChildren(QPushButton) if b.text()=='已确认，继续').click()
            QTimer.singleShot(150,confirm_startup)
            assert window.system_notice()
            window.grab().save(os.environ['NODEPILOT_SMOKE_TEST'])
            if os.environ.get('NODEPILOT_SMOKE_BBR'):
                from .bbr_ui import BbrDialog
                from .bbr_interactive import script_bytes
                assert script_bytes()
                dialog=BbrDialog(window,Settings(host='192.0.2.1',ssh_port=22))
                assert dialog.choices.count()==12 and not dialog.input.isEnabled()
                dialog.choices.setCurrentRow(1)
                assert dialog.input.text()=='2'
                dialog.ready();dialog.append_output('请选择一个操作 (1-12)：')
                assert dialog.input.isEnabled()
                dialog.show();app.processEvents()
                dialog.grab().save(str(Path(os.environ['NODEPILOT_SMOKE_TEST']).with_suffix('.bbr.png')))
                dialog.ended(0,'脚本已退出')
                assert not dialog.input.isEnabled()
                dialog.reject()
            if os.environ.get('NODEPILOT_SMOKE_SECURITY'):
                window.nav.setCurrentIndex(2);window.security_card.setExpanded(True)
                window.render_security({'scope':'ssh','jail':'sshd','enabled':True,'installed':True,'managed':False,
                    'totals':{'total_failed':91,'total_banned':17,'currently_failed':15},
                    'metrics':{'failed_ips':3,'failures':31,'bans':4,'currently_banned':2},
                    'rows':[{'ip':'198.51.100.2','failures':12,'bans':2,'last':0,'banned':True},
                            {'ip':'2001:db8::7','failures':19,'bans':2,'last':0,'banned':True}],
                    'policy':{},'collector':'未安装（刷新时读取已有日志）',
                    'note':'已识别手动 sshd；累计计数与 FinalShell 的 status 命令一致。'})
                assert '91' in window.security_totals.text() and window.security_action_payload()['jail']=='sshd'
                app.processEvents()
                scroll=window.stack.widget(2);scroll.ensureWidgetVisible(window.security_totals,0,150)
                scroll.horizontalScrollBar().setValue(0)
                app.processEvents()
                window.grab().save(str(Path(os.environ['NODEPILOT_SMOKE_TEST']).with_suffix('.security.png')))
            app.quit()
        QTimer.singleShot(300,smoke)
    app.exec()

def configure(app):
    import os
    fonts=Path(os.environ.get('WINDIR','C:/Windows'))/'Fonts'
    for name in ('segoeui.ttf','msyh.ttc'):
        if (fonts/name).exists():QFontDatabase.addApplicationFont(str(fonts/name))
    app.setStyle('Fusion')
    saved=load_public('appearance',{})
    apply_theme(app,saved.get('mode','light') if isinstance(saved,dict) else 'light')
    app.setWindowIcon(QIcon(str(ASSETS/'branding/nodepilot.ico')))
    app.setFont(QFont('Microsoft YaHei UI',10))
