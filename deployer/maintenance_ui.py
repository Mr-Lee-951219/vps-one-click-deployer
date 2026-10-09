"""Maintenance cards and per-server list, sharing the existing two-column layout."""
import json
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, QDateTime, Signal
from PySide6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QFormLayout,QLabel,QLineEdit,
    QCheckBox,QDateTimeEdit,QRadioButton,QButtonGroup,QDialog,QTableWidget,QTableWidgetItem,
    QAbstractItemView,QMessageBox,QFileDialog,QInputDialog,QPushButton)
from .models import Settings, validate_panel_login, random_panel_password
from .widgets import CollapsibleCard
from .maintenance import date_text, BEIJING
from .storage import saved_servers,save_public,forget_server,server_id,save_server_limits,LIMIT_KEYS,load_login_password,forget_login_password
from .portable_backup import unseal,validate_bundle
from .public_panel import public_url
from .widgets import PortEdit
from .security_ui import SecurityUi

def hint(text):
    label=QLabel(text);label.setWordWrap(True);label.setObjectName('subtitle');return label

def action_button(text,callback):
    b=QPushButton(text);b.setCursor(Qt.PointingHandCursor);b.clicked.connect(callback);return b

class LimitsEditor(QWidget):
    changed=Signal()
    def __init__(self,single=False):
        super().__init__()
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0);layout.setSpacing(12)
        layout.addWidget(hint('日期统一使用北京时间；流量按 3x-ui 的 GB 计算（1 GB = 1024³ 字节）。这是节点配额，不是服务商剩余流量。'))
        self.due_on=QCheckBox('记录 VPS 续费日期（仅供参考）')
        self.due=QDateTimeEdit();self.due.setDisplayFormat('yyyy-MM-dd HH:mm');self.due.setCalendarPopup(True)
        self.expiry_on=QCheckBox('设置节点到期时间')
        self.expiry=QDateTimeEdit();self.expiry.setDisplayFormat('yyyy-MM-dd HH:mm');self.expiry.setCalendarPopup(True)
        self.quota=QLineEdit('0');self.quota.setPlaceholderText('0 表示不限量')
        self.unit_gb=QRadioButton('GB');self.unit_tb=QRadioButton('TB');self.unit_gb.setChecked(True)
        self.unit_group=QButtonGroup(self);self.unit_group.addButton(self.unit_gb);self.unit_group.addButton(self.unit_tb)
        units=QHBoxLayout();units.addWidget(self.quota,1);units.addWidget(self.unit_gb);units.addWidget(self.unit_tb)
        self.split=QCheckBox('分别分配 VLESS / HY2 流量（GB）')
        self.vless=QLineEdit('0');self.hy2=QLineEdit('0');self.reset=QLineEdit();self.reset.setPlaceholderText('1–31；空白表示不记录')
        layout.addWidget(self.due_on);layout.addWidget(self.due);layout.addWidget(self.expiry_on);layout.addWidget(self.expiry)
        self.copy_button=action_button('用续费日期作为节点到期时间',self.copy_due);layout.addWidget(self.copy_button)
        form=QFormLayout();form.addRow('可分配总流量',units);layout.addLayout(form)
        layout.addWidget(self.split);self.split_fields=QWidget();form=QFormLayout(self.split_fields);form.setContentsMargins(0,0,0,0)
        form.addRow('VLESS 配额',self.vless);form.addRow('HY2 配额',self.hy2);layout.addWidget(self.split_fields)
        self.reset_widget=QWidget();form=QFormLayout(self.reset_widget);form.setContentsMargins(0,0,0,0);form.addRow('服务商重置日',self.reset);layout.addWidget(self.reset_widget)
        self.extra_hint=hint('重置日只作记录，不会自动清零节点流量。开启两种协议时默认平均分配总流量。');layout.addWidget(self.extra_hint)
        self.preview=hint('');layout.addWidget(self.preview)
        for edit in (self.quota,self.vless,self.hy2,self.reset):edit.textChanged.connect(self.refresh)
        for check in (self.due_on,self.expiry_on,self.split,self.unit_gb,self.unit_tb):check.toggled.connect(self.refresh)
        for edit in (self.due,self.expiry):edit.dateTimeChanged.connect(self.refresh)
        self.protocols=(True,True);self.set_values({})
        if single:
            for widget in (self.due_on,self.due,self.copy_button,self.split,self.reset_widget,self.extra_hint):widget.hide()

    def copy_due(self):
        if self.due_on.isChecked():self.expiry.setDateTime(self.due.dateTime());self.expiry_on.setChecked(True)
    def stamp(self,editor):
        # Read displayed components, never implicitly use the Windows local timezone.
        return int(datetime.strptime(editor.dateTime().toString('yyyy-MM-dd HH:mm'),' %Y-%m-%d %H:%M'.strip()).replace(tzinfo=BEIJING).timestamp()*1000)
    def read(self):
        def number(edit):return float(edit.text().strip() or 0)
        data={'server_due':self.stamp(self.due) if self.due_on.isChecked() else 0,
              'expiry':self.stamp(self.expiry) if self.expiry_on.isChecked() else 0,
              'quota_gb':number(self.quota)*(1024 if self.unit_tb.isChecked() else 1),
              'split_quota':self.split.isChecked(),'vless_quota_gb':number(self.vless),
              'hy2_quota_gb':number(self.hy2),'reset_day':int(self.reset.text().strip() or 0)}
        s=Settings(vless=self.protocols[0],hy2=self.protocols[1],**data);s.validate_limits()
        return data
    def set_values(self,data):
        for check,key in ((self.due_on,'server_due'),(self.expiry_on,'expiry')):
            check.setChecked(bool(data.get(key,0)))
        for edit,key in ((self.due,'server_due'),(self.expiry,'expiry')):
            value=data.get(key,0)
            if value:edit.setDateTime(QDateTime.fromString(date_text(value),'yyyy-MM-dd HH:mm'))
            else:edit.setDateTime(QDateTime.fromString(datetime.now(BEIJING).strftime('%Y-%m-%d %H:%M'),'yyyy-MM-dd HH:mm').addYears(1))
        self.unit_gb.setChecked(True)
        self.quota.setText(str(data.get('quota_gb',0)));self.vless.setText(str(data.get('vless_quota_gb',0)));self.hy2.setText(str(data.get('hy2_quota_gb',0)))
        self.split.setChecked(data.get('split_quota',False));self.reset.setText(str(data.get('reset_day',0) or ''));self.refresh()
    def refresh(self,*args):
        self.due.setEnabled(self.due_on.isChecked());self.expiry.setEnabled(self.expiry_on.isChecked())
        self.copy_button.setEnabled(self.due_on.isChecked())
        self.split_fields.setVisible(self.split.isChecked())
        try:
            data=self.read();s=Settings(vless=self.protocols[0],hy2=self.protocols[1],**data)
            parts=[]
            for key,on in zip(('vless','hy2'),self.protocols):
                if on:
                    quota=s.quota_bytes(key)
                    parts.append(key.upper()+'：'+('不限量' if not quota else '%.2f GB'%(quota/1024**3)))
            self.preview.setText(' · '.join(parts)+'\n节点到期：'+date_text(s.expiry))
        except (ValueError,OverflowError) as ex:self.preview.setText('请检查输入：'+str(ex))
        self.changed.emit()

class MaintenanceUi(SecurityUi):
    def build_manage(self):
        page=self.page()
        self.maintenance_target=hint('目标服务器：尚未选择');page.addWidget(self.maintenance_target)
        def section(title,description,actions):
            card=CollapsibleCard(title,description)
            for text,fn in actions:card.area.addWidget(action_button(text,fn))
            page.addWidget(card);return card
        self.overview_card=section('服务器概览','读取运行状态、资源、监听端口与后台任务。',[
            ('刷新服务器状态',lambda:self.start('overview')),('查看诊断与建议',lambda:self.start('diagnose')),
            ('查看后台安装任务',lambda:self.start('overview')),
            ('继续未完成部署',lambda:self.confirm_action('resume_deploy','将读取服务器原部署记录，沿用原协议、端口和节点身份，检查并继续未完成步骤。已完成部署不会重装。')),
            ('导出当前诊断日志',self.export_logs)])
        section('服务与日志','操作前会显示目标服务器；重启会中断相关连接。',[
            ('重启节点核心',lambda:self.confirm_action('restart_core','会短暂中断节点连接。')),
            ('重启 3x-ui 面板',lambda:self.confirm_action('restart_panel','面板和节点会短暂中断。')),
            ('重启服务器',lambda:self.confirm_action('reboot','所有 SSH、面板和节点连接会中断。')),
            ('查看最近服务日志',lambda:self.start('service_logs')),('打开管理面板',lambda:self.start('open'))])
        section('面板账号与密码','修改这台服务器的 3x-ui 首个管理员账号与密码；SSH 登录信息单独保存。',[
            ('修改面板账号与密码',self.edit_panel_login)])
        section('端口与网络','读取真实监听和防火墙规则；外部超时需进一步排查云安全组或网络。',[
            ('读取监听与防火墙',lambda:self.start('overview')),('测试现有节点',lambda:self.start('test')),
            ('限量测速与重传诊断',lambda:self.confirm_action('network_diagnosis','将比较本机直连、VPS 直连和现有节点。每项最多 4 MiB，双协议共最多 16 MiB；不会调整网络参数。')),
            ('同步面板端口与本机规则',lambda:self.start('sync')),('复制云安全组清单',self.copy_rules)])
        self.build_security(page)
        card=section('BBR 管理','TCP BBR 与 HY2 QUIC 分开显示。安装内核后需要重启，只有状态检查通过才标记生效。',[
            ('刷新当前 BBR 状态',lambda:self.start('current_bbr')),
            ('启用系统内核 BBR',lambda:self.confirm_action('native_bbr','会启用当前内核的 TCP BBR + FQ 并保存原参数。原版 Debian 12 的 6.1 内核为 BBRv1；不会更换运行内核。')),
            ('安装 / 管理 byJoey BBRv3',self.bbr_menu_dialog),
            ('重启以应用 BBRv3',self.reboot_bbr_dialog),
            ('恢复原 TCP 参数',lambda:self.confirm_action('restore_bbr','恢复部署前保存的算法与队列；不会卸载当前内核。'))])
        self.bbr_summary=hint('尚未读取当前 BBR 状态');card.area.insertWidget(1,self.bbr_summary)
        card=section('节点日期与流量','先读取面板真实数据；修改日期、配额、启用状态与清零流量分别执行。',[
            ('刷新节点用户',lambda:self.start('clients')),
            ('修改所选用户的日期与配额',self.edit_client),
            ('启用 / 停用所选用户',self.toggle_client),('重置所选用户流量',self.reset_client)])
        self.client_table=QTableWidget(0,4);self.client_table.setHorizontalHeaderLabels(['用户','已用 / 配额 GB','到期（北京）','状态'])
        self.client_table.setSelectionBehavior(QAbstractItemView.SelectRows);self.client_table.setSelectionMode(QAbstractItemView.SingleSelection);self.client_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.client_table.setMinimumHeight(180);self.client_table.horizontalHeader().setStretchLastSection(True);card.area.insertWidget(1,self.client_table);self.client_data=[]
        section('域名与证书','检查面板 / HY2 证书与续期任务；仅 VLESS 也能给现有面板配置 HTTPS。',[
            ('查看证书有效期与续期任务',lambda:self.start('certificate_status')),
            ('续期 / 更新当前证书',lambda:self.confirm_action('renew_certificate','域名证书会请求续期；自签证书会重新生成，原 HY2 链接的证书指纹失效，需要重新导入。')),
            ('设置访问域名',self.focus_certificate),
            ('给现有面板 / HY2 应用域名证书',lambda:self.start('apply_certificate'))])
        card=section('备份与恢复','完整备份包含数据库、证书与续期配置；下载时用独立密码加密，可在重装系统后恢复。',[
            ('创建完整服务器备份',lambda:self.start('backup')),('刷新服务器备份列表',lambda:self.start('backups')),
            ('下载所选备份（加密）',self.download_backup_dialog),('从本机加密备份恢复',self.import_backup_dialog),
            ('从服务器备份恢复',self.restore_dialog)])
        self.backup_table=QTableWidget(0,2);self.backup_table.setHorizontalHeaderLabels(['备份时间','大小 MB']);self.backup_table.setMinimumHeight(150)
        self.backup_table.setSelectionBehavior(QAbstractItemView.SelectRows);self.backup_table.setSelectionMode(QAbstractItemView.SingleSelection);self.backup_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.backup_table.horizontalHeader().setStretchLastSection(True);card.area.insertWidget(1,self.backup_table);self.backup_data=[]
        section('缓存与日志清理','安装缓存先预览再清理；旧日志清理范围为服务器系统日志，保留最近 14 天。',[
            ('预览安装缓存',lambda:self.start('cleanup_preview')),
            ('清理 14 天以前的系统日志',lambda:self.confirm_action('clean_old_logs','将清理这台服务器整个 systemd 日志库中超过 14 天的日志，不限于本软件；不能撤销。'))])
        page.addStretch()

    def target_text(self):
        return self.inputs['host'].text().strip()+':'+str(self.inputs['ssh_port'].value())
    def confirm_action(self,action,description,payload=None):
        if self.active and self.active.isRunning():return
        text='目标服务器：'+self.target_text()+'\n\n'+description
        if QMessageBox.question(self,'确认操作',text,QMessageBox.Yes|QMessageBox.No,QMessageBox.No)==QMessageBox.Yes:
            self.start(action,payload)

    def bbr_menu_dialog(self):
        if self.active and self.active.isRunning():
            QMessageBox.information(self,'任务进行中','请等待当前任务结束。');return
        try:
            settings=self.settings(False)
            if not settings.host or not settings.ssh_port:raise ValueError('请先填写服务器地址和 SSH 端口')
            if not settings.password and not settings.private_key:raise ValueError('请先填写 SSH 密码或选择已保存服务器')
            from .bbr_ui import BbrDialog
            self.bbr_dialog=BbrDialog(self,settings)
            self.bbr_dialog.exec()
            self.bbr_dialog.deleteLater();self.bbr_dialog=None
        except Exception as ex:QMessageBox.warning(self,'请检查连接信息',str(ex))

    def saved_servers_dialog(self):
        if self.active and self.active.isRunning():
            QMessageBox.information(self,'任务进行中','当前任务结束后再切换服务器。');return
        dialog=QDialog(self);dialog.setWindowTitle('已保存服务器');dialog.resize(740,440);layout=QVBoxLayout(dialog)
        layout.addWidget(hint('勾选“记住密码”后，连接成功会在本机加密保存。已保存密码的服务器可直接连接；删除记录同时清除保存的密码。'))
        table=QTableWidget(0,5);table.setHorizontalHeaderLabels(['名称','服务器地址','SSH 端口','密码','最近连接'])
        table.setSelectionBehavior(QAbstractItemView.SelectRows);table.setSelectionMode(QAbstractItemView.SingleSelection);table.setEditTriggers(QAbstractItemView.NoEditTriggers);table.horizontalHeader().setStretchLastSection(True);layout.addWidget(table)
        items=[]
        def refresh():
            items[:]=saved_servers();table.setRowCount(len(items))
            for row,item in enumerate(items):
                try:stored=bool(load_login_password(item['host'],item['ssh_port'],item.get('username','root')))
                except (OSError,ValueError,RuntimeError):stored=False
                values=(item.get('name','我的服务器'),item['host'],str(item['ssh_port']),'已加密保存' if stored else '未保存',datetime.fromtimestamp(item.get('last_connected',0)).strftime('%m-%d %H:%M'))
                for col,value in enumerate(values):table.setItem(row,col,QTableWidgetItem(value))
            if items:table.selectRow(0)
        def select():
            row=table.currentRow();return items[row] if 0<=row<len(items) else None
        def connect():
            item=select()
            if not item:return
            self.clear_connection()
            self.inputs['name'].setText(item.get('name','我的服务器'))
            self.inputs['host'].setText(item['host']);self.inputs['ssh_port'].setValue(item['ssh_port']);self.inputs['username'].setText(item.get('username','root'))
            self.load_server_record();self.limits.set_values(item.get('limits',{}))
            self.nav.setCurrentIndex(0);self.server_card.setExpanded(True);self.inputs['password'].setFocus()
            dialog.accept()
            if self.inputs['password'].text():
                self.append_log('已读取这台服务器本机加密保存的密码，正在连接。');self.start('inspect');return
            self.append_log('已选择 '+item['host']+'，请输入当前密码或私钥后连接。')
            password,ok=QInputDialog.getText(self,'连接服务器','服务器：'+self.target_text()+'\n当前 SSH 密码；勾选主界面“记住密码”后，连接成功会加密保存。',QLineEdit.Password)
            if ok and password:
                self.inputs['password'].setText(password);self.start('inspect')
        def remove():
            item=select()
            if item and QMessageBox.question(dialog,'删除服务器记录','删除 '+item['host']+':'+str(item['ssh_port'])+' 的列表记录和本机保存的登录密码？服务器配置会保留。',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)==QMessageBox.Yes:
                forget_server(item['id']);refresh()
        def forget_password():
            item=select()
            if not item:return
            forget_login_password(item['host'],item['ssh_port'])
            if self.target_text()==item['host']+':'+str(item['ssh_port']):
                self.inputs['password'].clear();self.inputs['remember_password'].setChecked(False)
            refresh()
        def rename():
            item=select()
            if not item:return
            value,ok=QInputDialog.getText(dialog,'修改名称','服务器名称',text=item.get('name',''))
            if ok and value.strip():
                item['name']=value.strip()[:80];save_public('servers',items);refresh()
        row=QHBoxLayout();row.addWidget(action_button('选择连接',connect));row.addWidget(action_button('修改名称',rename));row.addWidget(action_button('清除密码',forget_password));row.addWidget(action_button('删除',remove));row.addStretch();row.addWidget(action_button('关闭',dialog.reject));layout.addLayout(row)
        table.cellDoubleClicked.connect(lambda *_:connect());refresh();dialog.exec()

    def selected_client(self):
        row=self.client_table.currentRow()
        if not 0<=row<len(self.client_data):
            QMessageBox.information(self,'先选择用户','请刷新节点用户并选择一行。');return None
        return self.client_data[row]

    def copy_public_panel(self):
        url=public_url(self.record or {})
        if url:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(url);self.append_log('公网面板链接已复制。')
        else:QMessageBox.information(self,'尚无面板链接','部署后自动显示；已有服务器点击“打开面板”即可自动生成链接。')

    def edit_panel_login(self):
        if self.active and self.active.isRunning():return
        dialog=QDialog(self);dialog.setWindowTitle('修改 3x-ui 面板账号与密码');dialog.resize(510,270)
        layout=QVBoxLayout(dialog);target=self.target_text()
        layout.addWidget(hint('目标服务器：'+target+'\n账号手动填写；密码可以输入或随机生成。'))
        username=QLineEdit(self.record['identity']['panel_user'] if self.record else '')
        password=QLineEdit();password.setEchoMode(QLineEdit.Password)
        form=QFormLayout();form.addRow('面板账号',username)
        row=QHBoxLayout();row.addWidget(password,1)
        show=action_button('显示',lambda:toggle());row.addWidget(show)
        row.addWidget(action_button('随机',lambda:password.setText(random_panel_password())))
        def toggle():
            visible=password.echoMode()==QLineEdit.Password
            password.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password);show.setText('隐藏' if visible else '显示')
        form.addRow('新面板密码',row);layout.addLayout(form)
        def apply():
            try:validate_panel_login(username.text().strip(),password.text())
            except ValueError as ex:QMessageBox.warning(dialog,'请检查设置',str(ex));return
            if QMessageBox.question(dialog,'确认修改','目标服务器：'+target+'\n面板账号：'+username.text().strip()+'\n\n将修改管理员登录信息；下次打开面板请使用新账号密码。',QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
            dialog.accept();self.start('change_panel_login',{'endpoint':target,'username':username.text().strip(),'password':password.text()})
        buttons=QHBoxLayout();buttons.addWidget(action_button('取消',dialog.reject));buttons.addWidget(action_button('保存到服务器',apply));layout.addLayout(buttons);dialog.exec()
    def client_payload(self,row,mode,changes=None):
        return {'endpoint':self.target_text(),'inbound_id':row['inbound_id'],'email':row['email'],'before':{k:row[k] for k in ('total','expiry','enable')},'mode':mode,'changes':changes or {}}
    def edit_client(self):
        row=self.selected_client()
        if not row:return
        if row['expiry'] < 0:
            QMessageBox.information(self,'相对到期时间','该用户采用首次使用后到期的设置，请在 3x-ui 面板修改，避免把相对日期转换成固定日期。');return
        dialog=QDialog(self);dialog.setWindowTitle('修改日期与配额');dialog.resize(510,420);layout=QVBoxLayout(dialog)
        layout.addWidget(hint('目标：'+self.target_text()+'\n用户：'+row['email']+'\n已用：%.2f GB'%(row['used']/1024**3)))
        editor=LimitsEditor(single=True);editor.protocols=(True,False);editor.set_values({'quota_gb':row['total']/1024**3,'expiry':row['expiry']})
        # This dialog edits one client, not VPS reference data or protocol splits.
        editor.due_on.hide();editor.due.hide();editor.split.hide();editor.reset.hide()
        layout.addWidget(editor)
        def apply():
            try:
                data=editor.read();changes={'totalGB':int(data['quota_gb']*1024**3),'expiryTime':data['expiry']}
                note='用户：'+row['email']+'\n配额：%.2f → %.2f GB'%(row['total']/1024**3,changes['totalGB']/1024**3)+'\n到期：'+date_text(row['expiry'])+' → '+date_text(data['expiry'])+'\n已用流量保持，不会清零。'
                if changes['totalGB'] and changes['totalGB']<row['used']:note+='\n新配额低于已用流量，用户可能立即被停用。'
                if QMessageBox.question(dialog,'确认修改','服务器：'+self.target_text()+'\n'+note,QMessageBox.Yes|QMessageBox.No,QMessageBox.No)==QMessageBox.Yes:
                    dialog.accept();self.start('change_client',self.client_payload(row,'limits',changes))
            except ValueError as ex:QMessageBox.warning(dialog,'请检查输入',str(ex))
        layout.addWidget(action_button('预览并应用',apply));dialog.exec()
    def toggle_client(self):
        row=self.selected_client()
        if row:self.confirm_action('change_client',('停用' if row['enable'] else '启用')+'用户 '+row['email']+'；配额、日期与已用流量保持。',self.client_payload(row,'enable',{'enable':not row['enable']}))
    def reset_client(self):
        row=self.selected_client()
        if row:self.confirm_action('change_client','清零用户 '+row['email']+' 的已用流量，允许重新消耗配额；不能撤销。日期与总配额保持。',self.client_payload(row,'reset'))

    def render_clients(self,rows):
        self.client_data=rows;self.client_table.setRowCount(len(rows))
        for n,row in enumerate(rows):
            total='不限' if not row['total'] else '%.2f'%(row['total']/1024**3)
            state='停用' if not row['enable'] else '受限' if not row.get('effective_enable',True) else '启用'
            values=(row['remark']+' / '+row['email'],'%.2f / '%(row['used']/1024**3)+total,date_text(row['expiry']),state)
            for c,value in enumerate(values):self.client_table.setItem(n,c,QTableWidgetItem(value))
        if rows:self.client_table.selectRow(0)
    def render_backups(self,rows):
        self.backup_data=rows;self.backup_table.setRowCount(len(rows))
        for n,row in enumerate(rows):
            self.backup_table.setItem(n,0,QTableWidgetItem(row['id']));self.backup_table.setItem(n,1,QTableWidgetItem('%.2f'%(row['bytes']/1024**2)))
        if rows:self.backup_table.selectRow(0)
    def backup_password(self):
        value,ok=QInputDialog.getText(self,'备份密码','独立备份密码（至少 8 位，恢复时需要）',QLineEdit.Password)
        if not ok:return None
        if len(value)<8:QMessageBox.warning(self,'密码太短','请使用至少 8 位的备份密码。');return None
        return value
    def download_backup_dialog(self):
        row=self.backup_table.currentRow()
        if not 0<=row<len(self.backup_data):
            QMessageBox.information(self,'先选择备份','请刷新备份列表并选择一个备份。');return
        password=self.backup_password()
        if password is None:return
        confirm,ok=QInputDialog.getText(self,'确认备份密码','再次输入备份密码',QLineEdit.Password)
        if not ok:return
        if confirm!=password:QMessageBox.warning(self,'密码不一致','两次输入的密码不一致。');return
        path,_=QFileDialog.getSaveFileName(self,'下载加密备份','NodePilot-'+self.backup_data[row]['id']+'.npbackup','NodePilot 备份 (*.npbackup)')
        if path:self.start('download_backup',{'id':self.backup_data[row]['id'],'password':password,'path':path})
    def import_backup_dialog(self):
        path,_=QFileDialog.getOpenFileName(self,'选择加密备份','','NodePilot 备份 (*.npbackup)')
        if not path:return
        password=self.backup_password()
        if password is None:return
        try:
            bundle=unseal(Path(path).read_bytes(),password);record,_=validate_bundle(bundle)
            ports='、'.join(k+':'+str(v) for k,v in record['ports'].items())
            self.confirm_action('import_backup','将恢复备份 '+str(bundle.get('created',''))+'。\n原服务器：'+record['settings']['host']+'\n恢复端口：'+ports+'\n现有配置会先备份；恢复期间面板和节点中断。重装后的 Debian 12 也可使用。',{'path':path,'password':password})
        except Exception as ex:QMessageBox.warning(self,'无法读取备份',str(ex))

