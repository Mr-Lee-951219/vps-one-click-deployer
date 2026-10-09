"""One collapsible maintenance card for protection and its nested statistics."""
import json
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (QLabel,QLineEdit,QPlainTextEdit,QVBoxLayout,QHBoxLayout,QFormLayout,
    QComboBox,QCheckBox,QPushButton,QTableWidget,QTableWidgetItem,QAbstractItemView,QMessageBox,QFileDialog)
from .widgets import CollapsibleCard
from .security import validate_policy
from .maintenance import BEIJING


def text(value):
    label=QLabel(value);label.setWordWrap(True);label.setObjectName('subtitle');return label


def action(label, callback):
    button=QPushButton(label);button.setCursor(Qt.PointingHandCursor);button.clicked.connect(callback);return button


class SecurityUi:
    def build_security(self, page):
        self.security_card=CollapsibleCard('防爆破','SSH 与 3x-ui 面板独立防护、独立统计。只封禁所选服务的实际端口；当前管理来源自动加入白名单。关闭软件后仍继续防护。')
        page.addWidget(self.security_card);area=self.security_card.area
        self.security_data={};self.security_rows=[]
        self.security_scope=QComboBox();self.security_scope.addItem('SSH 登录','ssh');self.security_scope.addItem('3x-ui 面板登录','panel')
        scope_form=QFormLayout();scope_form.addRow('防护对象',self.security_scope);area.addLayout(scope_form)
        self.security_scope.currentIndexChanged.connect(self.change_security_scope)
        self.security_jail=QComboBox()
        self.security_jail.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon);self.security_jail.setMinimumContentsLength(12)
        for label,value in [('自动识别（优先 sshd）','auto'),('sshd · 通用 / 手动规则','sshd'),('nodepilot-sshd · 旧版软件规则','nodepilot-sshd')]:self.security_jail.addItem(label,value)
        self.security_jail_form=QFormLayout();self.security_jail_form.setRowWrapPolicy(QFormLayout.WrapLongRows);self.security_jail_form.addRow('SSH 防护规则',self.security_jail);area.addLayout(self.security_jail_form)
        self.security_jail.currentIndexChanged.connect(self.change_security_jail)
        self.security_summary=text('尚未读取防护状态');area.addWidget(self.security_summary)
        self.security_retry=QLineEdit('5');self.security_retry.setValidator(QIntValidator(2,30))
        self.security_window=QLineEdit('10');self.security_window.setValidator(QIntValidator(1,1440))
        self.security_bantime=QComboBox()
        for label,seconds in [('15 分钟',900),('1 小时',3600),('24 小时',86400),('7 天',604800),('30 天',2592000),('永久（手动解封）',-1)]:self.security_bantime.addItem(label,seconds)
        self.security_bantime.setCurrentIndex(1)
        form=QFormLayout();form.setRowWrapPolicy(QFormLayout.WrapLongRows);form.addRow('失败次数阈值',self.security_retry);form.addRow('观察时间（分钟）',self.security_window);form.addRow('首次封禁时长',self.security_bantime);area.addLayout(form)
        self.security_increment=QCheckBox('重复尝试延长封禁');self.security_increment.setChecked(True);area.addWidget(self.security_increment)
        area.addWidget(text('默认按 1 小时 → 24 小时 → 7 天递增；修改首次时长后，后续时长按倍数计算。'))
        self.security_whitelist=QPlainTextEdit();self.security_whitelist.setMaximumHeight(76);self.security_whitelist.setPlaceholderText('可选白名单：每行一个 IP 或网段，例如 203.0.113.8/32');area.addWidget(self.security_whitelist)
        self.security_apply_button=action('启用 / 更新 SSH 防爆破',self.apply_security_dialog);area.addWidget(self.security_apply_button)
        row=QHBoxLayout();self.security_disable_button=action('停用 SSH 防爆破',lambda:self.confirm_action('security_disable','停用当前所选 '+self.security_label()+' 规则并解除其封禁；sshd 包括手动配置的同名规则。另一项防护和历史统计保留。',self.security_action_payload()));row.addWidget(self.security_disable_button);row.addWidget(action('恢复上一次规则',lambda:self.confirm_action('security_restore','恢复当前规则上一次由软件保存的设置，当前管理来源仍加入白名单。',self.security_action_payload())));area.addLayout(row)
        area.addWidget(text('面板 HTTPS：申请域名证书保护登录信息传输。它不替代 SSH 封禁，也不改变节点线路。'))
        area.addWidget(action('配置现有面板 HTTPS',self.security_https))
        area.addWidget(text('面板防护用于直接访问 VPS 面板端口，支持 HTTP / HTTPS。反向代理或橙云入口需单独适配；修改面板端口后请重新启用 / 更新面板规则。若 SSH 被封，可从服务商控制台解封；面板被封可通过 SSH 解封。'))
        title=QLabel('查看统计项');title.setObjectName('section');area.addWidget(title)
        self.security_range=QComboBox()
        for label,days in [('今天（北京时间）',1),('最近 7 天',7),('最近 30 天',30),('最近 90 天',90)]:self.security_range.addItem(label,days)
        area.addWidget(self.security_range)
        row=QHBoxLayout();row.addWidget(action('刷新防护与统计',lambda:self.start('security_status',self.security_payload())));row.addWidget(action('导出统计',self.export_security));area.addLayout(row)
        self.security_auto=QCheckBox('每 30 秒自动刷新');self.security_auto.setToolTip('仅在当前防爆破页面展开且没有其他任务时刷新');area.addWidget(self.security_auto)
        self.security_totals=text('Fail2ban 累计计数（与 status 命令一致）：刷新后显示');area.addWidget(self.security_totals)
        self.security_metrics=text('所选时间段登录失败 IP：—\n所选时间段失败次数：—\n当前封禁 IP：—\n所选时间段封禁次数：—');area.addWidget(self.security_metrics)
        self.security_table=QTableWidget(0,5);self.security_table.setHorizontalHeaderLabels(['IP','失败次数','封禁次数','最近时间（北京）','状态'])
        self.security_table.setSelectionBehavior(QAbstractItemView.SelectRows);self.security_table.setSelectionMode(QAbstractItemView.SingleSelection);self.security_table.setEditTriggers(QAbstractItemView.NoEditTriggers);self.security_table.setMinimumHeight(170);self.security_table.horizontalHeader().setStretchLastSection(True);area.addWidget(self.security_table)
        self.security_unban_button=action('解除所选 IP 的 SSH 封禁',self.unban_security_dialog);area.addWidget(self.security_unban_button)
        self.security_times=text('封禁与解封时间：刷新后显示');area.addWidget(self.security_times)
        self.security_timer=QTimer(self);self.security_timer.setInterval(30000);self.security_timer.timeout.connect(self.refresh_security_if_visible);self.security_timer.start()

    def security_payload(self):
        return {'endpoint':self.target_text(),'scope':self.security_scope.currentData(),'days':self.security_range.currentData(),
                'jail':self.security_jail.currentData() if self.security_scope.currentData()=='ssh' else 'nodepilot-panel'}

    def security_action_payload(self):
        payload=self.security_payload()
        if payload['jail']=='auto' and self.security_data.get('jail'):
            payload['jail']=self.security_data['jail']
        return payload

    def change_security_jail(self):
        self.security_data={};self.security_rows=[];self.security_table.setRowCount(0)
        self.security_summary.setText('请刷新当前规则的防护状态')
        self.security_totals.setText('Fail2ban 累计计数：刷新后显示')
        self.security_metrics.setText('所选时间段统计：刷新后显示')
        self.security_times.setText('封禁与解封时间：刷新后显示')

    def security_label(self):
        return '3x-ui 面板' if self.security_scope.currentData()=='panel' else 'SSH'

    def change_security_scope(self):
        name=self.security_label()
        self.security_apply_button.setText('启用 / 更新 '+name+' 防爆破')
        self.security_disable_button.setText('停用 '+name+' 防爆破')
        self.security_unban_button.setText('解除所选 IP 的 '+name+' 封禁')
        self.security_data={};self.security_rows=[];self.security_table.setRowCount(0)
        self.security_jail.setVisible(self.security_scope.currentData()=='ssh')
        self.security_jail_form.labelForField(self.security_jail).setVisible(self.security_scope.currentData()=='ssh')
        self.security_totals.setText('Fail2ban 累计计数：刷新后显示')
        self.security_summary.setText('尚未读取当前服务器的 '+name+' 防护状态')
        self.security_metrics.setText('请刷新 '+name+' 的统计')
        self.security_times.setText('封禁与解封时间：刷新后显示')
        self.security_retry.setText('5');self.security_window.setText('10');self.security_bantime.setCurrentIndex(1)
        self.security_increment.setChecked(True);self.security_whitelist.clear()

    def apply_security_dialog(self):
        try:
            payload={**self.security_action_payload(),'maxretry':int(self.security_retry.text()),'findtime':int(self.security_window.text())*60,
                     'bantime':self.security_bantime.currentData(),'increment':self.security_increment.isChecked(),
                     'whitelist':[x.strip() for x in self.security_whitelist.toPlainText().splitlines() if x.strip()]}
            policy=validate_policy(payload)
            length='永久，需手动解封' if policy['bantime']==-1 else str(policy['bantime']//60)+' 分钟'
            self.confirm_action('security_apply','将在服务器安装 / 配置 '+self.security_label()+' 的 Fail2ban 规则。\n%d 分钟内失败 %d 次后封禁，首次时长：%s。\n新服务器使用通用 sshd；已有旧版规则继续使用原名称。更新 sshd 会调整同名手动规则的有效配置，原手动文件保留。\n只保护所选服务的实际端口，另一项防护不变；当前管理 IP 自动加入白名单。'%(policy['findtime']//60,policy['maxretry'],length),payload)
        except (ValueError,TypeError) as ex:QMessageBox.warning(self,'请检查防护规则',str(ex))

    def security_https(self):
        self.focus_certificate();self.tls.setCurrentIndex(self.tls.findData('domain'));self.inputs['domain'].setFocus()

    def refresh_security_if_visible(self):
        if not self.security_auto.isChecked() or not self.security_card.isExpanded() or self.nav.currentIndex()!=2:return
        if self.active and self.active.isRunning():return
        if not self.security_data.get('installed'):return
        self.start('security_status',self.security_payload())

    def render_security(self, result):
        if result.get('scope','ssh')!=self.security_scope.currentData():return
        if self.security_scope.currentData()=='ssh' and self.security_jail.currentData()!='auto' and result.get('jail',self.security_jail.currentData())!=self.security_jail.currentData():return
        self.security_data=result;self.security_rows=result.get('rows',[])
        policy=result.get('policy',{})
        management='；管理白名单：'+policy['management_ip'] if policy.get('management_ip') else ''
        name=self.security_label()
        state=name+' 防护状态读取失败' if result.get('state_error') else (name+' 防爆破已启用' if result.get('enabled') else name+' 防爆破未启用')
        if result.get('target_error'):state=name+' 防护规则需检查或更新'
        if policy.get('port'):state+=' · TCP '+str(policy['port'])
        if result.get('action_error'):state='封禁动作异常 · 请重新启用 / 更新防护'
        if result.get('jail'):state+=' · '+result['jail']
        if len(result.get('available_jails',[]))>1:state+='\n检测到两套 SSH 规则，可切换规则分别查看；统计不合并。'
        self.security_summary.setText(state+management+'\n'+result.get('note',''))
        metrics=result.get('metrics',{})
        metrics={key:('未确认' if value is None else value) for key,value in metrics.items()}
        totals=result.get('totals',{})
        value=lambda key:'未确认' if totals.get(key) is None else str(totals[key])
        self.security_totals.setText('Fail2ban 累计计数（与 status 命令一致）：\n累计失败次数：'+value('total_failed')+'\n当前待处理失败：'+value('currently_failed')+'\n累计封禁次数：'+value('total_banned'))
        self.security_metrics.setText('所选时间段登录失败 IP：%s\n所选时间段失败次数：%s\n当前封禁 IP：%s\n所选时间段封禁次数：%s'%(metrics.get('failed_ips','—'),metrics.get('failures','—'),metrics.get('currently_banned','—'),metrics.get('bans','—')))
        if result.get('partial'):self.security_metrics.setText(self.security_metrics.text()+'\n日志过大：本次按天数据仅含已读取记录。累计计数不受影响。')
        self.security_table.setRowCount(len(self.security_rows))
        for n,row in enumerate(self.security_rows):
            recent=datetime.fromtimestamp(row['last'],BEIJING).strftime('%m-%d %H:%M') if row['last'] else '所选时间段无记录'
            status='未确认' if row['banned'] is None else ('已封禁' if row['banned'] else '未封禁')
            for col,cell in enumerate((row['ip'],str(row['failures']),str(row['bans']),recent,status)):self.security_table.setItem(n,col,QTableWidgetItem(cell))
        if self.security_rows:self.security_table.selectRow(0)
        self.security_times.setText('实际封禁时间（服务器时间，含解封时间）：\n'+(result.get('ban_times') or '当前没有封禁记录')+'\n统计采集：'+result.get('collector','未安装'))
        if policy:
            self.security_retry.setText(str(policy['maxretry']));self.security_window.setText(str(policy['findtime']//60))
            index=self.security_bantime.findData(policy['bantime'])
            if index<0:self.security_bantime.addItem(str(policy['bantime']//60)+' 分钟',policy['bantime']);index=self.security_bantime.count()-1
            self.security_bantime.setCurrentIndex(index);self.security_increment.setChecked(policy['increment']);self.security_whitelist.setPlainText('\n'.join(policy['whitelist']))

    def unban_security_dialog(self):
        row=self.security_table.currentRow()
        if not 0<=row<len(self.security_rows):QMessageBox.information(self,'先选择 IP','请刷新统计并选择一个被封禁的 IP。');return
        item=self.security_rows[row]
        if not item['banned']:QMessageBox.information(self,'IP 未被封禁','这个 IP 当前没有 '+self.security_label()+' 封禁。');return
        self.confirm_action('security_unban','解除 '+item['ip']+' 的当前 '+self.security_label()+' 规则封禁；再次违反规则仍可能被封禁。',{**self.security_action_payload(),'ip':item['ip']})

    def export_security(self):
        if not self.security_data:QMessageBox.information(self,'请先刷新','刷新防护与统计后再导出。');return
        path,_=QFileDialog.getSaveFileName(self,'导出防爆破统计','NodePilot-security-'+self.security_scope.currentData()+'.json','JSON (*.json)')
        if path:Path(path).write_text(json.dumps(self.security_data,ensure_ascii=False,indent=2),encoding='utf-8')
