"""Themed BBR menu with a real SSH terminal and a single-line reply box."""
import re
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (QApplication,QDialog,QFrame,QHBoxLayout,QLabel,QLineEdit,
    QListWidget,QMessageBox,QPlainTextEdit,QPushButton,QVBoxLayout)

from .bbr_interactive import BbrSession,MENU


def text(value, name=None):
    widget=QLabel(value);widget.setWordWrap(True)
    if name:widget.setObjectName(name)
    return widget


class BbrDialog(QDialog):
    def __init__(self,parent,settings):
        super().__init__(parent)
        self.settings=settings;self.worker=None;self.pending_cr=False;self.at_menu=False;self.prompt_tail='';self.connected=False
        self.setWindowTitle('byJoey BBR · 选择与交互')
        available=self.screen().availableGeometry()
        self.resize(min(1060,available.width()-60),min(780,available.height()-70))
        outer=QVBoxLayout(self);outer.setContentsMargins(24,22,24,22);outer.setSpacing(14)
        outer.addWidget(text('BBR 交互管理','brand'))
        outer.addWidget(text('目标服务器：'+settings.host+' · SSH '+str(settings.ssh_port),'subtitle'))
        outer.addWidget(text('点击左侧操作填入编号，再发送；后续版本编号、y/n 和默认回车，也在下方输入。','subtitle'))
        body=QHBoxLayout();body.setSpacing(16)
        choice=QFrame();choice.setObjectName('card');column=QVBoxLayout(choice);column.setContentsMargins(16,16,16,16)
        column.addWidget(text('选择操作','section'))
        self.choices=QListWidget();self.choices.setObjectName('bbrChoices');self.choices.setMinimumWidth(275)
        for number,title in enumerate(MENU,1):self.choices.addItem(str(number)+'. '+title)
        self.choices.currentRowChanged.connect(self.choose);column.addWidget(self.choices,1)
        column.addWidget(text('选项 1 / 2 可继续选择标准版或 Max，以及需要安装的版本。','subtitle'))
        body.addWidget(choice,2)
        terminal=QFrame();terminal.setObjectName('terminal');area=QVBoxLayout(terminal);area.setContentsMargins(10,12,10,10)
        header=QHBoxLayout();header.addWidget(text('实时脚本输出','section'),1)
        copy=QPushButton('复制');copy.clicked.connect(lambda:QApplication.clipboard().setText(self.console.toPlainText()));header.addWidget(copy);area.addLayout(header)
        self.console=QPlainTextEdit();self.console.setObjectName('liveLog');self.console.setReadOnly(True)
        self.console.setLineWrapMode(QPlainTextEdit.WidgetWidth);self.console.document().setMaximumBlockCount(10000)
        self.console.setAccessibleName('byJoey 脚本实时输出');area.addWidget(self.console,1);body.addWidget(terminal,3);outer.addLayout(body,1)
        self.status=text('尚未连接 · 打开菜单后按脚本提示操作','subtitle');outer.addWidget(self.status)
        self.input=QLineEdit();self.input.setObjectName('bbrReply');self.input.setMaxLength(1024)
        self.input.setPlaceholderText('输入操作 / 版本编号或 y/n；留空发送 = 直接回车')
        self.input.setAccessibleName('脚本回答输入框');self.input.returnPressed.connect(self.send)
        row=QHBoxLayout();row.addWidget(text('输入回答'));row.addWidget(self.input,1)
        self.send_button=QPushButton('发送 / 回车');self.send_button.setObjectName('primary');self.send_button.clicked.connect(self.send)
        self.send_button.setDefault(True);row.addWidget(self.send_button);outer.addLayout(row)
        outer.addWidget(text('打开 byJoey 菜单会安装缺少的依赖、创建 b 快捷命令并写入安全模块黑名单。安装内核、卸载、调优和重启按你的选择执行。','subtitle'))
        footer=QHBoxLayout()
        self.connect_button=QPushButton('连接并打开菜单');self.connect_button.clicked.connect(self.connect_session)
        self.stop_button=QPushButton('中断脚本');self.stop_button.clicked.connect(self.interrupt)
        self.close_button=QPushButton('返回维护页');self.close_button.clicked.connect(self.reject)
        for button in (self.connect_button,self.stop_button,self.close_button):
            button.setAutoDefault(False);button.setCursor(Qt.PointingHandCursor)
        footer.addWidget(self.connect_button);footer.addWidget(self.stop_button);footer.addStretch();footer.addWidget(self.close_button);outer.addLayout(footer)
        self.set_inputs(False);self.stop_button.setEnabled(False)

    def running(self):return self.worker is not None and self.worker.isRunning()

    def set_inputs(self,enabled):
        self.input.setEnabled(enabled);self.send_button.setEnabled(enabled)

    def choose(self,row):
        if row>=0:self.input.setText(str(row+1));self.input.setFocus()

    def connect_session(self):
        if self.running():return
        self.console.clear();self.pending_cr=False;self.at_menu=False;self.prompt_tail='';self.connected=False
        self.connect_button.setEnabled(False);self.close_button.setEnabled(False);self.stop_button.setEnabled(True)
        self.set_inputs(False);self.status.setText('正在连接服务器并核对脚本…')
        # Worker clears its own password after completion; keep the form snapshot reusable.
        from dataclasses import replace
        self.worker=BbrSession(replace(self.settings),self)
        self.worker.verify.connect(self.parent().verify_host)
        self.worker.output.connect(self.append_output);self.worker.ready.connect(self.ready)
        self.worker.ended.connect(self.ended);self.worker.finished.connect(self.session_finished)
        self.worker.start()

    def ready(self):
        self.connected=True;self.status.setText('SSH 已连接 · 正在打开脚本菜单…')

    def send(self):
        value=self.input.text()
        if not self.worker:return
        if self.at_menu and value.strip() in ('9','11','12'):
            notes={'9':'将卸载 byJoey 内核，可能包括当前运行内核。请先确认原版内核能够启动。',
                   '11':'将清除 byJoey 脚本写入的网络优化配置。',
                   '12':'将执行极限测速模式，修改网络参数，并可能运行消耗较多流量的测速。'}
            if QMessageBox.question(self,'确认操作',notes[value.strip()],QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        try:
            self.worker.submit(value);self.input.clear();self.at_menu=False;self.prompt_tail=''
            self.status.setText('已发送回答 · 请查看下一条脚本提示');self.input.setFocus()
        except ValueError as ex:self.status.setText(str(ex))

    def append_output(self,value):
        self.prompt_tail=(self.prompt_tail+value)[-512:]
        if self.connected and '请选择一个操作' in self.prompt_tail:
            self.at_menu=True;self.set_inputs(True);self.status.setText('菜单已打开 · 选择操作编号后发送');self.input.setFocus()
        cursor=self.console.textCursor();cursor.movePosition(QTextCursor.End)
        for part in re.split(r'([\r\n\b])',value):
            if not part:continue
            if self.pending_cr:
                self.pending_cr=False
                if part!='\n':
                    cursor.movePosition(QTextCursor.StartOfBlock);cursor.movePosition(QTextCursor.EndOfBlock,QTextCursor.KeepAnchor);cursor.removeSelectedText()
            if part=='\r':self.pending_cr=True
            elif part=='\b':cursor.deletePreviousChar()
            else:cursor.insertText(part)
        self.console.setTextCursor(cursor);self.console.ensureCursorVisible()

    def ended(self,code,message):
        self.connected=False;self.at_menu=False;self.prompt_tail=''
        self.set_inputs(False);self.status.setText(message)
        self.append_output('\n\n'+message+'\n')

    def session_finished(self):
        self.set_inputs(False);self.stop_button.setEnabled(False);self.close_button.setEnabled(True)
        self.connect_button.setEnabled(True);self.connect_button.setText('重新打开菜单')
        worker=self.worker;self.worker=None;worker.deleteLater()

    def interrupt(self):
        if not self.running():return
        note='中断会停止当前交互脚本。若正在安装内核，可能留下未完成的软件包，建议等待完成。确认中断？'
        if QMessageBox.question(self,'中断脚本',note,QMessageBox.Yes|QMessageBox.No,QMessageBox.No)==QMessageBox.Yes:
            self.worker.requestInterruption();self.stop_button.setEnabled(False);self.set_inputs(False);self.status.setText('正在中断脚本…')

    def reject(self):
        if self.running():
            self.status.setText('脚本运行中，请等待结束；需要中断时使用“中断脚本”按钮');return
        self.settings.password='';super().reject()

    def closeEvent(self,event):
        if self.running():
            event.ignore();self.status.setText('脚本运行中，请等待结束或点击“中断脚本”')
        else:
            self.settings.password='';super().closeEvent(event)
