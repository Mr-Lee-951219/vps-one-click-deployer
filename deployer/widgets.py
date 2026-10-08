"""Inline, keyboard accessible controls for the deployment form."""
from PySide6.QtCore import Qt,Signal
from PySide6.QtGui import QColor,QIcon,QIntValidator
from PySide6.QtWidgets import (QWidget,QFrame,QVBoxLayout,QHBoxLayout,QPushButton,QToolButton,QLabel,QLineEdit,QGraphicsDropShadowEffect,QSizePolicy)
from .engine import ASSETS
from .theme import themed_icon

def icon(name):return themed_icon(name)

class CollapsibleCard(QFrame):
    def __init__(self,title,description=''):
        super().__init__();self.setObjectName('card')
        outer=QVBoxLayout(self);outer.setContentsMargins(12,10,12,10);outer.setSpacing(0)
        self.header=QToolButton();self.header.setObjectName('cardToggle');self.header.setText(title)
        self.header.setToolButtonStyle(Qt.ToolButtonTextBesideIcon);self.header.setCheckable(True)
        self.header.setCursor(Qt.PointingHandCursor);self.header.setMinimumHeight(38)
        self.header.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Fixed)
        self.header.setAccessibleName(title+'，展开或收起');outer.addWidget(self.header)
        self.body=QWidget();self.area=QVBoxLayout(self.body);self.area.setContentsMargins(10,12,10,12);self.area.setSpacing(14)
        if description:
            hint=QLabel(description);hint.setWordWrap(True);hint.setObjectName('subtitle');self.area.addWidget(hint)
        outer.addWidget(self.body);self.header.toggled.connect(self.setExpanded);self.setExpanded(False)
        shadow=QGraphicsDropShadowEffect(self);shadow.setBlurRadius(20);shadow.setOffset(0,4);shadow.setColor(QColor(30,30,50,14));self.setGraphicsEffect(shadow)
    def setExpanded(self,expanded):
        self.header.setChecked(expanded);self.header.setIcon(icon('chevron.svg' if expanded else 'chevron-right.svg'))
        self.body.setVisible(expanded);self.updateGeometry()
    def isExpanded(self):return self.header.isChecked()

class PortEdit(QLineEdit):
    def __init__(self,value=''):
        super().__init__(str(value));self.setValidator(QIntValidator(1,65535,self));self.setMaxLength(5)
    def value(self):return int(self.text()) if self.text() else 0
    def setValue(self,value):self.setText(str(value) if value else '')

class RandomPortField(QFrame):
    def __init__(self,edit,title,callback):
        super().__init__();self.setObjectName('portField')
        row=QHBoxLayout(self);row.setContentsMargins(0,0,6,0);row.setSpacing(0)
        self.edit=edit;edit.setObjectName('portValue');row.addWidget(edit,1)
        self.random=QToolButton();self.random.setObjectName('randomPort');self.random.setIcon(icon('shuffle.svg'))
        self.random.setFixedSize(30,30);self.random.setCursor(Qt.PointingHandCursor)
        self.random.setToolTip('重新随机生成'+title);self.random.setAccessibleName('重新随机生成'+title)
        self.random.clicked.connect(callback);row.addWidget(self.random)

class CertificateSelector(QWidget):
    """Expands inside the card so certificate choices cannot obscure other fields."""
    currentIndexChanged=Signal(int)
    items=[('请选择证书方式',''),('自签证书 · HY2 固定指纹','selfsigned'),('域名证书 · 自动申请','domain')]
    def __init__(self):
        super().__init__();self.index=0
        self.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Fixed)
        outer=QVBoxLayout(self);outer.setContentsMargins(0,0,0,0);outer.setSpacing(8)
        self.opener=QPushButton(self.items[0][0]);self.opener.setObjectName('certificateSelect');self.opener.setCheckable(True)
        self.opener.setCursor(Qt.PointingHandCursor);self.opener.setAccessibleName('选择部署证书方式');outer.addWidget(self.opener)
        self.choices=QFrame();self.choices.setObjectName('certificateChoices');options=QVBoxLayout(self.choices);options.setContentsMargins(6,6,6,6);options.setSpacing(6)
        self.buttons={}
        for i,text in ((1,'自签证书 · 固定指纹\n无需域名，部署时生成'),(2,'域名证书 · 自动申请\n灰云解析到 VPS，需放行 TCP 80')):
            choice=QPushButton(text);choice.setObjectName('certificateChoice');choice.setCheckable(True);choice.setCursor(Qt.PointingHandCursor)
            choice.clicked.connect(lambda checked=False,n=i:self.setCurrentIndex(n));options.addWidget(choice);self.buttons[i]=choice
        outer.addWidget(self.choices);self.choices.hide();self.opener.toggled.connect(self.expand_choices)
    def expand_choices(self,expanded):
        self.choices.setVisible(expanded);self.layout().invalidate();self.layout().activate();self.updateGeometry()
    def findData(self,value):return next((i for i,item in enumerate(self.items) if item[1]==('domain' if value=='cloudflare' else value)),-1)
    def currentData(self):return self.items[self.index][1]
    def currentIndex(self):return self.index
    def setCurrentIndex(self,index):
        if not 0<=index<len(self.items):return
        changed=index!=self.index;self.index=index;self.opener.setText(self.items[index][0])
        for i,choice in self.buttons.items():choice.setChecked(i==index)
        self.hidePopup()
        if changed:self.currentIndexChanged.emit(index)
    def showPopup(self):self.opener.setChecked(True)
    def hidePopup(self):self.opener.setChecked(False)
    def setFocus(self,*args):self.opener.setFocus(*args)
