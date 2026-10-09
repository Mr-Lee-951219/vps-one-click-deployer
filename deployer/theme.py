"""Shared light/dark appearance, including dialogs and native Fusion controls."""
import re
from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import QApplication, QToolButton, QPushButton

STYLE = '''
QWidget { font-family:"Segoe UI","Microsoft YaHei UI"; font-size:14px; color:#27272d; }
QMainWindow, QStackedWidget, QScrollArea, QScrollArea>QWidget>QWidget { background:#f3f3f6; }
QDialog, QMessageBox { background:#f7f7f9; }
QFrame#card { background:#ffffff; border:1px solid #e7e7ec; border-radius:18px; }
QFrame#header { background:#fcfcfd; border-bottom:1px solid #e5e5eb; }
QLabel#brand { font-size:21px; font-weight:600; color:#24242b; }
QLabel#logo { color:white; background:#d62f59; border-radius:13px; font-size:17px; font-weight:600; }
QFrame#nav { background:#eaeaf0; border:1px solid #e3e3e9; border-radius:13px; }
QTabBar::tab { background:transparent; padding:11px 24px; margin:4px; border-radius:9px; color:#62626f; }
QTabBar::tab:selected { background:white; color:#be2450; font-weight:600; }
QTabBar::tab:hover:!selected { background:#f2f2f6; color:#353540; }
QTabBar::tab:focus { border:1px solid #d62f59; }
QFrame#status { background:white; border:1px solid #e7e7ec; border-radius:15px; }
QLabel#statusText { color:#353540; font-weight:600; }
QLabel#elapsed { background:#f4f4f7; border-radius:7px; padding:4px 9px; color:#62626f; font-family:Consolas; }
QFrame#terminal { background:white; border:1px solid #e1e1e8; border-radius:18px; }
QFrame#terminalHeader { background:transparent; border-bottom:1px solid #ededf2; }
QLabel#terminalMeta { color:#666674; font-size:12px; }
QPlainTextEdit#liveLog { background:#fcfcfd; color:#34343f; border:0; border-radius:12px; padding:16px; font-size:13px; selection-background-color:#f9dce5; selection-color:#27272d; }
QFrame#terminal QPushButton { background:#fafafc; color:#62626f; border:1px solid #e5e5ec; padding:6px 12px; font-size:12px; border-radius:8px; }
QFrame#terminal QPushButton:hover { background:#f9edf1; color:#be2450; border-color:#efc4d0; }
QFrame#terminal QCheckBox { color:#666674; font-size:12px; }
QSplitter::handle { background:transparent; width:16px; }
QSplitter::handle:hover { background:#e7e7ed; border-radius:7px; }
QLabel#title { font-size:26px; font-weight:600; }
QLabel#subtitle { color:#666674; }
QLabel#section { font-size:17px; font-weight:600; color:#27272d; }
QToolButton#cardToggle { background:transparent; border:0; border-radius:8px; padding:6px 8px; color:#27272d; font-size:16px; font-weight:600; text-align:left; }
QToolButton#cardToggle:hover { background:#faf3f6; }
QToolButton#cardToggle:focus { background:#fbeaf0; }
QPushButton#certificateSelect { text-align:left; background:#fafafd; border:1px solid #dedee7; border-radius:9px; padding:11px 36px 11px 12px; background-image:url(@ICONS@/select-chevron.svg); background-repeat:no-repeat; background-position:right center; }
QPushButton#certificateSelect:checked, QPushButton#certificateSelect:focus { border-color:#d62f59; background-color:#ffffff; }
QFrame#certificateChoices { background:#fafafd; border:1px solid #e7e7ee; border-radius:11px; }
QPushButton#certificateChoice { text-align:left; background:white; border:1px solid transparent; border-radius:8px; padding:10px 12px; min-height:40px; color:#454550; }
QPushButton#certificateChoice:hover { background:#fbeaf0; border-color:#f1d0da; }
QPushButton#certificateChoice:checked { background:#fbe6ee; border-color:#efc3d1; color:#af2249; }
QFrame#portField { background:#fafafd; border:1px solid #dedee7; border-radius:9px; }
QLineEdit#portValue, QLineEdit#portValue:focus { border:0; background:transparent; padding:9px 12px; }
QToolButton#randomPort { border:0; border-radius:7px; background:transparent; }
QToolButton#randomPort:hover, QToolButton#randomPort:focus { background:#f9e1e9; }
QToolButton#randomPort:disabled { background:#f1f1f5; }
QToolButton#copyResult { background:#fafafd; border:1px solid #e7e7ee; border-radius:9px; }
QToolButton#copyResult:hover, QToolButton#copyResult:focus { background:#fbeaf0; border-color:#e8b5c5; }
QToolButton#copyResult:disabled { background:#f3f3f6; }
QPushButton { background:#ffffff; border:1px solid #dedee6; border-radius:10px; padding:10px 16px; color:#454550; }
QPushButton:hover { background:#faf0f4; border-color:#e8b5c5; color:#be2450; }
QPushButton:pressed { background:#f9e1e9; }
QPushButton:disabled { color:#9999a3; background:#f1f1f5; border-color:#e7e7ec; }
QPushButton#primary { background:#d62f59; color:white; border:1px solid #d62f59; font-weight:600; }
QPushButton#primary:hover { background:#c22850; border-color:#c22850; }
QPushButton#primary:pressed { background:#ad2147; }
QPushButton#primary:disabled { background:#e5b7c4; border-color:#e5b7c4; color:#ffffff; }
QPushButton:focus { border:2px solid #a62248; }
QLineEdit, QSpinBox, QComboBox { background:#fafafd; border:1px solid #dedee7; border-radius:9px; padding:9px 12px; min-height:22px; color:#373741; selection-background-color:#f9dce5; selection-color:#27272d; }
QLineEdit:hover, QSpinBox:hover, QComboBox:hover { border-color:#b9bbc8; background:#ffffff; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border:1px solid #d62f59; background:#ffffff; }
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled { color:#9999a3; background:#f4f4f7; border-color:#e7e7ed; }
QLineEdit { placeholder-text-color:#848491; }
QSpinBox { padding-right:66px; }
QSpinBox::up-button { subcontrol-origin:border; subcontrol-position:center right; width:26px; height:26px; right:7px; background:#ededf3; border:0; border-radius:6px; }
QSpinBox::down-button { subcontrol-origin:border; subcontrol-position:center right; width:26px; height:26px; right:36px; background:#ededf3; border:0; border-radius:6px; }
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background:#f5dfe7; }
QSpinBox::up-button:pressed, QSpinBox::down-button:pressed { background:#efc4d2; }
QSpinBox::up-arrow { image:url(@ICONS@/plus.svg); width:12px; height:12px; }
QSpinBox::down-arrow { image:url(@ICONS@/minus.svg); width:12px; height:12px; }
QComboBox { padding-right:36px; }
QComboBox::drop-down { subcontrol-origin:border; subcontrol-position:top right; width:34px; border:0; background:transparent; }
QComboBox::down-arrow { image:url(@ICONS@/chevron.svg); width:16px; height:16px; }
QComboBox QAbstractItemView { background:white; color:#353540; border:1px solid #e1e1e8; border-radius:10px; padding:6px; outline:0; selection-background-color:#fbe6ee; selection-color:#af2249; }
QComboBox QAbstractItemView::item { min-height:36px; padding:4px 10px; border-radius:6px; border:0; }
QComboBox QAbstractItemView::item:hover, QComboBox QAbstractItemView::item:selected { background:#fbe6ee; color:#af2249; }
QListWidget#bbrChoices { background:transparent; border:0; outline:0; selection-background-color:#fbe6ee; selection-color:#af2249; }
QListWidget#bbrChoices::item { padding:10px 8px; min-height:24px; border-radius:8px; margin:2px 0; }
QListWidget#bbrChoices::item:hover { background:#faf0f4; }
QListWidget#bbrChoices::item:selected { background:#fbe6ee; color:#af2249; }
QListWidget#bbrChoices::item:focus { border:1px solid #d62f59; }
QCheckBox { spacing:9px; padding:4px 0; }
QCheckBox::indicator { width:16px; height:16px; border:1px solid #b9bac6; border-radius:5px; background:white; }
QCheckBox::indicator:hover { border-color:#d62f59; }
QCheckBox::indicator:checked { background:#d62f59; border:1px solid #d62f59; image:url(@ICONS@/check.svg); }
QCheckBox::indicator:disabled { background:#eeeef3; border-color:#d9d9e2; }
QCheckBox::indicator:checked:disabled { background:#d6a5b4; image:url(@ICONS@/check.svg); }
QCheckBox:focus { color:#af2249; }
QRadioButton { spacing:8px; padding:4px 0; }
QRadioButton::indicator { width:16px; height:16px; border:1px solid #b9bac6; border-radius:8px; background:white; }
QRadioButton::indicator:checked { border:5px solid #d62f59; width:8px; height:8px; border-radius:9px; background:white; }
QDateTimeEdit { background:#fafafd; border:1px solid #dedee7; border-radius:9px; padding:9px 12px; min-height:22px; }
QDateTimeEdit::up-button, QDateTimeEdit::down-button { width:0; border:0; }
QDateTimeEdit::drop-down { width:30px; border:0; }
QDateTimeEdit::down-arrow { image:url(@ICONS@/chevron.svg); width:16px; height:16px; }
QCalendarWidget QWidget { background:white; color:#353540; }
QCalendarWidget QToolButton { background:#fafafd; color:#454550; border:0; padding:7px; }
QPlainTextEdit { background:white; border:1px solid #e5e5ec; border-radius:10px; padding:12px; font-family:Consolas,"Microsoft YaHei UI"; }
QProgressBar { border:0; border-radius:3px; background:#f0f0f4; height:6px; }
QProgressBar::chunk { background:#d62f59; border-radius:3px; }
QTableWidget { background:white; border:1px solid #e5e5ec; border-radius:10px; gridline-color:#f0f0f4; }
QHeaderView::section { background:#f6f6f9; color:#62626f; padding:10px; border:0; font-weight:600; }
QScrollBar:vertical { width:8px; background:transparent; margin:4px 0; }
QScrollBar::handle:vertical { background:#cacbd4; border-radius:4px; min-height:36px; }
QScrollBar::handle:vertical:hover { background:#aaaab9; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background:transparent; }
QScrollBar:horizontal { height:8px; background:transparent; }
QScrollBar::handle:horizontal { background:#cacbd4; border-radius:4px; min-width:36px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
'''

# Keep geometry shared so switching appearance never changes the form layout.
DARK_COLORS = {
    '#f3f3f6':'#15171d', '#f7f7f9':'#1b1e26', '#ffffff':'#232630',
    '#fcfcfd':'#1b1e26', '#fafafd':'#292d38', '#fafafc':'#292d38',
    '#eaeaf0':'#21242e', '#f2f2f6':'#2d313e', '#f4f4f7':'#292d38',
    '#27272d':'#eceef4', '#24242b':'#f5f6fb', '#353540':'#dde1eb',
    '#34343f':'#d8dce7', '#373741':'#eceef4', '#454550':'#d7dbe6',
    '#62626f':'#a9afbf', '#666674':'#a5adbd', '#848491':'#959eaf',
    '#9999a3':'#747e91', '#b9bbc8':'#596275', '#b9bac6':'#677287',
    '#e7e7ec':'#343946', '#e5e5eb':'#303542', '#e3e3e9':'#303542',
    '#e1e1e8':'#343946', '#ededf2':'#303542', '#e5e5ec':'#363c4a',
    '#e7e7ed':'#343a47', '#e7e7ee':'#3a4050', '#dedee7':'#41495b',
    '#dedee6':'#41495b', '#ededf3':'#353b4a', '#eeeef3':'#343a47',
    '#d9d9e2':'#495163', '#f1f1f5':'#292e39', '#f0f0f4':'#303642',
    '#f6f6f9':'#2a2f3b', '#cacbd4':'#4d566a', '#aaaab9':'#6a748a',
    '#be2450':'#ff9cba', '#af2249':'#ffafc8', '#a62248':'#ff7fa7',
    '#f9dce5':'#583247', '#fbe6ee':'#493043', '#fbeaf0':'#3b2b39',
    '#faf3f6':'#302833', '#f9edf1':'#3b2b39', '#faf0f4':'#3b2b39',
    '#f9e1e9':'#4b3043', '#f5dfe7':'#4b3043', '#efc4d0':'#7e465e',
    '#f1d0da':'#704157', '#efc3d1':'#94506a', '#e8b5c5':'#94506a',
    '#efc4d2':'#704157', '#e5b7c4':'#653747', '#d6a5b4':'#724153',
}

EXTRA_STYLE = '''
QLabel#logo { background:transparent; border:0; }
QFrame#themeSwitcher { background:@SWITCH_BG@; border:1px solid @SWITCH_BORDER@; border-radius:10px; }
QFrame#themeSwitcher QPushButton { padding:6px 10px; border:0; border-radius:7px; background:transparent; min-height:20px; }
QFrame#themeSwitcher QPushButton:checked { background:@SWITCH_SELECTED@; color:@SWITCH_TEXT@; font-weight:600; }
QFrame#themeSwitcher QPushButton:hover:!checked { background:@SWITCH_HOVER@; }
QFrame#themeSwitcher QPushButton:focus { border:1px solid #d62f59; }
QTableWidget::item:selected { background:@SELECTION@; color:@SELECTED_TEXT@; }
QToolTip { background:@TIP_BG@; color:@TIP_TEXT@; border:1px solid @SWITCH_BORDER@; padding:7px; }
QDialog#hostIdentityPrompt, QDialog#systemPrompt { background:@DIALOG_BG@; }
'''


def stylesheet(mode, icons):
    dark = mode == 'dark'
    style = STYLE
    if dark:
        style = re.sub(r'#[0-9a-fA-F]{6}|\bwhite\b',
                       lambda m:DARK_COLORS.get('#ffffff' if m[0]=='white' else m[0].lower(),m[0]),style)
        # Primary buttons stay white on rose; selected navigation needs its own surface.
        style += '\nQPushButton#primary, QLabel#logo { color:#ffffff; }\nQPushButton#primary:disabled { color:#c8bac4; }\nQTabBar::tab:selected { background:#353b49; }\n'
    tokens = {
        '@SWITCH_BG@':'#21242e' if dark else '#eaeaf0',
        '@SWITCH_BORDER@':'#343946' if dark else '#e3e3e9',
        '@SWITCH_SELECTED@':'#353b49' if dark else '#ffffff',
        '@SWITCH_TEXT@':'#ff9cba' if dark else '#be2450',
        '@SWITCH_HOVER@':'#2d313e' if dark else '#f2f2f6',
        '@SELECTION@':'#493043' if dark else '#fbe6ee',
        '@SELECTED_TEXT@':'#ffafc8' if dark else '#af2249',
        '@TIP_BG@':'#292d38' if dark else '#ffffff',
        '@TIP_TEXT@':'#eceef4' if dark else '#27272d',
        '@DIALOG_BG@':'#1b1e26' if dark else '#ffffff',
    }
    style += EXTRA_STYLE
    for key,value in tokens.items():style = style.replace(key,value)
    return style.replace('@ICONS@',icons)


def themed_icon(name, group='ui'):
    from .engine import ASSETS
    app = QApplication.instance()
    path = ASSETS / group / ('dark' if app and app.property('appearance') == 'dark' else '') / name
    return QIcon(str(path))


def apply_theme(app, mode):
    from .engine import ASSETS
    mode = 'dark' if mode == 'dark' else 'light'
    dark = mode == 'dark'
    app.setProperty('appearance',mode)
    palette = QPalette()
    for role,color in (
        (QPalette.Window,'#15171d' if dark else '#f3f3f6'),
        (QPalette.WindowText,'#eceef4' if dark else '#27272d'),
        (QPalette.Base,'#232630' if dark else '#ffffff'),
        (QPalette.AlternateBase,'#2a2f3b' if dark else '#f7f7f9'),
        (QPalette.Text,'#eceef4' if dark else '#27272d'),
        (QPalette.Button,'#292d38' if dark else '#ffffff'),
        (QPalette.ButtonText,'#d7dbe6' if dark else '#454550'),
        (QPalette.Highlight,'#493043' if dark else '#fbe6ee'),
        (QPalette.HighlightedText,'#ffafc8' if dark else '#af2249'),
        (QPalette.ToolTipBase,'#292d38' if dark else '#ffffff'),
        (QPalette.ToolTipText,'#eceef4' if dark else '#27272d'),
        (QPalette.PlaceholderText,'#959eaf' if dark else '#848491'),
        (QPalette.Link,'#ff9cba' if dark else '#be2450'),
    ):palette.setColor(role,QColor(color))
    for role in (QPalette.Text,QPalette.ButtonText,QPalette.WindowText):
        palette.setColor(QPalette.Disabled,role,QColor('#747e91' if dark else '#9999a3'))
    app.setPalette(palette)
    icons = ASSETS / 'ui' / ('dark' if dark else '')
    app.setStyleSheet(stylesheet(mode,icons.as_posix()))
    # Refresh icons on widgets already on screen, preserving expansion and copy feedback.
    for widget in app.allWidgets():
        if isinstance(widget,QToolButton):
            name = widget.objectName()
            if name == 'cardToggle':widget.setIcon(themed_icon('chevron.svg' if widget.isChecked() else 'chevron-right.svg'))
            elif name == 'randomPort':widget.setIcon(themed_icon('shuffle.svg'))
            elif name == 'copyResult':widget.setIcon(themed_icon('copied.svg' if widget.property('copySuccess') else 'copy.svg','icons'))
        elif isinstance(widget,QPushButton) and widget.objectName() in ('lightTheme','darkTheme'):
            widget.setChecked(widget.objectName() == mode+'Theme')
    return mode
