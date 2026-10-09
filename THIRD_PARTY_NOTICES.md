# Third-party software

NodePilot invokes or distributes unmodified third-party components. Their respective licenses apply.

- 3x-ui official installation script v3.9.0: GPL-3.0, `assets/3x-ui-LICENSE`. Corresponding script source is included as `assets/official-install.sh`; full project source: https://github.com/MHSanaei/3x-ui/tree/v3.9.0
- Xray 26.9.30: MPL-2.0, `assets/Xray-LICENSE`. Unmodified binary extracted from the verified 3x-ui v3.9.0 Windows archive; archive and binary checksums are in `assets/core/provenance.json`. Corresponding source: https://github.com/XTLS/Xray-core/tree/v26.9.30
- PySide6 / Qt: LGPL-3.0 / GPL-3.0 / commercial options. This portable distribution uses separate shared Qt libraries; users can replace those libraries. Sources: https://code.qt.io/cgit/pyside/pyside-setup.git/ and https://code.qt.io/cgit/qt/qtbase.git/ . Distribution license texts are included under `assets/licenses`.
- Paramiko (LGPL), requests (Apache-2.0), cryptography (Apache-2.0 / BSD), qrcode (BSD), Pillow (HPND), PySocks (BSD), PyInstaller (GPL with bootloader exception). Installed package license texts are included under `assets/licenses` where supplied.
- acme.sh is downloaded on the user's VPS only when domain certificate mode is selected; source: https://github.com/acmesh-official/acme.sh/tree/3.1.6 .

NodePilot source is provided alongside the executable for review and modification.

## byJoey Actions-bbr-v3

Source: https://github.com/byJoey/Actions-bbr-v3
Pinned source commit: 5f10347280095b41f8597d974b9d7ad3ffa4fe2a
Standard kernel release: x86_64-7.2.9
License: assets/Actions-bbr-v3-LICENSE
Automatic deployment downloads the standard linux-image release directly, verifying its recorded SHA-256. Maintenance also offers the unmodified bundled upstream script as an interactive SSH PTY menu. Its SHA-256 is verified locally and remotely before execution; the script's own selected install/tuning operations are used. Script SHA-256: b49b5fe5cd21a41d7c465163ef52deafd781b0db70a0ffec180f915dfd14287e.
