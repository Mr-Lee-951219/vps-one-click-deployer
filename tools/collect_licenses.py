import importlib.metadata as metadata
from pathlib import Path
import shutil
root=Path(__file__).resolve().parents[1]/'assets'/'licenses'
root.mkdir(exist_ok=True)
for name in ['PySide6','PySide6_Essentials','PySide6_Addons','shiboken6','paramiko','requests','cryptography','qrcode','pillow','PySocks','pyinstaller']:
    dist=metadata.distribution(name)
    for file in dist.files or []:
        if '.dist-info/' in str(file) and any(p in file.name.lower() for p in ('license','copying','notice')):
            dest=root/name;dest.mkdir(exist_ok=True)
            shutil.copyfile(dist.locate_file(file),dest/file.name)
print('Third-party licenses collected')
