from pathlib import Path
import zipfile
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from deployer import __version__
target=root/'dist'/('NodePilot-v'+__version__+'-source.zip')
target.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
    for dirname in ['deployer','tools','tests','assets','docs','design-system']:
        for path in (root/dirname).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.name!='xray.exe':archive.write(path,path.relative_to(root))
    for name in ['main.py','requirements.txt','pytest.ini','build.ps1','README.md','THIRD_PARTY_NOTICES.md','.gitignore','.gitattributes']:
        archive.write(root/name,name)
print('Source archive created')
