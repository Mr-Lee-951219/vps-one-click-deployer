from pathlib import Path
import sys
import pefile
r=Path(sys.argv[1] if len(sys.argv)>1 else 'dist/NodePilot/_internal')
paths=[r,r/'PySide6',r/'shiboken6',Path('C:/Windows/System32')]
mapping={}
for directory in reversed(paths):
    for path in directory.glob('*'):
        if path.suffix.lower() in ('.dll','.pyd'):mapping[path.name.lower()]=path
pending=[r/'PySide6/QtCore.pyd',r/'PySide6/Qt6Core.dll',r/'PySide6/pyside6.abi3.dll']
visited=set();exports={}
while pending:
    path=pending.pop()
    if str(path) in visited or not path.exists():continue
    visited.add(str(path));pe=pefile.PE(str(path),fast_load=True)
    pe.parse_data_directories(directories=[1])
    for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
        name=entry.dll.decode().lower()
        if name.startswith(('api-ms-','ext-ms-')):continue
        dep=mapping.get(name)
        if not dep:print('MISSING DLL',path.name,name);continue
        if str(dep) not in exports:
            library=pefile.PE(str(dep),fast_load=True,max_symbol_exports=100000);library.parse_data_directories(directories=[0])
            exports[str(dep)]={x.name for x in getattr(library,'DIRECTORY_ENTRY_EXPORT',type('E',(),{'symbols':[]})()).symbols}
        absent=[x.name.decode() for x in entry.imports if x.name and x.name not in exports[str(dep)]]
        if absent:print('MISSING PROCEDURE',path.name,'->',dep,absent[:10])
        if dep.parent!=Path('C:/Windows/System32'):pending.append(dep)
print('Checked',len(visited),'libraries')
