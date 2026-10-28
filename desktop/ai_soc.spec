# PyInstaller spec for the desktop app:  pyinstaller desktop/ai_soc.spec --noconfirm
# Output: dist/AISOCPlatform/AISOCPlatform(.exe) (one-folder build: fast start, packaged by Inno Setup)
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent
ICON = ROOT / "desktop" / "assets" / "app.ico"
SKIP = (".tests", ".testing", ".conftest")


def wanted(name):
    return not any(part in name for part in SKIP)


datas = [
    (str(ROOT / "config"), "config"),
    (str(ROOT / "src" / "ui"), "src/ui"),
]
hiddenimports = (
    collect_submodules("src")
    + collect_submodules("uvicorn")
    + collect_submodules("sklearn", filter=wanted, on_error="ignore")
    + ["websockets", "h11", "httptools", "anyio._backends._asyncio", "webview", "aiohttp", "psutil", "dotenv"]
)

a = Analysis(
    [str(ROOT / "desktop" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "IPython", "jupyter", "notebook", "pytest", "tensorflow", "torch",
              "kafka", "elasticsearch"],  # optional server integrations; not needed by the desktop app
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="AISOCPlatform", console=False,
          icon=str(ICON) if ICON.exists() else None, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="AISOCPlatform")
