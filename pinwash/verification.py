"""Run installed doctor against installed code and bundled original tests."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def installed_doctor(package: Path) -> int:
    bundle = package / "_verification"
    if not all((bundle / name).is_file() for name in ("SPEC.md", "THREATMODEL.md")):
        sys.stderr.write("pinwash doctor: verification contracts missing from installation\n")
        return 2
    if not (bundle / "tests" / "__init__.py").is_file() or not list((bundle / "tests").rglob("test_*.py")):
        sys.stderr.write("pinwash doctor: verification tests missing from installation\n")
        return 2
    with tempfile.TemporaryDirectory(prefix="pinwash-doctor-") as temporary:
        root = Path(temporary)
        shutil.copytree(package, root / "pinwash", ignore=shutil.ignore_patterns("_verification", "__pycache__", "*.pyc"))
        shutil.copytree(bundle / "tests", root / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("SPEC.md", "THREATMODEL.md"):
            shutil.copyfile(bundle / name, root / name)
        bootstrap = "import sys; sys.path.insert(0,sys.argv[1]); from pinwash.cli import main; sys.exit(main(['doctor']))"
        # Inherit the nesting marker: clearing it would recurse indefinitely.
        result = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap, str(root)], cwd=root, check=False)
        return result.returncode if result.returncode == 0 else 2
