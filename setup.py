"""Build the standalone verification resources without installing top-level tests."""
from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithVerification(build_py):
    def _verification_files(self):
        root = Path(__file__).resolve().parent
        for name in ("SPEC.md", "THREATMODEL.md"):
            yield root / name, Path(name)
        for source in sorted((root / "tests").rglob("*.py")):
            yield source, source.relative_to(root)

    def run(self):
        super().run()
        target = Path(self.build_lib) / "pinwash" / "_verification"
        if not target.resolve().is_relative_to(Path(self.build_lib).resolve()):
            raise RuntimeError("Verification output escapes the build directory")
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)
        for source, relative in self._verification_files():
            destination = target / relative
            self.mkpath(str(destination.parent))
            self.copy_file(str(source), str(destination))

    def get_outputs(self, include_bytecode=1):
        target = Path(self.build_lib) / "pinwash" / "_verification"
        return super().get_outputs(include_bytecode) + [
            str(target / relative) for _, relative in self._verification_files()
        ]


setup(cmdclass={"build_py": BuildWithVerification})
