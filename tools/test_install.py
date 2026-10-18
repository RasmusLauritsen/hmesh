"""Offline installer tests: python3 -m unittest discover -s tools -p 'test_install.py'."""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        self.destination = self.root / "installed"
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin",
                        HMESH_INSTALL_DIR=str(self.destination),
                        FIXTURES=str(self.fixtures), TEST_OS="Linux",
                        TEST_ARCH="x86_64", TEST_GH="no")
        self.mock("uname", 'if [ "$1" = -s ]; then echo "$TEST_OS"; else echo "$TEST_ARCH"; fi')
        self.mock("gh", '''
case "$1 $2" in
  "auth status") [ "$TEST_GH" = yes ] ;;
  "release view") echo v1.2.3 ;;
  "release download")
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --dir ]; then dest=$2; shift; fi
      shift
    done
    cp "$FIXTURES"/* "$dest/" ;;
  *) exit 1 ;;
esac''')
        self.mock("curl", '''
[ "$TEST_GH" != yes ] || exit 99
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then dest=$2; shift; fi
  url=$1
  shift
done
case "$url" in
  */latest) printf 'https://github.com/RasmusLauritsen/hmesh/releases/tag/v1.2.3' ;;
  *) cp "$FIXTURES/${url##*/}" "$dest" ;;
esac''')

    def mock(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def fixture(self, os_name="linux", arch="amd64", corrupt=False):
        archive = self.fixtures / f"hmesh_1.2.3_{os_name}_{arch}.tar.gz"
        binary = b"#!/bin/sh\necho fixture\n"
        with tarfile.open(archive, "w:gz") as output:
            info = tarfile.TarInfo("hmesh")
            info.size = len(binary)
            info.mode = 0o755
            output.addfile(info, io.BytesIO(binary))
        digest = "0" * 64 if corrupt else hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.fixtures / "checksums.txt").write_text(f"{digest}  {archive.name}\n")

    def run_installer(self):
        return subprocess.run(["bash", str(INSTALLER)], env=self.env,
                              capture_output=True, text=True)

    def test_public_linux_install(self):
        self.fixture()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.access(self.destination / "hmesh", os.X_OK))

    def test_private_macos_arm_install(self):
        self.env.update(TEST_GH="yes", TEST_OS="Darwin", TEST_ARCH="arm64")
        self.fixture("darwin", "arm64")
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.destination / "hmesh").is_file())

    def test_checksum_failure_preserves_existing_binary(self):
        self.fixture(corrupt=True)
        self.destination.mkdir()
        binary = self.destination / "hmesh"
        binary.write_text("existing")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checksum verification failed", result.stderr)
        self.assertEqual(binary.read_text(), "existing")

    def test_missing_checksum(self):
        self.fixture()
        (self.fixtures / "checksums.txt").write_text("")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_unsupported_architecture(self):
        self.env["TEST_ARCH"] = "armv7l"
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported architecture", result.stderr)


if __name__ == "__main__":
    unittest.main()
