import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import InstallPureVPNMonitor as installer


@unittest.skipUnless(installer.os.name == 'posix', 'Tests native POSIX installer permissions')
class InstallerTests(unittest.TestCase):
    def test_interrupted_activation_retries_then_healthy_run_is_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'PureVPNMonitor.py').touch()
            (root / 'managed.json').touch()
            (root / 'start').mkdir()
            (root / 'update').mkdir()
            with patch.object(installer, 'ROOT', root), \
                    patch.object(installer, 'ACTION', root / 'actions.conf'), \
                    patch.object(installer, 'HOOK_ROOT', root), \
                    patch.object(installer.os, 'geteuid', return_value=0, create=True), \
                    contextlib.redirect_stdout(io.StringIO()):
                with patch.object(installer.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'service')):
                    with self.assertRaises(subprocess.CalledProcessError):
                        installer.main()
                self.assertTrue((root / 'integration-pending').exists())
                with patch.object(installer.subprocess, 'run') as run:
                    installer.main()
                    self.assertEqual(run.call_count, 3)
                self.assertFalse((root / 'integration-pending').exists())
                # Windows does not preserve POSIX modes; test the actual no-op on POSIX.
                if installer.os.name == 'posix':
                    with patch.object(installer.subprocess, 'run') as run:
                        installer.main()
                        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
