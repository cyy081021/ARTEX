import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from .campaign_entry import serve_configured
from .test_native_campaign_backend import probe_request


@unittest.skipUnless(sys.platform == "linux", "explicit local capability is Linux-only")
class ConfiguredEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.config = self.root / "config"
        self.stage.mkdir(mode=0o700)
        self.config.mkdir(mode=0o700)
        self.docker = self.root / "docker"
        self.docker.write_text("#!/bin/sh\nexit 99\n")
        self.docker.chmod(0o700)

    def test_missing_plan_wrong_root_and_operation_never_construct_backend(self):
        for mode in ("missing", "root", "operation"):
            frame = probe_request()
            frame["resource_plan"] = {"staging_root": str(self.stage)}
            if mode == "missing":
                del frame["resource_plan"]
            elif mode == "root":
                frame["resource_plan"]["staging_root"] = str(self.config)
            else:
                frame["operation"] = "session"
            def forbidden(**kwargs):
                self.fail("constructed backend for unauthorized entry")
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                serve_configured(str(self.docker), str(self.stage), str(self.config),
                                 io.StringIO(json.dumps(frame) + "\n"), io.StringIO(), forbidden)

    def test_overlapping_directories_refused(self):
        for config in (self.stage, self.stage / "config"):
            if config != self.stage:
                config.mkdir(mode=0o700)
            with self.subTest(config=str(config)), self.assertRaises(ValueError):
                serve_configured(str(self.docker), str(self.stage), str(config),
                                 io.StringIO(""), io.StringIO())

    def test_nonempty_config_refused_before_input(self):
        (self.config / "config.json").write_text("{}")
        with self.assertRaises(ValueError):
            serve_configured(str(self.docker), str(self.stage), str(self.config),
                             io.StringIO(""), io.StringIO())


if __name__ == "__main__":
    unittest.main()
