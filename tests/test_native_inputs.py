import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from crumbtrail.cli import LAB_CLIENT, parser
from crumbtrail.native import run_local
from crumbtrail.storage import CaseError


class StopBeforeNative(Exception):
    """End a compatibility check immediately after the input guards."""


class NativeInputTests(unittest.TestCase):
    def parse_local(self, *directory_args):
        return parser().parse_args([
            "local", "--root", "unused-case", "--client-id", LAB_CLIENT,
            "--velociraptor", "unused-collector", *directory_args,
        ])

    def test_cli_requires_log_directory(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                self.parse_local()
        self.assertEqual(error.exception.code, 2)

    def test_cli_rejects_blank_log_directory(self):
        for value in ("", "   ", "\t\r\n"):
            with self.subTest(value=value):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as error:
                        self.parse_local("--log-directory", value)
                self.assertEqual(error.exception.code, 2)
                self.assertIn("nonblank exported EVTX log directory", errors.getvalue())

    def test_cli_preserves_nonblank_directory_text(self):
        for value in (".", "relative-exports", "exports with spaces", " exports "):
            with self.subTest(value=value):
                args = self.parse_local("--log-directory", value)
                self.assertEqual(str(args.log_directory), value)

    def test_api_rejects_missing_and_blank_directory_before_native_work(self):
        for arguments in ({}, {"log_directory": None}, {"log_directory": ""},
                          {"log_directory": "   "}, {"log_directory": "\t\r\n"}):
            with self.subTest(arguments=arguments):
                case = Mock()
                with patch("crumbtrail.native.Path", side_effect=AssertionError("Unexpected path resolution")) as path, \
                     patch("crumbtrail.precision.require_parser", side_effect=AssertionError("Unexpected EVTX parser")) as precise, \
                     patch("crumbtrail.native.subprocess.run", side_effect=AssertionError("Unexpected collector")) as native:
                    with self.assertRaisesRegex(CaseError, "explicitly"):
                        run_local(case, LAB_CLIENT, "unused-collector", **arguments)
                    path.assert_not_called()
                    precise.assert_not_called()
                    native.assert_not_called()
                case.binding.assert_not_called()
                case.preserve.assert_not_called()

    def assert_stops_at_binding(self, executable, **arguments):
        case = Mock()
        case.binding.side_effect = StopBeforeNative
        with patch("crumbtrail.precision.require_parser", side_effect=AssertionError("Unexpected EVTX parser")) as precise, \
             patch("crumbtrail.native.subprocess.run", side_effect=AssertionError("Unexpected collector")) as native:
            with self.assertRaises(StopBeforeNative):
                run_local(case, LAB_CLIENT, executable, **arguments)
            precise.assert_not_called()
            native.assert_not_called()
        case.binding.assert_called_once_with(LAB_CLIENT)
        case.preserve.assert_not_called()

    def test_api_preserves_explicit_nonblank_directory_paths(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.chdir(temporary):
            executable = Path(temporary) / "inert-collector"
            executable.write_bytes(b"inert")
            for name in ("relative-exports", "exports with spaces", " exports "):
                Path(name).mkdir()
            for value in (".", Path("."), Path(""), "relative-exports", "exports with spaces", " exports "):
                with self.subTest(value=value):
                    self.assert_stops_at_binding(executable, log_directory=value)

    def test_fixture_does_not_require_log_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "inert-collector"
            executable.write_bytes(b"inert")
            for arguments in ({}, {"log_directory": None}, {"log_directory": ""},
                              {"log_directory": " \t "}):
                with self.subTest(arguments=arguments):
                    self.assert_stops_at_binding(executable, fixture=True, **arguments)


if __name__ == "__main__":
    unittest.main()
