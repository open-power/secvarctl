import unittest
import subprocess
import os
import signal

SECTOOLS = os.environ.get("SECVAR_TOOL", "../bin/secvarctl-dbg")
SECVARPATH = "/sys/firmware/secvar/vars/"


class CommandOutput:
    def __init__(self, comproc: subprocess.CompletedProcess):
        self.rc = not comproc.returncode
        # Certain tests probably dump raw data to stdout, so escape those rather than decode garbage
        self.stdout = comproc.stdout.decode(errors="backslashreplace")
        self.stderr = comproc.stderr.decode(errors="backslashreplace")

    def __bool__(self):
        return self.rc

    def __str__(self):
        return f"stdout:\n{self.stdout}\n\nstderr:\n{self.stderr}"


class SecvarctlTest(unittest.TestCase):
    test_env_dir = ""
    test_data_dir = ""

    def command(self, args):
        try:
            out = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            print(f"Error in command '{' '.join(args)}")
            raise e

        ret = CommandOutput(out)
        if out.returncode < 0:
            sig = signal.Signals(-out.returncode).name
            self.assertTrue(out.returncode >= 0, msg=f"Command exited via signal {sig}: '{' '.join(args)}'\n{ret}'")
        return ret

    def assertCmd(self, args, expected: bool):
        tmp_assert, msg = {
            True: (self.assertTrue, f"Expected success, but failed: '{' '.join(args)}'"),
            False: (self.assertFalse, f"Expected failure, received success: '{' '.join(args)}'"),
        }[expected]

        result = self.command(args)
        tmp_assert(bool(result), msg=f"{msg}\n{result}")

    def assertCmdTrue(self, args):
        self.assertCmd(args, True)

    def assertCmdFalse(self, args):
        self.assertCmd(args, False)

    def setupTestEnvironment(self):
        for var in ["test_env_dir", "test_data_dir"]:
            if not getattr(self, var):
                raise RuntimeError(f"required test case value '{var}' not set")

        self.command(["mkdir", "-p", f"{self.test_env_dir}"])
        self.command(
            ["cp", "-a", f"{self.test_data_dir}/goldenKeys/.", f"{self.test_env_dir}/"]
        )

    def checkBackend(self, backend):
        result = self.command([SECTOOLS, "-m", backend, "-h"])
        if not bool(result):
            raise unittest.SkipTest
