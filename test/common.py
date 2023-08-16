import unittest
import subprocess


class SecvarctlTest(unittest.TestCase):
    out = ""
    test_env_dir = ""
    test_data_dir = ""
    log_dir = ""

    def command(self, args, out=None):  # stores last log of function into log file
        if out:
            # if memory tests being done, use valgrind as well
            with open(out, "w") as f:
                f.write("\n\n**********COMMAND RAN: $" + " ".join(args) + "\n")
                result = subprocess.call(args, stdout=f, stderr=f)
                f.close()
                return not result
        return not subprocess.call(args, stdout=out, stderr=out)

    def assertCmd(self, args, out, expected: bool):
        tmp_assert, msg = {
            True: (self.assertTrue, f"Expected success, but failed: '{' '.join(args)}'"),
            False: (self.assertFalse, f"Expected failure, received success: '{' '.join(args)}'"),
        }[expected]

        tmp_assert(self.command(args, out), msg=msg)

    def assertCmdTrue(self, args, out):
        self.assertCmd(args, out, True)

    def assertCmdFalse(self, args, out):
        self.assertCmd(args, out, False)

    def setupTestEnvironment(self):
        for var in ["out", "test_env_dir", "test_data_dir", "log_dir"]:
            if not getattr(self, var):
                raise RuntimeError(f"required test case value '{var}' not set")

        self.out = "log.txt"
        self.command(["mkdir", "-p", f"{self.log_dir}"])
        self.command(["mkdir", "-p", f"{self.test_env_dir}"])
        self.command(
            ["cp", "-a", f"{self.test_data_dir}/goldenKeys/.", f"{self.test_env_dir}/"]
        )
