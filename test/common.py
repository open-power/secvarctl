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
                return result
        return subprocess.call(args, stdout=out, stderr=out)

    # TODO: slated for removal or merge with command
    def getCmdResult(self, args, out):
        return bool(self.command(args, out))

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
