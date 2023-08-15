import unittest
import subprocess

MEMCHECK = False
MEM_ERR = 101


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

    def getCmdResult(self, args, out):
        if MEMCHECK:
            mem_cmd = [
                "valgrind",
                "-q",
                "--error-exitcode=" + str(MEM_ERR),
                "--leak-check=full",
            ] + args
            with open(out, "w") as f:
                f.write("\n\n**********COMMAND RAN: $" + " ".join(mem_cmd) + "\n")
                result = subprocess.call(mem_cmd, stdout=f, stderr=f)
                f.close()
                self.assertNotEqual(result, MEM_ERR)
        # we run twice because valgrind interprets a -1 return code as a 0, which stinks
        rc = self.command(args, out)
        if rc == 0:
            return True
        else:
            return False

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
