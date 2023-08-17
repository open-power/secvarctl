# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
import unittest
import os
import filecmp
from common import SecvarctlTest, SECTOOLS

DATAPATH = "./testdata/host"
TESTENV = "./testenv/host"


goodAuths = []
badAuths = []
goodESLs = []
goodCRTs = []
brokenAuths = []
brokenESLs = []
brokenCrts = []
brokenPkcs7s = []


secvarctlCommands = [
    [["--usage"], True],
    [["--help"], True],
    [["-v"], False],  # no command
    [[], False],  # no commands
    [["foobar"], False]  # bad command
]
ppcSecVarsRead = [
    [["read"], True],
    [["read", "-v"], True], [["read", "-r"], True],  # verbose and raw
    [["read", "badVarname"], False],  # bad var name
]

readCommands = [
    [["-p", f"{TESTENV}/"], True],  # no args and change path
    [["-f", f"{TESTENV}/PK/data"], True],  # give esl file
    [["-p", f"{TESTENV}/", "PK"], True], [["-p", f"{TESTENV}/", "KEK"], True],
    [["-p", f"{TESTENV}/", "db"], True], [["-p", f"{TESTENV}/", "dbx"], True],  # print only PK, KEK,and dbx
    [["--usage"], True], [["--help"], True],  # usage and help
    [["-f", f"{TESTENV}/db/data", "-r"], True],  # print raw data from file
    [["-p", f"{TESTENV}/", "-r"], True],  # print raw data from current vars
    [["-p", "."], False],  # bad path
    [["-f", f"{DATAPATH}/db_by_PK.auth"], False],  # given authfile instead of esl
    [["-p"], False],  # only -p no path
    [["-f"], False],  # only -f no file
    [["-f", "-p", "-f"], False],  # idek but should fail
    [["-f", "foo"], False],  # fake file should fail
]

verifyCommands = [
    [["--usage"], True], [["--help"], True],
    [["-c", "PK", f"{TESTENV}/PK/data", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], True],  # update with current vars set and update set
    [["-c", "PK", f"{TESTENV}/PK/data", "KEK", f"{TESTENV}/KEK/data", "db", f"{TESTENV}/db/data", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/PK_by_PK.auth"], True],  # update chain with given current vars set
    [["-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/PK_by_PK.auth"], True],  # update chain with path set
    [["-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "db", f"{DATAPATH}/db_by_KEK.auth"], True],  # submit newer update after older
    [["-c", "PK", f"{TESTENV}/PK/data", "KEK", f"{TESTENV}/KEK/foo", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], True],  # KEK bad path, should continue
    [["-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/brokenFiles/1db_by_PK.auth", "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/PK_by_PK.auth"], False],  # update chain with one broken auth file should fail
    [["-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/bad_PK_by_db.auth"], False],  # update chain with one improperly signed auth file should fail
    [["-u", "db", f"{DATAPATH}/db_by_PK.auth", "-p"], False],  # no path given, should fail
    [["-c", "-u"], False],  # no vars given
    [["-c", "PK", f"{TESTENV}/PK/data"], False],  # no updates given
    [["-p", f"{TESTENV}", "-u", "db", f"{DATAPATH}/db_by_KEK.auth", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # submit older update after newer
    [["-p", f"{TESTENV}/", "-u",  "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/PK_by_PK.auth", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # update chain with bad order
    [["-v"], False],  # verify no args
    [["-u", "db", "notRealFile.auth"], False],  # not real file
    [["-u", f"{TESTENV}/db_by_PK.auth", "db"], False],  # wrong order
    [["-u", "PK"], False],  # no file given
    [["-v", "-w", "-c", "PK", f"{TESTENV}/PK/data", "KEK", f"{TESTENV}/KEK/data", "db", f"{TESTENV}/db/data", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "KEK", f"{DATAPATH}/KEK_by_PK.auth", "PK", f"{DATAPATH}/PK_by_PK.auth"], False],  # no where to write it too so should fail
    [["-p", f"{TESTENV}/", "-u", "TS", f"{DATAPATH}/db_by_KEK.auth"], False],  # cannot update TS variable, Its illegal, dont do it...ever
    [["-c", "PK", f"{TESTENV}/PK/data", "-u", "db", f"{DATAPATH}/db_by_PK.auth", "-u", "KEK", f"{DATAPATH}/KEK_by_PK.auth"], False],  # update vars set twice
    [["-c", "PK", f"{TESTENV}/PK/data", f"{TESTENV}/KEK/data", "KEK", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # current vars bad format
    [["-c", "PK", "KEK", f"{TESTENV}/PK/data", f"{TESTENV}/KEK/data", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # current vars bad format
    [["-c", "PK", f"{TESTENV}/PK/data", "KEK", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # current vars bad format
    [["-c", "KEK", f"{TESTENV}/KEK/data", "-u", "PK", f"{DATAPATH}/PK_by_PK.auth", "db", f"{DATAPATH}/bad_db_by_db.auth"], False]
]

writeCommands = [
    [["--usage"], True], [["--help"], True],
    [["KEK", f"{DATAPATH}/KEK_by_PK.auth", "-p", f"{TESTENV}/"], True],  # different ordering should still work
    [["KEK", f"{DATAPATH}/KEK_by_PK.auth", "-p", f"{TESTENV}/", "-v"], True],  # different ordering should still work with verbose
    [["TS", f"{DATAPATH}/KEK_by_PK.auth", "-p", f"{TESTENV}/"], False],  # no TS varible updates allowed
    [["db", "foo.file"], False],  # bad auth file
    [["KEK", "-v", "-p", f"{TESTENV}/"], False],  # should fail, no file
    [["KEK", f"{DATAPATH}/KEK_by_PK.auth", "-p"], False],  # no path should fail
    [["KeK", f"{DATAPATH}/KEK_by_PK.auth", "-p", f"{TESTENV}/"], False],  # bad var name should fail
    [["KEK", f"{DATAPATH}/KEK_by_PK.auth", "-p", f"{TESTENV}ironement/"], False],  # bad path should fail
    [["db"], False],  # no authfile
    [[], False]  # no auth or var
]

validateCommands = [
    [["--usage"], True], [["--help"], True],
    [["-v"], False],  # no input file
    [["thisDontExist.auth"], False],  # nonexistent file
    [["-e"], False],  # no esl
    [["-c"], False],  # no crt
    [["-p"], False],  # no pkcs7
    [["-p", f"{DATAPATH}/db_by_PK.auth"], False],  # give auth as pkcs7
]


# these really aren't tests with bad envs, its more so tests that use two commands to run.
badEnvCommands = [  # [arr command to skew env, output of first command, arr command for sectool, expected result]
    [["rm", f"{TESTENV}/KEK/size"], None, ["-m", "host", "read", "-p", f"{TESTENV}/", "KEK"], False],  # remove size and it should fail
    [["rm", f"{TESTENV}/KEK/size"], None, ["-m", "host", "read", "-p", f"{TESTENV}/"], True],  # remove size but as long as one is readable then it is ok
    [['echo', '"hey fail!"', '>', f"{TESTENV}/db/size"], None, ["-m", "host", "read", "-p", f"{TESTENV}/", "db"], False],  # read from ascii size file should fail
    [["dd", f"if={DATAPATH}/goldenKeys/KEK/data", f"of={TESTENV}/KEK/data", "count=100", "bs=1"], None, ["-m", "host", "verify", "-v", "-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_KEK.auth"], False],  # verify against path with bad esl files should fail, modified THAT SHOULD NEVER HAPPEN!
    [["rm", "-r", f"{TESTENV}/db", f"{TESTENV}/dbx", f"{TESTENV}/KEK", f"{TESTENV}/PK", f"{TESTENV}/TS"], None, ["-m", "host", "verify", "-v", "-p", f"{TESTENV}/", "-u", "PK", f"{DATAPATH}/PK_by_PK.auth"], True],  # no data in path should enter setup mode
    [["cp", f"{DATAPATH}/brokenFiles/empty.esl", f"{TESTENV}/PK/data"], None, ["-m", "host", "verify", "-v", "-p", f"{TESTENV}/", "-u", "PK", f"{DATAPATH}/PK_by_PK.auth"], True],  # no data in pk ==setup mode
    [["rm", f"{TESTENV}/db/update"], None, ["-m", "host", "verify", "-v", "-w", "-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], False],  # no update file should exit
    [["cp", f"{DATAPATH}/brokenFiles/empty.esl", f"{TESTENV}/PK/data"], None, ["-m", "host", "read", "-p", f"{TESTENV}/"], True],  # Pk will be empty but other files will have things
    [["cp", f"{DATAPATH}/brokenFiles/empty.esl", f"{TESTENV}/PK/data"], None, ["-m", "host", "read", "-p", f"{TESTENV}/", "PK"], False],  # Pk will be empty, nothing else read so overall failure
    [["echo", "16", ">", f"{TESTENV}/TS/size"], None, ["-m", "host", "verify", "-v", "-p", f"{TESTENV}/", "-u", "PK", f"{DATAPATH}/PK_by_PK.auth"], False],
    [["dd", "if=/dev/zero", f"of={TESTENV}/TS/data", "count=4", "bs=16"], None, ["-m", "host", "verify", "-p", f"{TESTENV}/", "-u", "PK", f"{DATAPATH}/PK_by_PK.auth"], True],  # If timestamp entry for a variable is empty than thats okay
    [["echo", "0", ">", f"{TESTENV}/KEK/size"], None, ["-m", "host", "verify", "-p", f"{TESTENV}/", "-u", "db", f"{DATAPATH}/db_by_PK.auth"], True]  # an empty KEK should not interupt db by PK verification
]


def setupArrays():
    for file in os.listdir(f"{DATAPATH}"):
        if file.endswith(".auth"):
            if file.startswith("bad_"):
                fileName = file[4:-5]
                arr = fileName.split("_")
                badAuths.append([file, arr[0], arr[2]])  # [filename, keyname,keysigner]
            elif file.startswith("empty_"):
                # auths with noESL are key delete updates, perfectly valid, add to goodauths
                fileName = file[6:-5]
                arr = fileName.split("_")
                goodAuths.append([file, arr[0], arr[2]])
            else:
                fileName = file[:-5]
                arr = fileName.split("_")
                goodAuths.append([file, arr[0], arr[2]])
        elif file.endswith(".esl") and not file.startswith("empty"):
            if not file.startswith("bad"):
                fileName = file[:-4]
                arr = fileName.split("_")
                goodESLs.append([file, arr[0], arr[2]])
        elif file.endswith(".der"):
            if not file.startswith("bad"):
                fileName = file[:-4]
                arr = fileName.split("_")
                goodCRTs.append([file, arr[0], arr[2]])
        elif file.endswith(".crt"):
            if not file.startswith("bad"):
                fileName = file[:-4]
                arr = fileName.split("_")
                goodCRTs.append([file, arr[0], arr[2]])

    for file in os.listdir(f"{DATAPATH}/brokenFiles"):  # sort broken files into esl's crts and auths
        if file.endswith(".esl"):
            brokenESLs.append(f"{DATAPATH}/brokenFiles/"+file)
        elif file.endswith(".der") or file.endswith(".crt"):
            brokenCrts.append(f"{DATAPATH}/brokenFiles/"+file)
        elif file.endswith(".auth"):
            brokenAuths.append(f"{DATAPATH}/brokenFiles/"+file)
        elif file.endswith(".pkcs7"):
            brokenPkcs7s.append(f"{DATAPATH}/brokenFiles/"+file)


class Test(SecvarctlTest):
    test_env_dir = f"{TESTENV}"
    test_data_dir = f"{DATAPATH}"

    def setUp(self):
        self.setupTestEnvironment()

    def test_secvarctl_basic(self):
        cmd = [SECTOOLS]
        cmd += ["-m", "host"]
        for i in secvarctlCommands:
            self.assertCmd(cmd+i[0], i[1])

    # def test_ppcSecVarsRead(self):
    #     out = "ppcSecVarsReadlog.txt"
    #     cmd = [SECTOOLS]
    #     cmd += ["-m", "host"]
    #     # if power sysfs exists read current keys
    #     if os.path.isdir(SECVARPATH):
    #         for i in ppcSecVarsRead:
    #             self.assertCmd(cmd+i[0], i[1])
    #     else:
    #         with open(out, "w") as f:
    #             f.write(f"POWER SECVAR LOCATION ( {SECVARPATH} ) DOES NOT EXIST SO NO TESTS RAN\n")
    #             f.close()

    def test_verify(self):
        cmd = [SECTOOLS]
        # cmd += ["-m","host","verify"]
        for fileInfo in goodAuths:
            file = f"{DATAPATH}/"+fileInfo[0]
            self.assertCmdTrue(cmd+["-m", "host", "verify", "-w", "-p", f"{TESTENV}/", "-u", fileInfo[1], file])  # verify all auths are signed by keys in testenv
            self.assertTrue(filecmp.cmp(f"{TESTENV}/"+fileInfo[1]+"/update", file))  # assert files wrote correctly
        for fileInfo in badAuths:
            file = f"{DATAPATH}/"+fileInfo[0]
            self.assertCmdFalse(cmd+["-m", "host", "verify", "-p", f"{TESTENV}/", "-u", fileInfo[1], file])  # verify all bad auths are not signed correctly
        for i in verifyCommands:
            self.assertCmd(cmd+["-m", "host", "verify"]+i[0], i[1])

    def test_validate(self):
        cmd = [SECTOOLS]
        cmd += ["-m", "host", "validate"]
        for i in validateCommands:
            self.assertCmd(cmd+i[0], i[1])
        for i in goodAuths:  # validate all auths
            file = f"{DATAPATH}/"+i[0]
            if i[1] != "dbx":
                self.assertCmdTrue(cmd+[file])
            else:
                self.assertCmdTrue(cmd+[file, "-x"])
        for i in goodESLs:
            file = f"{DATAPATH}/"+i[0]
            if i[1] != "dbx":
                file = f"{DATAPATH}/"+i[0]
                self.assertCmdTrue(cmd+["-e", file])
            else:
                self.assertCmdTrue(cmd+["-e", file, "-x"])
        for i in goodCRTs:
            file = f"{DATAPATH}/"+i[0]
            self.assertCmdTrue(cmd+["-v", "-c", file])
        for i in brokenAuths:
            self.assertCmdFalse(cmd+["-v", i])
        for i in brokenESLs:
            self.assertCmdFalse(cmd+["-v", "-e", i])
        for i in brokenCrts:
            self.assertCmdFalse(cmd+["-v", "-c", i])
        for i in brokenPkcs7s:
            self.assertCmdFalse(cmd+["-v", "-p", i])

    def test_read(self):
        cmd = [SECTOOLS]
        cmd += ["-m", "host", "read"]
        # self.assertEqual(not not not command(cmd, out, self), True) #no args
        for i in readCommands:
            self.assertCmd(cmd+i[0], i[1])
        for i in brokenESLs:
            # read should read sha and rsa esl's w no problem
            if i.startswith(f"{DATAPATH}/brokenFiles/sha") or i.startswith(f"{DATAPATH}/brokenFiles/rsa"):
                self.assertCmdTrue(cmd+["-f", i])
            else:
                self.assertCmdFalse(cmd+["-f", i])  # all truncated esls should fail to print human readable info

    def test_write(self):
        cmd = [SECTOOLS]
        cmd += ["-m", "host", "write"]
        path = f"{TESTENV}/"
        for i in writeCommands:
            self.assertCmd(cmd+i[0], i[1])
        for i in goodAuths:  # try write with good auths, validation included
            file = f"{DATAPATH}/"+i[0]
            preUpdate = file  # get auth
            postUpdate = path+i[1]+"/update"  # ./testenv/<varname>/update
            self.assertCmdTrue(cmd+["-p", path, i[1], file])  # assert command runs
            self.assertTrue(filecmp.cmp(preUpdate, postUpdate))  # assert auths esl is equal to data written to update file
        for i in brokenAuths:
            self.assertCmdFalse(cmd+["-p", path, "KEK", i])  # broken auths should fail
            self.assertCmdTrue(cmd+["-p", path, "-f", "KEK", i])  # if forced, they should work
            self.assertTrue(filecmp.cmp(i, path+"KEK/update"))

    def test_badenv(self):
        for i in badEnvCommands:
            self.setupTestEnvironment()
            os.system(" ".join(i[0]))  # TODO: probably wrap this in a better assert thing
            self.assertCmd([SECTOOLS]+i[2], i[3])


if __name__ == '__main__':
    setupArrays()
    unittest.main()
