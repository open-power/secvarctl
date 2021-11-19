# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
#These tests will use sectool's validate command to determine wether the file was correctly generated.
#We can use the validate command because it was previously tested in runTests.py
import subprocess #for commmands
import os #for getting size of file
import sys
import time
import unittest
import filecmp
import re
import random

MEM_ERR = 101
SECTOOLS="../secvarctl-cov"
GEN = [SECTOOLS, "generate", "-v"]
OUTDIR = "./generatedTestData/"

# fTOh = [#[generateCommand], resultofGenerateCommand, [validatation Command], result
# [["-h", "SHA512", "-i", ]]
# ]
secvarctlGenCommands = [
[["--help"], True],
[["--usage"], True],
[["f:h", "-i", "-o", "out.hash"], False], #no input file given
[[ "-i", SECTOOLS, "-o", "out.hash"], False], #no generation type given
[["f:h", "-i", SECTOOLS, "-o"], False], #no output file given
[["f:h"], False], #no in or output files
[["f:", "-i", SECTOOLS, "-o", "out.hash"], False], #no output type given
[[":h", "-i", SECTOOLS, "-o", "out.hash"], False], #no input type given
[["f:h", "-i", "foo.txt", "-o", "out.hash"], False], #input file DNE
[["f:c", "-i", SECTOOLS, "-o", "out.hash"], False], #generate cert is invalid
[["f:t", "-i", SECTOOLS, "-o", "out.hash"], False], #output type DNE
]
badESLcommands =[
[["t:e", "-i", "./testdata/db_by_PK.crt", "-o", OUTDIR+"foo.esl"], False], #input type dne
[["c:e", "-i", "./testdata/db_by_PK.der", "-o",OUTDIR+"foo.esl"], False], #not PEM format
[["c:e", "-i", "./testdata/brokenFiles/rsa4096.crt", "-o", OUTDIR+"foo.esl"], False], #cert will not pass prevalidation, rsa 4096
[["c:e", "-i", "./testdata/brokenFiles/SHA384.crt", "-o", OUTDIR+"foo.esl"], False], #cert will not pass prevalidation, sha384
[["f:e", "-i", SECTOOLS, "-o", OUTDIR+"foo.esl", "-h"], False], #no hash function
[["f:e", "-i", SECTOOLS, "-o", OUTDIR+"foo.esl", "-h", "SHAFOO"], False], #invalid hash function
[["h:e", "-i", SECTOOLS, "-o", OUTDIR+"foo.esl", "-h", "SHA256"], False], #input file is not SHA246

]
badSignedCommands = [
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n"], False], #no var name
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "foo"], False], #Invalid var
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t","2020-10-2010:2:20", ], False], #Wrong timestamp format
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "10:2:20T2020-10-20"], False], #Wrong timestamp order
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-50-20T10:2:20" ], False], #bad month
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-200T10:2:20" ], False], #bad day
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T25:2:20" ], False], #bad hour
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:61:20" ], False], #bad minute
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:2:61" ], False], #bad sec
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t" ], False], #no timestammp arg
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #no key file
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k","./testdata/goldenKeys/PK/PK.key", "-c","-n", "db"], False], #no crt file
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k","./testdata/goldenKeys/PK/PK.key","-c", "./testdata/goldenKeys/PK/PK.crt",  "-c", "./testdata/goldenKeys/KEK/KEK.crt", "-n", "db"], False], #crt != #keys
[["e:a", "-i", "foo.bar", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #invalid input file
[["t:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #invalid input format for auth
[["t:p", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #invalid input format for pkcs7
[["c:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #bad input data for auth
[["c:p", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #bad input data for pkcs7
[["e:p", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "TS"], False], #update var is TS for pkcs7
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "TS"], False], #update var is TS for auth
[["e:p", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt"], False], #no update var pkcs7
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt"], False], #no update var auth
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/KEK/KEK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #mismatched cert and key pair
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth",  "-n", "db"], False], #no signing keys given
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-c", "./testdata/goldenKeys/PK/PK.key", "-k", "./testdata/goldenKeys/PK/PK.key", "-n", "db"], False], #key given for crt
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-c", "./testdata/goldenKeys/PK/PK.crt", "-k", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #cert given for key
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-c", "./testdata/goldenKeys/PK/foo.crt", "-k", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #cert is not a file

[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-c", "./testdata/goldenKeys/PK/data", "-k", "./testdata/goldenKeys/PK/PK.crt", "-n", "db"], False], #cert is nnot PEM
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-c", "./testdata/goldenKeys/PK/PK.crt", "-k", "./testdata/goldenKeys/PK/data", "-n", "db"], False], #key is not PEM

]

toeslCommands=[
[["-i", "-o", "out.esl"], False],#no input file
[["-i", "./testdata/db_by_PK.auth", "-o"], False],#no output file
[["-i", "./testdata/db_by_PK.auth"], False],#no output option
]

insertCommands = [
[["--usage"], True],
[["--help"], True],
[["-i", "./testdata/db_by_PK.auth", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-i is not an esl
[["-i", "./testdata/foo", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-i is not file
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.auth", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False] ,#-e is not an esl
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/foo", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False] ,#-e is not a file
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.key", "-k", "testenv/PK/PK.key"], False] ,#-c is not a certificate
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.foo", "-k", "testenv/PK/PK.key"], False] ,#-c is not a file
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-t", "2021-06-24 18:00:00"], False], #-t is invalid
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-t", "2021-06-24T18:00:99"], False], #-t is incorrect
[["-i", "./testdata/db_by_PK.esl", "-w", "-p",  "./", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-p is not to secvars
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl",  "-k", "testenv/PK/PK.key"], False], #no -c arg
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl"], False], #no signer arg
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt"], False], #no -k arg
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-c", "testenv/PK/PK.crt"], False], #-k != -c
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "TS", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #cannot update TS
[["-i", "./testdata/db_by_PK.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #no -w or -o
]

removeCommands = [
[["--usage"], True],
[["--help"], True],
[["-i", "./testdata/db_by_PK.esl", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-i is not an valid flag in remove
[["-x", "23/47/63/D4/D8/7E/4F/72/DC/78/23/0F/45/88/6B/86/B9/B8/23/5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-x is not an proper format
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:55", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-x is not in esl
[["-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #no -x flag
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5Z", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-x is not in hex
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.auth", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False] ,#-e is not an esl
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/foo", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False] ,#-e is not a file
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.key", "-k", "testenv/PK/PK.key"], False] ,#-c is not a certificate
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.foo", "-k", "testenv/PK/PK.key"], False] ,#-c is not a file
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-t", "2021-06-24 18:00:00"], False], #-t is invalid
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-t", "2021-06-24T18:00:99"], False], #-t is incorrect
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-w", "-p",  "./", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #-p is not to secvars
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl",  "-k", "testenv/PK/PK.key"], False], #no -c arg
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl"], False], #no signer arg
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt"], False], #no -k arg
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-c", "testenv/PK/PK.crt"], False], #-k != -c
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-o", "foo.esl", "-n", "TS", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #cannot update TS
[["-x", "23:47:63:D4:D8:7E:4F:72:DC:78:23:0F:45:88:6B:86:B9:B8:23:5B", "-n", "db", "-e" "./testdata/db_by_PK.esl", "-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key"], False], #no -w or -o
]

def command(args,out=None, addCMDRan=True):#stores last log of function into log file
		if out:
			with open(out, "w") as f:
				if addCMDRan:
					f.write("\n\n**********COMMAND RAN: $"+ ' '.join(args) +"\n")
				result=subprocess.call(args,stdout=f , stderr=f)
				f.close();
				return result


		return subprocess.call(args,stdout=out , stderr=out)

def getCmdResult(args, out, self):
	if MEMCHECK:
		mem_cmd = ["valgrind", "-q", "--error-exitcode="+str(MEM_ERR), "--leak-check=full"] + args
		with open(out, "w") as f:
			f.write("\n\n**********COMMAND RAN: $"+ ' '.join(mem_cmd) +"\n")
			result = subprocess.call(mem_cmd, stdout=f , stderr=f)
			f.close()
			self.assertNotEqual(result, MEM_ERR)
	#we run twice because valgrind interprets a -1 return code as a 0, which stinks
	rc = command(args, out)
	if rc == 0:
		return True
	else:
		return False

def setupTestEnv():
	out="log.txt"
	command(["cp", "-a", "./testdata/goldenKeys/.", "testenv/"],out)

def createEnvironment():
	f = "log.txt"
	command(["mkdir", "./generatedTestData"],f)
	command(["mkdir", "./testenv"],f)
	command(["mkdir", "./generatedTestData/brokenFiles"],f)

def compareFiles(a,b):
		if filecmp.cmp(a,b):
			return True
		return False
# def generateESL(path="./generatedTestData/",inp="default.crt",out="default.esl"):
# 	return command(GEN+["c:e", "-i", path+inp, "-o", path+out])
def createSizeFile(path):
	size=os.path.getsize(path+"data")
	with open(path+"size", "w") as f:
		f.write(str(size));
# def generateHashESL(path="./generatedTestData/", inp="dbx.crt", out="dbx.esl", hashF = "SHA256"):
# 	command(GEN + ["f:h", "-h", hashF, "-o", path+"dbx.hash", "-i", path+inp])
# 	command(GEN + ["h:e", "-h", hashF, "-i", path+"dbx.hash", "-o", path+out])


class Test(unittest.TestCase):
	def test_Generate_basic(self):
		out="secvarctlGenBasiclog.txt"
		cmd=GEN
		for i in secvarctlGenCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
	def test_dbxEsl(self):
		out = "genDbxEslLog.txt"
		cmd = GEN
		#get previously generated dbx esl's, they were made with the certs so alls we gotta do is use the same input and the ouput should match
		dbxFiles = []
		
		for file in os.listdir("./testdata"):
			if file.startswith("dbx"):
				if file.endswith(".esl") : #we know the nature of how these were made, the input files have the same name but different extension
					fileName=file[:-4]; #remove .esl
					dbxFiles.append(fileName)
		for efiGen in dbxFiles:
			hashMade = OUTDIR + efiGen + ".hash"
			eslMade = OUTDIR + efiGen + ".esl"
			eslDesired =  "./testdata/" + efiGen + ".esl"
			#first do it with file to has to ESL
			self.assertEqual( getCmdResult(cmd + ["f:h", "-i", "./testdata/" + efiGen + ".crt", "-o" ,hashMade], out, self), True) #assert the hashfile can be made
			self.assertEqual( getCmdResult(cmd + ["h:e", "-i", hashMade, "-o" , eslMade], out, self), True) #assert the ESL is valid
			self.assertEqual( getCmdResult([SECTOOLS ,"validate", "-e", "-x", eslMade], out, self), True) #assert the ESL is correctly formated
			# self.assertEqual( compareFile(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
			#then do it with the file to ESL (hash generation done internally)
			self.assertEqual( getCmdResult(cmd + ["f:e", "-i", "./testdata/" + efiGen + ".crt", "-o" ,eslMade], out, self), True) #assert the esl can be made from a file
			self.assertEqual( getCmdResult([SECTOOLS ,"validate", "-e", "-x", eslMade], out, self), True) #assert the ESL is correctly formated
			# self.assertEqual( compareFile(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
	def test_genEsl(self):
			out = "genEslLog.txt"
			cmd = GEN
			#get previously generated esl's, they were made with the certs so alls we gotta do is use the same input and the ouput should match
			eslFiles = []
			for file in os.listdir("./testdata"):
				if file.endswith(".esl") : #we know the nature of how these were made, the input files have the same name but different extension
					if not file.startswith("dbx") and not file.startswith("empty"):
						fileName=file[:-4]; #remove .esl
						eslFiles.append(fileName)
			for efiGen in eslFiles:
				eslMade = OUTDIR + efiGen + ".esl"
				eslDesired =  "./testdata/" + efiGen + ".esl"
				#first do it with file to has to ESL
				self.assertEqual( getCmdResult(cmd + ["c:e", "-i", "./testdata/" + efiGen + ".crt", "-o" , eslMade], out, self), True) #assert the hashfile can be made
				self.assertEqual( getCmdResult([SECTOOLS ,"validate", "-e", eslMade], out, self), True) #assert the ESL is correctly formated
				self.assertEqual( compareFiles(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
			for i in badESLcommands:
				self.assertEqual( getCmdResult(cmd + i[0], out, self), i[1]) 
	def test_genSignedFilesGen(self):
		out = "genSignedFilesLog.txt"
		auths = [] #array of[filename, key being updated, key signing]
		cmd = GEN
		#get all the 'valid' auths we made in /testdata, we will compare our results to these
		for file in os.listdir("./testdata"):
			if file.endswith(".auth"):
				if file.startswith("bad_"):
					fileName=file[4:-5];
					arr=fileName.split("_")
					auths.append([file,arr[0],arr[2]]) #[filename, keyname,keysigner]
				elif file.startswith("empty_"):
					#auths with noESL are key delete updates, perfectly valid, add to goodauths
					fileName = file[6:-5]
					arr=fileName.split("_")
					auths.append([file, arr[0],arr[2]])
				else:
					fileName=file[:-5];
					arr=fileName.split("_")
					auths.append([file,arr[0],arr[2]])
		for i in auths:
			fileBaseName=i[0][:-5]
			authDesired = "./testdata/"+i[0]
			genE2A = OUTDIR + i[0][0:-5]+"_fromESL.auth"
			genE2P = OUTDIR + i[0][0:-5]+"_fromESL.pkcs7"
			genC2A = OUTDIR + i[0][0:-5]+"_fromCert.auth"
			genC2P = OUTDIR + i[0][0:-5]+"_fromCert.pkcs7"
			signerKey= "./testdata/goldenKeys/"+i[2]+"/"+i[2]+".key"
			signerCrt= "./testdata/goldenKeys/"+i[2]+"/"+i[2]+".crt"
			if i[0].startswith("empty"):
				esl = "./testdata/empty.esl"
				#should fail if no force flag
				self.assertEqual( getCmdResult(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2A ], out, self), False)
				self.assertEqual( getCmdResult(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2A, "-f"], out, self), True)
				#build PKCS7 as well
				self.assertEqual( getCmdResult(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2P ], out, self), False)
				self.assertEqual( getCmdResult(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2P, "-f"], out, self), True)
			else:
				esl = "./testdata/"+fileBaseName+".esl"
				cert = "./testdata/"+fileBaseName+".crt"
				self.assertEqual( getCmdResult(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o",  genE2A], out, self), True)
				#build pkcs7
				self.assertEqual( getCmdResult(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o",  genE2P], out, self), True)
				#build auth/pkcs7 from certs
				if i[1] == "dbx":
					self.assertEqual( getCmdResult(cmd + ["f:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2A], out, self), True)
					#build pkcs7
					self.assertEqual( getCmdResult(cmd + ["f:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2P], out, self), True)
				else:
					self.assertEqual( getCmdResult(cmd + ["c:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2A], out, self), True)
					#build pkcs7
					self.assertEqual( getCmdResult(cmd + ["c:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2P], out, self), True)

			#all files should be valid format, check if dbx though
			if i[1] =="dbx":
				self.assertEqual( getCmdResult([SECTOOLS, "validate", "-x", genE2A], out, self), True)
				#validate pkcs7
				self.assertEqual( getCmdResult([SECTOOLS, "validate", "-x", "-p", genE2P], out, self), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "validate", "-x", genC2A], out, self), True)
					#validate pkcs7
					self.assertEqual( getCmdResult([SECTOOLS, "validate", "-x", "-p", genC2P], out, self), True)
			else:
				self.assertEqual( getCmdResult([SECTOOLS, "validate", genE2A], out, self), True)
				#validate pkcs7
				self.assertEqual( getCmdResult([SECTOOLS, "validate", "-p", genE2P], out, self), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "validate", genC2A], out, self), True)
					#validate pkcs7
					self.assertEqual( getCmdResult([SECTOOLS, "validate", "-p", genC2P], out, self), True)
			#all files besides the one that start with bad should be verified, bad means signed incorrectly
			if i[0].startswith("bad"):
				self.assertEqual( getCmdResult([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A], out, self), False)
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A], out, self), False)
			else:
				self.assertEqual( getCmdResult([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A], out, self), True)
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A], out, self), True)
 
		#now test custom timestamp works
		customTSAuth1 = OUTDIR+"db_by_PK_customTS1.auth"
		customTSAuth2 = OUTDIR+"db_by_PK_customTS2.auth"
		self.assertEqual( getCmdResult(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth1, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:2:8" ], out, self), True) 
		time.sleep(4)
		self.assertEqual( getCmdResult(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth2, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:2:8" ], out, self), True) 
		self.assertEqual( getCmdResult([SECTOOLS, "validate", customTSAuth1], out, self), True)
		self.assertEqual( getCmdResult([SECTOOLS, "validate", customTSAuth2], out, self), True)
		self.assertEqual( compareFiles(customTSAuth1, customTSAuth2), True)

		#now test incorrect generate commands
		for i in badSignedCommands:
			self.assertEqual( getCmdResult(cmd + i[0], out, self), i[1])
	def test_genResetFiles(self):
		#to test generating reset files we will use the 'generate a:e' command, this command was already tested in runTests.py
		out = 'genResetFilesLog.txt'
		cmd = GEN + ["reset"]
		inpDir = "./testdata/goldenKeys/"
		goodResetKeys = [ #[ key to be reset, signer]
		["db", "KEK"],
		["db", "PK"],
		["KEK", "PK" ],
		["PK", "PK"],
		["dbx", "KEK"],
		["dbx", "PK"]
		]
		badResetKeys = [ #these files will be valid but they will be signed with a signer without priviledges 
		["db", "db"],
		["KEK", "KEK"], 
		["KEK", "db"],
		["PK", "db"],
		["PK", "KEK"],
		["PK", "db"],
		["dbx", "db"]
		]
		emptyESLDesired = OUTDIR + "empty.esl"
		emptyESLActual = OUTDIR + "resultEmpyESL.esl"
		verifyCommand = [SECTOOLS, "verify", "-p", inpDir, "-u"]
		command(["touch", emptyESLDesired])
		toESLCommand = GEN + ["a:e", "-o", emptyESLActual, "-i"]
		for i in goodResetKeys:
			outFile = OUTDIR + "reset_" + i[0] + "_by_" + i[1]+".auth"
			crt = inpDir + i[1]+"/"+i[1]+".crt"
			key = inpDir + i[1]+"/"+i[1]+".key"
			#make sure it generates
			self.assertEqual( getCmdResult(cmd + ["-n", i[0], "-k", key, "-c", crt, "-o", outFile], out, self), True)
			#make sure it verifies (verify calls validate)
			self.assertEqual ( getCmdResult(verifyCommand + [i[0], outFile], out, self), True)
			#make sure its appended ESL is empty
			self.assertEqual( getCmdResult(toESLCommand + [outFile], out, self), True)
			self.assertEqual( compareFiles(emptyESLDesired, emptyESLActual), True)
			#cleanup
			command(["rm", emptyESLActual])
		#same process but verifying should fail
		for i in badResetKeys:
			outFile = OUTDIR + "bad_reset_" + i[0] + "_by_" + i[1]+".auth"
			crt = inpDir + i[1]+"/"+i[1]+".crt"
			key = inpDir + i[1]+"/"+i[1]+".key"
			#make sure it generates
			self.assertEqual( getCmdResult(cmd + ["-n", i[0], "-k", key, "-c", crt, "-o", outFile], out, self), True)
			#make sure it doesn't verify (verify calls validate)
			self.assertEqual ( getCmdResult(verifyCommand + [i[0], outFile], out, self), False)
			#make sure its appended ESL is empty
			self.assertEqual( getCmdResult(toESLCommand + [outFile], out, self), True)
			self.assertEqual( compareFiles(emptyESLDesired, emptyESLActual), True)
			#cleanup
			command(["rm", emptyESLActual])
		command(["rm", emptyESLDesired])

	def test_genExternalSig(self):
		out = "genExternalSigLog.txt"

		if OPENSSL:
			command(['echo' , '"TEST NOT RAN, OPENSSL BUILDS DO NOT HAVE THIS FEATURE"' ], out, False)
			return
		timestamp = ["-t", "2020-1-1T1:1:1"]
		inpCrt = "./testdata/db_by_KEK.crt"
		sigCrt = "./testdata/goldenKeys/KEK/KEK.crt"
		sigKey = "./testdata/goldenKeys/KEK/KEK.key"
		outDigest = OUTDIR + "digest_db_by_KEK.hash"
		digestHeaderTxt = OUTDIR + "digest_Header.txt"
		digestHeader = OUTDIR +"digest_Header.bin"
		expectedOutput = OUTDIR + "exp_db_by_KEK.auth"
		actualOutput = OUTDIR + "ext_sig_db_by_KEK.auth"
		digestWHeader = OUTDIR + "digestWHeader_db_by_KEK.bin"
		genSig = OUTDIR + "ext_sig_db_by_KEK.sig"
		#generate expected file
		self.assertEqual(getCmdResult(GEN + ["c:a", "-n", "db", "-k", sigKey, "-c", sigCrt, "-i", inpCrt, "-o", expectedOutput] + timestamp, out, self), True)
		#generate digest
		self.assertEqual(getCmdResult(GEN + ["c:x", "-n", "db", "-i", inpCrt, "-o", outDigest ] + timestamp, out, self), True)
		#add SHA256 oid to file
		command(['echo' , '"3031300D060960864801650304020105000420"' ], digestHeaderTxt, False)
		#convert ascii to binry
		command(["xxd", "-ps", "-r", digestHeaderTxt,digestHeader])
		#combine two files
		command(["cat", digestHeader, outDigest], digestWHeader, False)
		#do external signing
		command(["openssl", "rsautl", "-in", digestWHeader, "-sign", "-inkey", sigKey, "-pkcs", "-out", genSig,])
		#use external signature to make authfile
		self.assertEqual(getCmdResult(GEN + ["c:a", "-n", "db", "-s", genSig, "-c", sigCrt, "-i", inpCrt, "-o", actualOutput] + timestamp, out, self), True)
		#two files should be eqaul
		self.assertEqual(compareFiles(expectedOutput, actualOutput), True)
		
	def test_genHash(self):
		out = "genHashLog.txt"
		inpDir = "./testdata/"
		hashes = [ #hashes and there respective lengths in bytes
			["SHA1", 20],
			["SHA224", 28],
			["SHA256", 32],
			["SHA384", 48],
			["SHA512", 64]
		]
		#basic test, invalid inForm for generating hash 't'
		self.assertEqual( getCmdResult(GEN + ["t:h", "-i", inpDir+"db_by_PK.auth", "-o", "foo.bar"], out, self), False)
		for function in hashes:
			inpDir = "./testdata/"
			for file in os.listdir(inpDir):
			 	outFile = OUTDIR+function[0]+"_"+file+".hash"
			 	if file.endswith(".auth"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		else:
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
			 	elif file.endswith(".esl") and not file.startswith("empty"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( getCmdResult(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		else:
			 			self.assertEqual( getCmdResult(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
			 	elif file.endswith(".crt"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		else:
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), True)
			 		self.assertEqual(os.path.getsize(outFile), function[1])
			inpDir = "./testdata/brokenFiles/"
			#these should all fail unless forced
			for file in os.listdir(inpDir):
				outFile = OUTDIR+function[0]+"_"+file+".hash"
				if file.endswith(".auth"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)

			 		else:
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
			 			self.assertEqual( getCmdResult(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
				elif file.endswith(".esl"):
					if file.startswith("dbx"):
						self.assertEqual( getCmdResult(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
						self.assertEqual( getCmdResult(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)
					else:
			 			self.assertEqual( getCmdResult(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
			 			self.assertEqual( getCmdResult(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)
					self.assertEqual( os.path.getsize(outFile), function[1])
				elif file.endswith(".crt"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)

			 		else:
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out, self), False)
			 			self.assertEqual( getCmdResult(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out, self), True)

			 		self.assertEqual( os.path.getsize(outFile), function[1])
	def test_authtoesl(self):
		out="authtoesllog.txt"
		cmd=[SECTOOLS,"generate", "a:e"]
		inpDir = "./testdata/"
		postUpdate="testGenerated.esl"
		for file in os.listdir(inpDir):
			if not file.endswith(".auth"):
				continue;
			file = inpDir+file
			if file.startswith("./testdata/empty"):
				preUpdate = "./testdata/empty.esl"
			else:
				preUpdate=file[:-4]+"esl"#get esl in auth
			if file.startswith("./testdata/dbx"):
				self.assertEqual( getCmdResult(cmd+[ "-n",  "dbx", "-i", file, "-o", postUpdate],out, self), True)#assert command runs
			else:
				self.assertEqual( getCmdResult(cmd+[ "-i", file, "-o", postUpdate],out, self), True)#assert command runs
			self.assertEqual(compareFiles(preUpdate,postUpdate), True)
		command(["rm",postUpdate])
		for i in toeslCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		inpDir = './testdata/brokenFiles/'
		for file in os.listdir(inpDir):
			if not file.endswith(".auth"):
				continue;
			self.assertEqual( getCmdResult(cmd+["-i", file, "-o", postUpdate],out, self), False) #all broken auths should fail to have correct esl
			self.assertEqual( getCmdResult(["rm",postUpdate],out, self), False) #removal of output file should fail since it was never made

	def test_insert(self):
		out = "insertlog.txt"
		cmd = [SECTOOLS, "insert", "-v"]
		inpDir = "testdata/"
		timestamp = "2021-06-24T18:00:00"
		for i in insertCommands:
			self.assertEqual(getCmdResult(cmd + i[0], out, self), i[1])
		# goal is to:
		# add one ESL to the current secvar (KEK signed by PK)
		# then verify it is a  valid update and submitting it
		# then we convert auth to esl and set the new esl as updated variable (update PK as if reboot)
		# make a lower level key be signed with the new update and make sure it verifys, do not commit (make and verify new db update signed with new KEK key)
		# add another ESL to step one chain and repeat process
		# eventually all db updates should verify since they are signed with one of the many KEK ESL's
		required_auth_args = ["-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-n", "KEK", "-t", timestamp]
		required_path_args = ["-p", "testenv/"]
		output_file = "generatedTestData/foo.auth"
		output_file_esl = "generatedTestData/foo.esl"
		test_auth = "generatedTestData/new_db.auth"
		irrelevant_esl = "testdata/db_by_PK.esl" #this is just an ESL, nothing relvant about `db` by `PK` in filename
		setupTestEnv()
		#loop through all ESL's contiaing an x509, use as KEK update, test with db update signed with new KEK
		for file in os.listdir(inpDir):
			if not file.endswith(".esl") or file.startswith("dbx") or file.startswith("empty"):
				continue;
			file = inpDir+file
			self.assertEqual( getCmdResult(cmd + [ "-i", file, "-w"] + required_path_args + required_auth_args, out, self), True)
			# start side quest: make sure same result is achieved if ouptut to user defined file
			self.assertEqual(getCmdResult(cmd + [ "-i", file, "-o", output_file] + required_path_args + required_auth_args, out, self), True)
			self.assertEqual(compareFiles("testenv/KEK/update", output_file), True)
			#end side quest
			#ensure signing was success
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + [ "-u", "KEK", output_file], out, self), True)
			#create a db update with the new KEK data as signer
			crt = file[:-3] + "crt" #get new ESL's crt
			key = file[:-3] + "key" #get new ESL's key
			self.assertEqual(getCmdResult([SECTOOLS, "generate", "e:a", "-c", crt, "-k", key, "-n", "db", "-i", irrelevant_esl, "-o", test_auth ], out ,self), True)
			#ensure that `verify` fails since signed by ESL not yet in KEK
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + ["-u", "db", test_auth], out, self), False)
			#okay now make sure that test_auth DOES verify if the new KEK is updated successfully so that
			# the signer of test_auth is an entry in KEK ESL chain
			self.assertEqual(getCmdResult([SECTOOLS, "generate", "a:e", "-i", output_file, "-o", output_file_esl], out, self), True)
			#BUZZ BEE BOOP robot noises, pretend reboot w valid KEK update
			self.assertEqual(getCmdResult(["cp", output_file_esl, "testenv/KEK/data"], out, self), True)
			createSizeFile("testenv/KEK/")
			#now verify should pass since db update is signed by the latest entry in KEK
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + ["-u", "db", test_auth], out, self), True)
			command(["rm", output_file, output_file_esl, test_auth])
			#keep adding ESL's to KEK and checking with db updates

		setupTestEnv()
		#add test for appending to dbx
		#make auth file with new dbx entry appended to current dbx
		new_dbx=inpDir+"dbx_by_PK.esl"
		self.assertEqual(getCmdResult(cmd + [ "-i", new_dbx, "-o", output_file] + required_path_args + ["-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-n", "dbx"], out, self), True)
		#run `secvarctl verify` to ensure it would be successful
		self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + ["-u", "dbx", output_file], out, self), True)
		#the contained ESL should equal dbx entry in sysfs appended with new ESL
		self.assertEqual(getCmdResult([SECTOOLS, "generate", "a:e", "-i", output_file, "-o", output_file_esl, "-n", "dbx"], out, self), True)
		dbx_expected ="generatedTestData/foo_expected.esl"
		with open(dbx_expected, 'wb') as out_file:
			for dbx_esl in ['testenv/dbx/data', new_dbx]:
					with open(dbx_esl, 'rb') as in_file:
						out_file.write(in_file.read())
		self.assertEqual(compareFiles(output_file_esl, dbx_expected), True)
		command(["rm", output_file, output_file_esl, dbx_expected])
		#extra test for force flag
		#appending and signing two empty files should fail since 0 + 0 is not an esl
		self.assertEqual(getCmdResult(cmd + required_auth_args + ["-i", "./testdata/empty.esl", "-e", "testdata/empty.esl", "-o", "generatedTestData/empty_w_empy.auth"], out, self ), False)
		#should pass if forced
		self.assertEqual(getCmdResult(cmd + required_auth_args + ["-i", "./testdata/empty.esl", "-e", "testdata/empty.esl", "-o", "generatedTestData/empty_w_empy.auth", "-f"], out, self ), True)

	def test_remove(self):
		out = "removelog.txt"
		cmd = [SECTOOLS, "remove", "-v"]
		inpDir = "testdata/"
		timestamp = "2021-06-24T18:00:00"
		for i in removeCommands:
			self.assertEqual(getCmdResult(cmd + i[0], out, self), i[1])
		# goal is to:
		# create dictionary of serial numbers that map to private/public/esl 
		# create a large KEK contianing all serial numbers in previous step
		# select random entry from dictionary, sign a db update with it
		# ensure this db update will be successful with secvarctl verify
		# remove the selected entry from the KEK with output file and -w flag (ensure these two result in the same auth file)
		# update the KEK with removed entry
		# ensure the db update is no longer successful with secvarctl verify (since its signer has been removed)
		required_auth_args = ["-c", "testenv/PK/PK.crt", "-k", "testenv/PK/PK.key", "-n", "KEK", "-t", timestamp]
		required_path_args = ["-p", "testenv/"]
		output_file = "generatedTestData/foo.auth"
		output_file_esl = "generatedTestData/foo.esl"
		test_auth = "generatedTestData/new_db.auth"
		irrelevant_esl = "testdata/db_by_PK.esl" #this is just an ESL, nothing relvant about `db` by `PK` in filename
		setupTestEnv()
		# dictionary with serial # = [esl,crt, key]
		serial_dict = {}
		#loop through all ESL's contiaing an x509, add it to a dictionary with its public/private/esl files
		for esl in os.listdir(inpDir):
			if not esl.endswith(".esl") or esl.startswith("dbx") or esl.startswith("empty"):
				continue;
			esl = inpDir+esl
			crt = esl[:-3] + "crt" #get new ESL's crt
			key = esl[:-3] + "key" #get new ESL's key
			# extract serial number from X509 in ESL
			read_crt_output = subprocess.run([SECTOOLS, 'validate', '-v', '-c', crt], stdout=subprocess.PIPE).stdout.decode('utf-8')
			if read_crt_output is None:
				self.fail(f'could not extract serial number from {crt}')
			serial = re.search(r'(?i)serial number\s*:\s+(\S+)', read_crt_output)
			serial_dict[serial.group(1)] = [esl, crt, key]
		#append all found esl's to one esl list, make sure it is valid, pretend it is our KEK
		with open(output_file_esl, 'wb') as out_file:
			for serial in serial_dict:
				with open(serial_dict[serial][0], 'rb') as in_file:
					out_file.write(in_file.read())
		self.assertEqual(getCmdResult([SECTOOLS, 'validate', "-v", "-e", output_file_esl], out, self ), True)
		self.assertEqual(getCmdResult(["cp", output_file_esl, "testenv/KEK/data"], out, self), True)
		createSizeFile("testenv/KEK/")

		# setup is done, we now have a KEK with many ESL's in it
		# now we can test 'secvarctl remove'
		for i in range(len(serial_dict)):
			serial, files = random.choice(list(serial_dict.items()))
			crt = files[1]
			key = files[2]
			self.assertEqual( getCmdResult(cmd + [ "-x", serial, "-w"] + required_path_args + required_auth_args, out, self), True)
			# start side quest: make sure same result is achieved if ouptut to user defined file
			self.assertEqual(getCmdResult(cmd + [ "-x", serial, "-o", output_file] + required_path_args + required_auth_args, out, self), True)
			self.assertEqual(compareFiles("testenv/KEK/update", output_file), True)
			#end side quest
			#ensure signing was success
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + [ "-u", "KEK", output_file], out, self), True)
			# make db update signed with random entry in KEK
			self.assertEqual(getCmdResult([SECTOOLS, "generate", "e:a", "-c", crt, "-k", key, "-n", "db", "-i", irrelevant_esl, "-o", test_auth ], out ,self), True)
			#ensure that `verify` passes since update is signed by ESL in KEK
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + ["-u", "db", test_auth], out, self), True)
			#okay now make sure that test_auth DOES NOT verify if the new KEK is updated successfully so that
			# the signer of test_auth is no longer an entry in KEK ESL chain
			self.assertEqual(getCmdResult([SECTOOLS, "generate", "a:e", "-i", output_file, "-o", output_file_esl], out, self), True)
			#BUZZ BEE BOOP robot noises, pretend reboot w valid KEK update
			self.assertEqual(getCmdResult(["cp", output_file_esl, "testenv/KEK/data"], out, self), True)
			createSizeFile("testenv/KEK/")
			#now verify should fail since db update is no longer signed by the latest entry in KEK
			self.assertEqual(getCmdResult([SECTOOLS, "verify", "-v"] + required_path_args + ["-u", "db", test_auth], out, self), False)
			command(["rm", output_file, output_file_esl, test_auth])
			del serial_dict[serial]

		# at this point the KEK should now be empty
		final_KEK_size = subprocess.run(['cat', 'testenv/KEK/size'], stdout=subprocess.PIPE).stdout.decode('utf-8')
		self.assertEqual(final_KEK_size, '0')
		setupTestEnv()
if __name__ == '__main__':
	if "MEMCHECK" in sys.argv:
	 	MEMCHECK = True
	else: 
	 	MEMCHECK = False
	if 'OPENSSL_TESTS_ONLY' in sys.argv:
		OPENSSL = True
	else:
		OPENSSL = False
	del sys.argv[1:]
	createEnvironment()
	setupTestEnv()
	unittest.main()




