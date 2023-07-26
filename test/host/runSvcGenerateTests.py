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
import argparse

MEM_ERR = 101
SECTOOLS="../../bin/secvarctl-cov"
GEN = [SECTOOLS, "-m", "host", "generate", "-v"]
OUTDIR = "./generatedTestData/"
MEMCHECK = False
OPENSSL = True
GNUTLS = False

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
# def createSizeFile(path):
# 	size=os.path.getsize(path+"data")
# 	with open(path+"size", "w") as f:
# 		f.write(str(size));
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
			self.assertEqual( getCmdResult([SECTOOLS , "-m", "host", "validate", "-e", "-x", eslMade], out, self), True) #assert the ESL is correctly formated
			# self.assertEqual( compareFile(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
			#then do it with the file to ESL (hash generation done internally)
			self.assertEqual( getCmdResult(cmd + ["f:e", "-i", "./testdata/" + efiGen + ".crt", "-o" ,eslMade], out, self), True) #assert the esl can be made from a file
			self.assertEqual( getCmdResult([SECTOOLS , "-m", "host", "validate", "-e", "-x", eslMade], out, self), True) #assert the ESL is correctly formated
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
				self.assertEqual( getCmdResult([SECTOOLS , "-m", "host", "validate", "-e", eslMade], out, self), True) #assert the ESL is correctly formated
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
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-x", genE2A], out, self), True)
				#validate pkcs7
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-x", "-p", genE2P], out, self), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-x", genC2A], out, self), True)
					#validate pkcs7
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-x", "-p", genC2P], out, self), True)
			else:
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", genE2A], out, self), True)
				#validate pkcs7
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-p", genE2P], out, self), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", genC2A], out, self), True)
					#validate pkcs7
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", "-p", genC2P], out, self), True)
			#all files besides the one that start with bad should be verified, bad means signed incorrectly
			if i[0].startswith("bad"):
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A], out, self), False)
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A], out, self), False)
			else:
				self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A], out, self), True)
				if not i[0].startswith("empty"):
					self.assertEqual( getCmdResult([SECTOOLS, "-m", "host",  "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A], out, self), True)
 
		#now test custom timestamp works
		customTSAuth1 = OUTDIR+"db_by_PK_customTS1.auth"
		customTSAuth2 = OUTDIR+"db_by_PK_customTS2.auth"
		self.assertEqual( getCmdResult(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth1, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:2:8" ], out, self), True) 
		time.sleep(4)
		self.assertEqual( getCmdResult(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth2, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20T10:2:8" ], out, self), True) 
		self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", customTSAuth1], out, self), True)
		self.assertEqual( getCmdResult([SECTOOLS, "-m", "host", "validate", customTSAuth2], out, self), True)
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
		verifyCommand = [SECTOOLS, "-m", "host", "verify", "-p", inpDir, "-u"]
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

		if OPENSSL or GNUTLS:
			command(['echo' , '"TEST NOT RAN, OPENSSL/GNUTLS BUILDS DO NOT HAVE THIS FEATURE"' ], out, False)
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
		cmd=[SECTOOLS, "-m", "host", "generate", "a:e"]
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


		



if __name__ == '__main__':
        argParser = argparse.ArgumentParser()
        argParser.add_argument("-m", "--memcheck", type=int, help="enable/disable memory leak check")
        argParser.add_argument("-o", "--openssl", type=int, help="enable/disable OPENSSL")
        argParser.add_argument("-g", "--gnutls", type=int, help="enable/disable GNUTLS")
        argParser.add_argument("-s", "--secvarctl", help="set secvarctl tool")
        args = argParser.parse_args()

        if args.memcheck != None:
            MEMCHECK = args.memcheck
        if args.openssl != None:
            OPENSSL = args.openssl
        if args.gnutls != None:
            GNUTLS = args.gnutls
        if args.secvarctl != None:
            SECTOOLS = args.secvarctl
            GEN[0] = args.secvarctl

        del sys.argv[1:]
        createEnvironment()
        setupTestEnv()
        unittest.main()




