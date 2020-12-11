#NEEDS ASSERTS AND TEST CASES TO BE ADDED!!!
#These tests will use sectool's validate command to determine wether the file was correctly generated.
#We can use the validate command because it was previously tested in runTests.py
import subprocess #for commmands
import os #for getting size of file
import sys
import time
import unittest
import filecmp

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
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "10:2:20", "2020-10-20"], False], #Wrong timestamp order
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-50-20", "10:2:20" ], False], #bad month
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-200", "10:2:20" ], False], #bad day
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20", "25:2:20" ], False], #bad hour
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20", "10:61:20" ], False], #bad minute
[["e:a", "-i", "./testdata/db_by_PK.esl", "-o", OUTDIR+"foo.auth", "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20", "10:2:61" ], False], #bad sec
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

def command(args,out=None):#stores last log of function into log file
		if out:
			with open(out, "w") as f:
				f.write("\n\n**********COMMAND RAN: $"+ ' '.join(args) +"\n")
				result=subprocess.call(args,stdout=f , stderr=f)
				f.close();
				return result


		return subprocess.call(args,stdout=out , stderr=out)
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
			return 0
		return 1
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
			self.assertEqual( not not not command(cmd+i[0],out),i[1])
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
			self.assertEqual( not not not command(cmd + ["f:h", "-i", "./testdata/" + efiGen + ".crt", "-o" ,hashMade], out), True) #assert the hashfile can be made
			self.assertEqual( not not not command(cmd + ["h:e", "-i", hashMade, "-o" , eslMade], out), True) #assert the ESL is valid
			self.assertEqual( not not not command([SECTOOLS ,"validate", "-e", "-x", eslMade], out), True) #assert the ESL is correctly formated
			# self.assertEqual( not not not compareFiles(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
			#then do it with the file to ESL (hash generation done internally)
			self.assertEqual( not not not command(cmd + ["f:e", "-i", "./testdata/" + efiGen + ".crt", "-o" ,eslMade], out), True) #assert the esl can be made from a file
			self.assertEqual( not not not command([SECTOOLS ,"validate", "-e", "-x", eslMade], out), True) #assert the ESL is correctly formated
			# self.assertEqual( not not not compareFiles(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
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
				self.assertEqual( not not not command(cmd + ["c:e", "-i", "./testdata/" + efiGen + ".crt", "-o" , eslMade], out), True) #assert the hashfile can be made
				self.assertEqual( not not not command([SECTOOLS ,"validate", "-e", eslMade], out), True) #assert the ESL is correctly formated
				self.assertEqual( not not not compareFiles(eslMade, eslDesired), True) #make sure the generated file is byte for byte the same as the one we know is correct
			for i in badESLcommands:
				self.assertEqual( not not not command(cmd + i[0], out), i[1]) 
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
				self.assertEqual( not not not command(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2A ], out), False)
				self.assertEqual( not not not command(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2A, "-f"], out), True)
				#build PKCS7 as well
				self.assertEqual( not not not command(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2P ], out), False)
				self.assertEqual( not not not command(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o", genE2P, "-f"], out), True)
			else:
				esl = "./testdata/"+fileBaseName+".esl"
				cert = "./testdata/"+fileBaseName+".crt"
				self.assertEqual( not not not command(cmd + ["e:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o",  genE2A], out), True)
				#build pkcs7
				self.assertEqual( not not not command(cmd + ["e:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", esl, "-o",  genE2P], out), True)
				#build auth/pkcs7 from certs
				if i[1] == "dbx":
					self.assertEqual( not not not command(cmd + ["f:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2A], out), True)
					#build pkcs7
					self.assertEqual( not not not command(cmd + ["f:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2P], out), True)
				else:
					self.assertEqual( not not not command(cmd + ["c:a", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2A], out), True)
					#build pkcs7
					self.assertEqual( not not not command(cmd + ["c:p", "-k", signerKey, "-c", signerCrt, "-n", i[1], "-i", cert, "-o",  genC2P], out), True)

			#all files should be valid format, check if dbx though
			if i[1] =="dbx":
				self.assertEqual( not not not command([SECTOOLS, "validate", "-x", genE2A], out), True)
				#validate pkcs7
				self.assertEqual( not not not command([SECTOOLS, "validate", "-x", "-p", genE2P], out), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( not not not command([SECTOOLS, "validate", "-x", genC2A], out), True)
					#validate pkcs7
					self.assertEqual( not not not command([SECTOOLS, "validate", "-x", "-p", genC2P], out), True)
			else:
				self.assertEqual( not not not command([SECTOOLS, "validate", genE2A], out), True)
				#validate pkcs7
				self.assertEqual( not not not command([SECTOOLS, "validate", "-p", genE2P], out), True)
				#validate auth/pkcs7 from certs
				if not i[0].startswith("empty"):
					self.assertEqual( not not not command([SECTOOLS, "validate", genC2A], out), True)
					#validate pkcs7
					self.assertEqual( not not not command([SECTOOLS, "validate", "-p", genC2P], out), True)
			#all files besides the one that start with bad should be verified, bad means signed incorrectly
			if i[0].startswith("bad"):
				self.assertEqual( not not not command([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A],out), False)
				if not i[0].startswith("empty"):
					self.assertEqual( not not not command([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A],out), False)
			else:
				self.assertEqual( not not not command([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genE2A],out), True)
				if not i[0].startswith("empty"):
					self.assertEqual( not not not command([SECTOOLS, "verify", "-p", "./testdata/goldenKeys/", "-u", i[1], genC2A],out), True)
 
		#now test custom timestamp works
		customTSAuth1 = OUTDIR+"db_by_PK_customTS1.auth"
		customTSAuth2 = OUTDIR+"db_by_PK_customTS2.auth"
		self.assertEqual( not not not command(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth1, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20", "10:2:8" ], out), True) 
		time.sleep(4)
		self.assertEqual( not not not command(cmd+ ["e:a", "-i", "./testdata/db_by_PK.esl", "-o", customTSAuth2, "-k", "./testdata/goldenKeys/PK/PK.key", "-c", "./testdata/goldenKeys/PK/PK.crt", "-n", "db", "-t", "2020-10-20", "10:2:8" ],out), True) 
		self.assertEqual( not not not command([SECTOOLS, "validate", customTSAuth1], out), True)
		self.assertEqual( not not not command([SECTOOLS, "validate", customTSAuth2], out), True)
		self.assertEqual( not not not compareFiles(customTSAuth1, customTSAuth2), True)

		#now test incorrect generate commands
		for i in badSignedCommands:
			self.assertEqual( not not not command(cmd + i[0], out), i[1])
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
		for function in hashes:
			inpDir = "./testdata/"
			for file in os.listdir(inpDir):
			 	outFile = OUTDIR+function[0]+"_"+file+".hash"
			 	if file.endswith(".auth"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( not not not command(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		else:
			 			self.assertEqual( not not not command(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
			 	elif file.endswith(".esl") and not file.startswith("empty"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( not not not command(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		else:
			 			self.assertEqual( not not not command(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
			 	elif file.endswith(".crt"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( not not not command(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		else:
			 			self.assertEqual( not not not command(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), True)
			 		self.assertEqual(os.path.getsize(outFile), function[1])
			inpDir = "./testdata/brokenFiles/"
			#these should all fail unless forced
			for file in os.listdir(inpDir):
				outFile = OUTDIR+function[0]+"_"+file+".hash"
				if file.endswith(".auth"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( not not not command(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
			 			self.assertEqual( not not not command(GEN + ["a:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)

			 		else:
			 			self.assertEqual( not not not command(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
			 			self.assertEqual( not not not command(GEN + ["a:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)
			 		self.assertEqual( os.path.getsize(outFile), function[1])
				elif file.endswith(".esl"):
					if file.startswith("dbx"):
						self.assertEqual( not not not command(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
						self.assertEqual( not not not command(GEN + ["e:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)
					else:
			 			self.assertEqual( not not not command(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
			 			self.assertEqual( not not not command(GEN + ["e:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)
					self.assertEqual( os.path.getsize(outFile), function[1])
				elif file.endswith(".crt"):
			 		if file.startswith("dbx"):
			 			self.assertEqual( not not not command(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
			 			self.assertEqual( not not not command(GEN + ["c:h", "-n", "dbx", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)

			 		else:
			 			self.assertEqual( not not not command(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile], out), False)
			 			self.assertEqual( not not not command(GEN + ["c:h", "-h", function[0], "-i", inpDir+file, "-o", outFile, "-f"], out), True)

			 		self.assertEqual( os.path.getsize(outFile), function[1])


		




createEnvironment()
setupTestEnv()
unittest.main()



