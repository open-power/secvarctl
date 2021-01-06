import unittest
import subprocess
import os
import filecmp
import sys
MEM_ERR = 101
SECTOOLS="../secvarctl-cov"
SECVARPATH="/sys/firmware/secvar/vars/"
goodAuths=[]
badAuths=[]
goodESLs=[]
goodCRTs=[]
brokenAuths=[]
brokenESLs=[]
brokenCrts=[]
brokenPkcs7s=[]


secvarctlCommands=[
[["--usage"], True],
[["--help"], True],
[["-v"], False],  #no command
[[], False],#no commands
[["foobar"], False]#bad command
]
ppcSecVarsRead=[
[["-p","6", "read"], True], #print log correct
[["read"], True],
[["read", "-v"], True], [["read", "-r"], True], #verbose and raw
[["read", "badVarname"], False], #bad var name
]
#=[[command], return expected]
readCommands=[
	
	[["-p","./testenv/"], True], #no args and change path 
	[["-f", "./testenv/PK/data"], True], #give esl file
	[["-p","./testenv/","PK"], True],[["-p","./testenv/","KEK"], True],
	[["-p","./testenv/","db"], True],[["-p","./testenv/","dbx"], True],#print only PK, KEK,and dbx
	[["--usage"], True],[["--help"], True], #usage and help
	[["-f", "./testenv/db/data", "-r"], True],#print raw data from file
	[["-p", "./testenv/", "-r"], True], #print raw data from current vars

	[["-p", "."], False],#bad path
	[["-f", "./testdata/db_by_PK.auth"], False],#given authfile instead of esl
	[["-p"], False], #only -p no path
	[["-f"], False],#only -f no file
	[["-f","-p","-f"], False], #idek but should fail
	[["-f", "foo"], False], #fake file should fail


]
verifyCommands=[
[["--usage"], True],[["--help"], True],
[["-c", "PK","./testenv/PK/data", "-u", "db","./testdata/db_by_PK.auth"], True],#update with current vars set and update set
[["-c", "PK","./testenv/PK/data","KEK","./testenv/KEK/data","db","./testenv/db/data","-u", "db","./testdata/db_by_PK.auth", "KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/PK_by_PK.auth" ], True], #update chain with given current vars set
[["-p","./testenv/","-u", "db","./testdata/db_by_PK.auth", "KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/PK_by_PK.auth" ], True], #update chain with path set
[["-p", "./testenv/", "-u", "db", "./testdata/db_by_PK.auth", "db", "./testdata/db_by_KEK.auth"], True], #submit newer update after older
[["-c", "PK","./testenv/PK/data", "KEK", "./testenv/KEK/foo", "-u", "db","./testdata/db_by_PK.auth"], True],#KEK bad path, should continue
[["-p","./testenv/", "-u", "db", "./testdata/brokenFiles/1db_by_PK.auth","KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/PK_by_PK.auth" ], False], #update chain with one broken auth file should fail
[["-p","./testenv/", "-u", "db", "./testdata/db_by_PK.auth","KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/bad_PK_by_db.auth" ], False], #update chain with one improperly signed auth file should fail
[["-u" ,"db", "./testdata/db_by_PK.auth","-p"], False], #no path given, should fail
[["-c","-u"], False],#no vars given
[["-c","PK","./testenv/PK/data"], False],#no updates given
[["-p", "./testenv", "-u", "db", "./testdata/db_by_KEK.auth", "db", "./testdata/db_by_PK.auth"], False], #submit older update after newer
[["-p","./testenv/","-u",  "KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/PK_by_PK.auth","db","./testdata/db_by_PK.auth" ], False],#update chain with bad order
[["-v"], False], #verify no args
[["-u", "db", "notRealFile.auth"], False], #not real file
[["-u", "./testenv/db_by_PK.auth", "db"], False],#wrong order
[["-u", "PK"], False],#no file given
[["-v", "-w", "-c", "PK","./testenv/PK/data","KEK","./testenv/KEK/data","db","./testenv/db/data","-u", "db","./testdata/db_by_PK.auth", "KEK", "./testdata/KEK_by_PK.auth", "PK", "./testdata/PK_by_PK.auth" ], False],#no where to write it too so should fail
[["-p", "./testenv/", "-u", "TS", "testdata/db_by_KEK.auth"], False], #cannot update TS variable, Its illegal, dont do it...ever
[["-c", "PK","./testenv/PK/data", "-u", "db","./testdata/db_by_PK.auth","-u", "KEK","./testdata/KEK_by_PK.auth"], False],#update vars set twice
[["-c", "PK","./testenv/PK/data", "./testenv/KEK/data", "KEK", "-u", "db","./testdata/db_by_PK.auth"], False],#current vars bad format 
[["-c", "PK", "KEK", "./testenv/PK/data", "./testenv/KEK/data", "-u", "db","./testdata/db_by_PK.auth"], False],#current vars bad format 
[["-c", "PK", "./testenv/PK/data", "KEK", "-u", "db","./testdata/db_by_PK.auth"], False],#current vars bad format 




]
writeCommands=[
[["--usage"], True],[["--help"], True],
[["KEK","./testdata/KEK_by_PK.auth", "-p", "./testenv/"], True], #different ordering should still work
[["KEK","./testdata/KEK_by_PK.auth", "-p", "./testenv/","-v"], True], #different ordering should still work with verbose
[["TS", "./testdata/KEK_by_PK.auth", "-p", "./testenv/"], False], #no TS varible updates allowed
[["db", "foo.file"], False], #bad auth file 
[["KEK","-v", "-p", "./testenv/"], False], #should fail, no file
[["KEK","./testdata/KEK_by_PK.auth", "-p"], False],#no path should fail
[["KeK","./testdata/KEK_by_PK.auth", "-p", "./testenv/"], False], #bad var name should fail
[["KEK","./testdata/KEK_by_PK.auth", "-p", "./testenvironement/"], False], #bad path should fail
[["db"], False], #no authfile
[[], False]#no auth or var

]
validateCommands=[
[["--usage"], True],[["--help"], True],
[["-v"], False],#no input file
[["thisDontExist.auth"], False],#nonexistent file
[["-e"], False], #no esl
[["-c"], False], # no crt
[["-p"], False],#no pkcs7
[["-p","./testdata/db_by_PK.auth"], False],#give auth as pkcs7
]
toeslCommands=[
[["-i", "-o", "out.esl"], False],#no input file
[["-i", "./testdata/db_by_PK.auth", "-o"], False],#no output file
[["-i", "./testdata/db_by_PK.auth"], False],#no output option
]
badEnvCommands=[ #[arr command to skew env, output of first command, arr command for sectool, expected result]
[["rm", "./testenv/KEK/size"],None,["read", "-p", "./testenv/", "KEK"], False], #remove size and it should fail
[["rm", "./testenv/KEK/size"],None,["read", "-p", "./testenv/"], True], #remove size but as long as one is readable then it is ok
[['echo', '"hey fail!"'],"./testenv/db/size",["read", "-p", "./testenv/", "db"], False], #read from ascii size file should fail
[["dd" , "if=./testdata/goldenKeys/KEK/data", "of=./testenv/KEK/data", "count=100", "bs=1"],"log.txt",["verify", "-v","-p", "./testenv/", "-u","db", "./testdata/db_by_KEK.auth"], False], #verify against path with bad esl files should fail, modified THAT SHOULD NEVER HAPPEN!
[["rm", "-r", "./testenv/db","./testenv/dbx","./testenv/KEK","./testenv/PK", "./testenv/TS" ],None,["verify","-v","-p", "./testenv/","-u","PK", "./testdata/PK_by_PK.auth"], True],# no data in path should enter setup mode
[["cp","./testdata/brokenFiles/empty.esl" ,"./testenv/PK/data" ],None,["verify","-v","-p", "./testenv/","-u","PK", "./testdata/PK_by_PK.auth"], True],# no data in pk ==setup mode
[["rm","./testenv/db/update"],None,["verify","-v","-w","-p", "./testenv/","-u","db", "./testdata/db_by_PK.auth"], False],# no update file should exit
[["cp","./testdata/brokenFiles/empty.esl" ,"./testenv/PK/data" ],None,["read","-p", "./testenv/"], True],# Pk will be empty but other files will have things
[["cp","./testdata/brokenFiles/empty.esl" ,"./testenv/PK/data" ],None,["read","-p", "./testenv/", "PK"], False],# Pk will be empty, nothing else read so overall failure
[["echo", "16"], "./testenv/TS/size", ["verify", "-v" , "-p", "./testenv/", "-u", "PK", "./testdata/PK_by_PK.auth"], False],
]

def command(args, out=None):#stores last log of function into log file
	if out:
		#if memory tests being done, use valgrind as well	
		with open(out, "w") as f:
			f.write("\n\n**********COMMAND RAN: $"+ ' '.join(args) +"\n")
			result = subprocess.call(args, stdout=f , stderr=f)
			f.close()
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
	command(["cp", "-a", "./testdata/goldenKeys/.", "testenv/"], out)
def setupArrays():
	for file in os.listdir("./testdata"):
		if file.endswith(".auth"):
			if file.startswith("bad_"):
				fileName=file[4:-5];
				arr=fileName.split("_")
				badAuths.append([file,arr[0],arr[2]]) #[filename, keyname,keysigner]
			elif file.startswith("empty_"):
				#auths with noESL are key delete updates, perfectly valid, add to goodauths
				fileName = file[6:-5]
				arr=fileName.split("_")
				goodAuths.append([file, arr[0],arr[2]])
			else:
				fileName=file[:-5];
				arr=fileName.split("_")
				goodAuths.append([file,arr[0],arr[2]])
		elif file.endswith(".esl") and not file.startswith("empty"):
			if not file.startswith("bad"):
				fileName=file[:-4];
				arr=fileName.split("_")
				goodESLs.append([file,arr[0],arr[2]])
		elif file.endswith(".der"):
			if not file.startswith("bad"):
				fileName=file[:-4]
				arr=fileName.split("_")
				goodCRTs.append([file,arr[0],arr[2]])
		elif file.endswith(".crt"):
			if not file.startswith("bad"):
				fileName=file[:-4]
				arr=fileName.split("_")
				goodCRTs.append([file,arr[0],arr[2]])
	for file in os.listdir("./testdata/brokenFiles"): #sort broken files into esl's crts and auths
		if file.endswith(".esl"):
			brokenESLs.append("./testdata/brokenFiles/"+file)
		elif file.endswith(".der") or file.endswith(".crt"):
			brokenCrts.append("./testdata/brokenFiles/"+file)
		elif file.endswith(".auth"):
			brokenAuths.append("./testdata/brokenFiles/"+file)
		elif file.endswith(".pkcs7"):
			brokenPkcs7s.append("./testdata/brokenFiles/"+file)
def compareFiles(a,b):
		if filecmp.cmp(a,b):
			return True
		return False

class Test(unittest.TestCase):
	def test_secvarctl_basic(self):
		out="secvarctlBasiclog.txt"
		cmd=[SECTOOLS]
		for i in secvarctlCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
	def test_ppcSecVarsRead(self):
		out="ppcSecVarsReadlog.txt"
		cmd=[SECTOOLS]
		#if power sysfs exists read current keys
		if os.path.isdir(SECVARPATH):
			for i in ppcSecVarsRead:
				self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		else:
			with open(out, "w") as f:
				f.write("POWER SECVAR LOCATION ( "+ SECVARPATH  + " ) DOES NOT EXIST SO NO TESTS RAN\n")
				f.close();

	def test_verify(self):
		out="verifylog.txt"
		cmd=[SECTOOLS, "verify"]
		for fileInfo in goodAuths:
			file="./testdata/"+fileInfo[0]
			self.assertEqual( getCmdResult(cmd+[ "-w", "-p", "testenv/","-u",fileInfo[1],file],out, self), True)#verify all auths are signed by keys in testenv
			self.assertEqual(compareFiles("testenv/"+fileInfo[1]+"/update", file), True)#assert files wrote correctly
		for fileInfo in badAuths:
			file="./testdata/"+fileInfo[0]
			self.assertEqual( getCmdResult(cmd+[ "-p", "testenv/","-u",fileInfo[1],file],out, self), False)#verify all bad auths are not signed correctly
		for i in verifyCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
	def test_validate(self):
		out="validatelog.txt"
		cmd=[SECTOOLS, "validate"]
		for i in validateCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		for i in goodAuths:		#validate all auths
			file="./testdata/"+i[0]
			if i[1] != "dbx":
				
				self.assertEqual( getCmdResult(cmd+[file],out, self), True)
			else:
				self.assertEqual( getCmdResult(cmd+[file, "-x"],out, self), True)
		for i in goodESLs:
			file="./testdata/"+i[0]
			if i[1] != "dbx":
				file="./testdata/"+i[0]
				self.assertEqual( getCmdResult(cmd+["-e",file],out, self), True)
			else:
				self.assertEqual( getCmdResult(cmd+["-e", file, "-x"],out, self), True)
		for i in goodCRTs:
			file="./testdata/"+i[0]
			self.assertEqual( getCmdResult(cmd+["-v","-c",file],out, self), True)
		for i in brokenAuths:
			self.assertEqual( getCmdResult(cmd+["-v", i],out, self), False)
		for i in brokenESLs:
			self.assertEqual( getCmdResult(cmd+["-v", "-e", i],out, self), False)
		for i in brokenCrts:
			self.assertEqual( getCmdResult(cmd+["-v", "-c", i],out, self), False)
		for i in brokenPkcs7s:
			self.assertEqual( getCmdResult(cmd+["-v", "-p", i],out, self), False)
	def test_read(self):
		out="readlog.txt"
		cmd=[SECTOOLS, "read"]
		#self.assertEqual(not not not command(cmd,out, self), True) #no args
		for i in readCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		for i in brokenESLs:
			#read should read sha and rsa esl's w no problem
			if i.startswith("./testdata/brokenFiles/sha") or i.startswith("./testdata/brokenFiles/rsa"):
							self.assertEqual( getCmdResult(cmd+["-f", i],out, self), True) 
			else:
				self.assertEqual( getCmdResult(cmd+["-f", i],out, self), False) #all truncated esls should fail to print human readable info
	def test_write(self):
		out="writelog.txt"
		cmd=[SECTOOLS,"write"]
		path="./testenv/"
		for i in writeCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		for i in goodAuths:	#try write with good auths, validation included
			file="./testdata/"+i[0]
			preUpdate=file#get auth
			postUpdate=path+i[1]+"/update" #./testenv/<varname>/update
			self.assertEqual( getCmdResult(cmd+[ "-p", path,i[1],file],out, self), True)#assert command runs
			self.assertEqual(compareFiles(preUpdate,postUpdate), True)# assert auths esl is equal to data written to update file
		for i in brokenAuths:
			self.assertEqual( getCmdResult(cmd+["-p", path, "KEK",i],out, self), False)#broken auths should fail
			self.assertEqual( getCmdResult(cmd+["-p", path ,"-f", "KEK",i],out, self), True)#if forced, they should work
			self.assertEqual(compareFiles(i,path+"KEK/update"), True)
	def test_authtoesl(self):
		out="authtoesllog.txt"
		cmd=[SECTOOLS,"generate", "a:e"]
		for i in goodAuths:
			file="./testdata/"+i[0]
			if file.startswith("./testdata/empty"):
				preUpdate = "./testdata/empty.esl"
			else:
				preUpdate=file[:-4]+"esl"#get esl in auth
			postUpdate="testGenerated.esl" #./testenv/<varname>/update
			if file.startswith("./testdata/dbx"):
				self.assertEqual( getCmdResult(cmd+[ "-n",  "dbx", "-i", file, "-o", postUpdate],out, self), True)#assert command runs
			else:
				self.assertEqual( getCmdResult(cmd+[ "-i", file, "-o", postUpdate],out, self), True)#assert command runs
			self.assertEqual(compareFiles(preUpdate,postUpdate), True)
		command(["rm",postUpdate])
		for i in toeslCommands:
			self.assertEqual( getCmdResult(cmd+i[0],out, self),i[1])
		for i in brokenAuths:
			postUpdate="testGenerated.esl" #./testenv/<varname>/update
			self.assertEqual( getCmdResult(cmd+["-i", i, "-o", postUpdate],out, self), False) #all broken auths should fail to have correct esl
			self.assertEqual( getCmdResult(["rm",postUpdate],out, self), False) #removal of output file should fail since it was never made
	def test_badenv(self):
		out="badEnvLog.txt"
		for i in badEnvCommands:
			setupTestEnv()
			command(i[0],i[1])
			self.assertEqual( getCmdResult([SECTOOLS]+i[2],out, self),i[3])
			setupTestEnv()

if __name__ == '__main__':
	if "MEMCHECK" in sys.argv:
	 	MEMCHECK = True
	else: 
	 	MEMCHECK = False
	del sys.argv[1:]
	setupArrays()
	setupTestEnv()
	unittest.main()
    