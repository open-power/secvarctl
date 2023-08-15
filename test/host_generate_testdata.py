# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
import subprocess #for commmands
import os #for getting size of file
import sys
import time

DATAPATH = f"./testdata/host"

#[nameoffile,var,signing var]
goodUpdates=[
		["PK_by_PK","PK","PK"],
		["db_by_PK","db","PK"],
		["db_by_KEK","db","KEK"],
		["KEK_by_PK","KEK","PK"]
			]



badUpdates=[
		["PK_by_db","db","PK"],
		["KEK_by_db", "db", "PK"],
		["db_by_db", "db", "db"]
]
dbxUpdates=[
["dbx_by_PK", "dbx", "PK"],
["dbx_by_KEK", "dbx", "KEK"]
]
variables=["PK","KEK","db", "dbx"]
badCerts=[	#output name, crtType, rsa,sha
["rsa4096", "-x509","rsa:4096","-sha256" ],
["sha384","-x509","rsa:2048","-sha384"],
["sha512","-x509","rsa:2048","-sha512"],
]
if len(sys.argv)>1:
	efitools=sys.argv[1]
else:
	efitools=""
	

def command(args, err=None, out=None):#stores last log of function into log file
		# print(args)
		return subprocess.call(args, stderr=err, stdout=out)
def createEnvironment():
	with open("log.txt", "w") as f:
		command(["mkdir", f"{DATAPATH}"],f,f)
		command(["mkdir", "./testenv/host/"],f,f)
		command(["mkdir", f"{DATAPATH}/goldenKeys"],f,f)
		command(["mkdir", f"{DATAPATH}/brokenFiles"],f,f)
		for i in variables:
			command(["mkdir" ,f"{DATAPATH}/goldenKeys/"+i],f,f)

def pemToDer(path=f"{DATAPATH}",inp="default.crt",out="default.der"):
	command([ "openssl", "x509", "-outform", "der", "-in", path+inp, "-out" ,path+out])

def generateX509(path=f"{DATAPATH}/",priv="default.key",pub="default.crt",crtType="-x509",rsa="rsa:2048", sha="-sha256", nodes="-nodes",subj="/C=NC/O=testing corp" ):
	command(["openssl", "req", "-new" ,crtType ,"-newkey", rsa, "-keyout",path+priv, "-out", path+pub,nodes, sha, "-subj",subj])
	pemToDer(path,pub,pub[:-4]+".der")
	return

def generateESL(path=f"{DATAPATH}/",inp="default.crt",out="default.esl"):
	command([efitools+"cert-to-efi-sig-list", path+inp, path+out])

def createSizeFile(path):
	size=os.path.getsize(path+"data")
	with open(path+"size", "w") as f:
		f.write(str(size));

def generateHashESL(path=f"{DATAPATH}/", inp="dbx.crt", out="dbx.esl"):
	# command(["openssl", "dgst", "-sha256", "-binary", "-out", path+out+"hash", path+inp]) #we now know hash is done internally
	command([efitools+"hash-to-efi-sig-list-modified", path+inp, path+out])

def createDbx():
	path=f"{DATAPATH}/goldenKeys/dbx/"
	generateHashESL(path=path, inp="dbx.crt", out="data")
	createSizeFile(path)
def createGoldenFiles():
	for i in variables:#generate valid pub and private keys
		generateX509(f"{DATAPATH}/goldenKeys/"+i+"/",i+".key",i+".crt")
		generateESL(f"{DATAPATH}/goldenKeys/"+i+"/", i+".crt", "data")
		command(["touch", f"{DATAPATH}/goldenKeys/"+i+"/update"])
		createSizeFile(f"{DATAPATH}/goldenKeys/"+i+"/")
	createDbx()
def createTS():
	path=f"{DATAPATH}/goldenKeys/"
	command(["mkdir", path+"TS"])
	command(["touch", path+"TS/data"])
	command(["touch", path+"TS/update"])
	file_object = open(path+"TS/data", 'wb')
	for i in variables:
		t=time.localtime(os.path.getmtime(path+i+"/data"))
		file_object.write((t.tm_year).to_bytes(2,byteorder=sys.byteorder))
		file_object.write((t.tm_mon).to_bytes(1,byteorder=sys.byteorder))
		file_object.write((t.tm_mday).to_bytes(1,byteorder=sys.byteorder))
		file_object.write((t.tm_hour).to_bytes(1,byteorder=sys.byteorder))
		file_object.write((t.tm_min).to_bytes(1,byteorder=sys.byteorder))
		file_object.write((t.tm_sec).to_bytes(1,byteorder=sys.byteorder))
		file_object.write((0).to_bytes(9,byteorder=sys.byteorder))


	file_object.close()
	createSizeFile(path+"TS/")

def generateAuth(var,signer,out="default.auth",path=f"{DATAPATH}/", inp="default.esl"):
	time.sleep(1)
	command([efitools+"sign-efi-sig-list", "-k", f"{DATAPATH}/goldenKeys/"+signer+"/"+signer+".key","-c", f"{DATAPATH}/goldenKeys/"+signer+"/"+signer+".crt",var, path+inp,path+out])
def generatePKCS7(inp, out, signCrt, signKey, hashAlg):
	command(["openssl", "cms", "-sign", "-binary", "-in", inp ,"-signer", signCrt, "-inkey", signKey, "-out", out,"-noattr", "-outform", "DER", "-md", hashAlg])

	
def createUpdates():
	for i in goodUpdates:
		generateX509(priv=i[0]+".key",pub=i[0]+".crt")
		generateESL(inp=i[0]+".crt", out=i[0]+".esl")
		generateAuth(i[1],i[2],i[0]+".auth",inp=i[0]+".esl")
	for i in badUpdates:
		generateX509(priv="bad_"+i[0]+".key",pub="bad_"+i[0]+".crt")
		generateESL(inp="bad_"+i[0]+".crt", out="bad_"+i[0]+".esl")
		generateAuth(i[1],i[2],"bad_"+i[0]+".auth",inp="bad_"+i[0]+".esl")
	for i in dbxUpdates:
		generateX509(priv=i[0]+".key",pub=i[0]+".crt")
		generateHashESL(inp=i[0]+".crt", out=i[0]+".esl")
		generateAuth(i[1],i[2],i[0]+".auth", inp=i[0]+".esl")
def createTruncatedFiles():
	path=f"{DATAPATH}/"
	outPath=path+"brokenFiles/"
	for i in goodUpdates:
		count=0
		auth=i[0]+".auth"
		der=i[0]+".der"
		crt=i[0]+".crt"
		esl=i[0]+".esl"
		crtSize=os.path.getsize(path+crt)
		derSize=os.path.getsize(path+der)
		eslSize=os.path.getsize(path+esl)
		authSize=os.path.getsize(path+auth)
		count+=1
		command(["dd", "if="+path+auth,"of="+outPath+str(count)+auth, "count="+str(authSize-derSize), "bs=1"])#remove crtificate from auth, saved as 1-----.auth
		count+=1
		command(["dd", "if="+path+auth,"of="+outPath+str(count)+auth, "count="+str(authSize-1), "bs=1"])#remove last byte from auth, saved as 2---.auth
		count+=1
		command(["dd", "if="+path+auth,"of="+outPath+str(count)+auth, "count="+str(int(authSize/2)), "bs=1"])#remove half bytes from auth, saved as 3---.auth
		count+=1
		command(["dd", "if="+path+esl,"of="+outPath+str(count)+esl, "count="+str(eslSize-derSize), "bs=1"])#remove cert from esl, saved as 4---.esl
		count+=1
		command(["dd", "if="+path+esl,"of="+outPath+str(count)+esl, "count="+str(eslSize-1), "bs=1"])#remove last byte from esl, saved as 5---.esl
		count+=1
		command(["dd", "if="+path+esl,"of="+outPath+str(count)+esl, "count="+str(int(eslSize/2)), "bs=1"])#remove half bytes from esl, saved as 6---.esl
		count+=1
		command(["dd", "if="+path+der,"of="+outPath+str(count)+der, "count="+str(derSize-1), "bs=1"])#remove last byte from der crt, saved as 7---.der
		count+=1
		command(["dd", "if="+path+der,"of="+outPath+str(count)+der, "count="+str(int(derSize/2)), "bs=1"])#remove half data from der crt, saved as 8.der
		count+=1
		command(["dd", "if="+path+auth,"of="+outPath+str(count)+auth, "count="+str(50), "bs=1"])#remove everything besides auth header and some pkcs7data, saved as 9---.auth
		count+=1
		command(["dd", "if="+path+crt,"of="+outPath+str(count)+crt, "count="+str(crtSize-20), "bs=1"])#remove 20 bytes from crt, saved as 10---.der
		count+=1
		command(["dd", "if="+path+der,"of="+outPath+str(count)+crt, "count="+str(int(crtSize/2)), "bs=1"])#remove half data from  crt, saved as 11.der
		count+=1
	command(["touch" ,outPath+"empty.crt"])#make empty files
	command(["touch" ,outPath+"empty.der"])
	command(["touch" ,outPath+"empty.auth"])
	command(["touch" ,outPath+"empty.esl"])


def createBadCerts():
	path=f"{DATAPATH}/brokenFiles/"
	for i in badCerts:
		#output name, crtType, rsa,sha
		generateX509(path=path,pub=i[0]+".crt",priv=i[0]+".key", crtType=i[1], rsa=i[2],sha=i[3])
		generateESL(path=path,inp=i[0]+".crt", out=i[0]+".esl")
		generateAuth(path=path,var="db",signer="PK",out=i[0]+".auth",inp=i[0]+".esl")
def createEmptyAuths():
	path = f"{DATAPATH}/"
	command(["touch", path+"empty.esl"])
	for i in goodUpdates:
		generateAuth(i[1],i[2],"empty_"+i[0]+".auth",inp="empty.esl")
def createBrokenPKCS7():
	path = f"{DATAPATH}/brokenFiles/"
	inp = f"{DATAPATH}/db_by_PK.crt"
	signCrt = f"{DATAPATH}/goldenKeys/PK/PK.crt"
	signKey = f"{DATAPATH}/goldenKeys/PK/PK.key"
	hashFunct = ["SHA512", "SHA1", "SHA384"]
	for i in hashFunct:
		out = path+i+".pkcs7"
		generatePKCS7(inp, out, signCrt, signKey, i)
	for i in badCerts:
		out = path+"signedWith_"+i[0]+".pkcs7"
		signCrt = path+i[0]+".crt"
		signKey =  path+i[0]+".key"
		hashFunct= "SHA256"
		generatePKCS7(inp, out, signCrt, signKey, hashFunct)





def createBrokenFiles():
	createTruncatedFiles()
	createBadCerts()
	createEmptyAuths()
	createBrokenPKCS7()
	

		
createEnvironment()
createGoldenFiles()
createTS()
createUpdates()
createBrokenFiles()


