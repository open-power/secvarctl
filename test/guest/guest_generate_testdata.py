# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
import subprocess #for commmands
import os #for getting size of file
import sys
import time

#[nameoffile,var,signing var]
variable_by_PK = [
		    ["PK_by_PK","PK","PK"],
		    ["KEK_by_PK","KEK","PK"],
		    ["db_by_PK","db","PK"],
		    ["dbx_by_PK","dbx","PK"],
		    ["grubdb_by_PK","grubdb","PK"],
		    ["grubdbx_by_PK","grubdbx","PK"],
		    ["moduledb_by_PK","moduledb","PK"],
		    ["trustedcadb_by_PK","trustedcadb","PK"],
		    ["sbat_by_PK","sbat","PK"]
                 ]


variable_by_KEK = [
		    ["db_by_KEK","db","KEK"],
		    ["dbx_by_KEK","dbx","KEK"],
		    ["grubdb_by_KEK","grubdb","KEK"],
		    ["grubdbx_by_KEK","grubdbx","KEK"],
		    ["moduledb_by_KEK","moduledb","KEK"],
		    ["trustedcadb_by_KEK","trustedcadb","KEK"],
		    ["sbat_by_KEK","sbat","KEK"]
	          ]

hash_algorithm = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]
x509_hash_algorithm = ["SHA256", "SHA384", "SHA512"]

variables = ["PK", "KEK", "db", "dbx", "grubdb", "grubdbx", "moduledb", "trustedcadb", "sbat"]
sbat_data = ["sbat,1\n", "grub,1\n", "grub.ibm.grub,1\n", "grub.fedora,1"]
SBAT_name = "sbat"

test_dir = ["./testdata/eslfiles/", "./testdata/authfiles/", "./testdata/x509certs/",
            "./testdata/goldenkeys/", "./testdata/pkcs7files/"]

cert_to_esl = "c:e"
file_to_esl = "f:e"
cert_to_auth = "c:a"
file_to_auth = "f:a"
force = "-f"
non_force = ""
auth_reset = "reset"
log_dir = "./log"

if len(sys.argv)>1:
	secvarctl = [sys.argv[1]]
else:
	secvarctl = ["../../secvarctl-cov"]

secvarctl = secvarctl + ["-m", "guest", "generate"]

def command (args, err=None, out=None):#stores last log of function into log file
		return subprocess.call (args, stderr=err, stdout=out)

def create_environments ():
	command (["mkdir", "-p", log_dir])
	with open ("./log/genlog.txt", "w") as f:
		for directory in test_dir:
		        command (["mkdir", "-p", directory], f, f)
		for var_name in variables:
			command (["mkdir", "-p", test_dir[3] + var_name], f, f)

def convert_pem_to_Der (pem_cert_file, der_cert_file):
	command ([ "openssl", "x509", "-outform", "der", "-in", pem_cert_file, "-out", der_cert_file])

def generate_x509_cert (priv="default.key",pub="default.crt",crtType="-x509",rsa="rsa:2048", sha="-sha256", nodes="-nodes",subj="/C=NC/O=testing corp" ):
	command (["openssl", "req", "-new" ,crtType ,"-newkey", rsa, "-keyout",priv, "-out", pub,nodes, sha, "-subj",subj])
	convert_pem_to_Der (pub, pub[:-4] + ".der")
	return

def generate_esl (variable_name, format_type, cert_file, esl_file):
	command (secvarctl + [format_type, "-i", cert_file, "-o", esl_file, "-n", variable_name])

def generate_auth (variable_name, signer_key_file, signer_cert_file, cert_file, auth_file, format_type, enforce = ""):
	time.sleep (1)
	cmd = [format_type, "-k", signer_key_file, "-c", signer_cert_file, "-n", variable_name, "-i", cert_file, "-o", auth_file]
	if enforce == force:
		cmd = cmd + [force]
	command (secvarctl + cmd)

def generate_pkcs7 (input_file, output_file, sign_cert, sign_key, hash_algo):
	command (["openssl", "cms", "-sign", "-binary", "-in", input_file , "-signer", sign_cert, "-inkey", sign_key, "-out", output_file, "-noattr", "-outform", "DER", "-md", hash_algo])

def create_sbat_file (sbat_file):
	with open (sbat_file, "w") as f:
	        for data in sbat_data:
	                f.write (data);

def create_size_file (data_file, size_file):
	size = os.path.getsize (data_file)
	with open (size_file, "w") as f:
		f.write (str (size));
		f.close ();

def add_timestamp (esl_file, data_file):
	file_object = open (data_file, 'wb')
	t=time.gmtime()
	file_object.write((0).to_bytes(1,byteorder=sys.byteorder))
	file_object.write((t.tm_year).to_bytes(2,byteorder=sys.byteorder))
	file_object.write((t.tm_mon).to_bytes(1,byteorder=sys.byteorder))
	file_object.write((t.tm_mday).to_bytes(1,byteorder=sys.byteorder))
	file_object.write((t.tm_hour).to_bytes(1,byteorder=sys.byteorder))
	file_object.write((t.tm_min).to_bytes(1,byteorder=sys.byteorder))
	file_object.write((t.tm_sec).to_bytes(1,byteorder=sys.byteorder))
	file_object.close()
	os.system("cat " + esl_file + " >> " + data_file)
	os.system("rm -rf " + esl_file)

def create_goldenkey_files ():

	for var_name in variables:#generate valid pub and private keys
		esl_file = test_dir[3] + var_name + "/esldata"
		data_file = test_dir[3] + var_name + "/data"
		update_file = test_dir[3] + var_name + "/update"
		size_file = test_dir[3] + var_name + "/size"

		if var_name == SBAT_name:
		        cert_file = test_dir[3] + var_name + "/" + var_name + ".csv"
		        create_sbat_file (cert_file)
		        format_type = file_to_esl
		else:
		        format_type = cert_to_esl
		        key_file = test_dir[3] + var_name + "/" + var_name + ".key"
		        cert_file = test_dir[3] + var_name + "/" + var_name + ".crt"
		        generate_x509_cert (key_file, cert_file)

		generate_esl (var_name, format_type, cert_file, esl_file)
		add_timestamp (esl_file, data_file)
		command (["touch", update_file])
		create_size_file (data_file, size_file)

def create_pkcs7_files ():

	for hash_alg in hash_algorithm:
	        for var_by_PK in variable_by_PK:
		        if var_by_PK[1] != SBAT_name and hash_alg == "SHA256":
		                pkcs7_file = test_dir[4] + hash_alg + "_" + var_by_PK[0] + ".pkcs7"
		                key_file = test_dir[2] + var_by_PK[2] + ".key"
		                cert_file = test_dir[2] + var_by_PK[2] + ".crt"
		                var_cert_file = test_dir[2] + var_by_PK[0] + ".crt"
		                generate_pkcs7 (var_cert_file, pkcs7_file, cert_file, key_file, hash_alg)

	        for var_by_KEK in variable_by_KEK:
		        if var_by_KEK[1] != SBAT_name and hash_alg == "SHA256":
		                pkcs7_file = test_dir[4] + hash_alg + "_" + var_by_KEK[0] + ".pkcs7"
		                key_file = test_dir[2] + var_by_KEK[2] + ".key"
		                cert_file = test_dir[2] + var_by_KEK[2] + ".crt"
		                var_cert_file = test_dir[2] + var_by_KEK[0] + ".crt"
		                generate_pkcs7 (var_cert_file, pkcs7_file, cert_file, key_file, hash_alg)

def create_x509_cert_files ():

	for var_name in variables:
		if var_name == SBAT_name:
		        cert_file = test_dir[2] + var_name + ".csv"
		        create_sbat_file (cert_file)
		else:
		        key_file = test_dir[2] + var_name + ".key"
		        cert_file = test_dir[2] + var_name + ".crt"
		        generate_x509_cert (key_file, cert_file)

	for var_by_PK in variable_by_PK:
		if var_by_PK[1] != SBAT_name:
		        key_file = test_dir[2] + var_by_PK[0] + ".key"
		        cert_file = test_dir[2] + var_by_PK[0] + ".crt"
		        generate_x509_cert (key_file, cert_file)

	for var_by_KEK in variable_by_KEK:
		if var_by_KEK[1] != SBAT_name:
		        key_file = test_dir[2] + var_by_KEK[0] + ".key"
		        cert_file = test_dir[2] + var_by_KEK[0] + ".crt"
		        generate_x509_cert (key_file, cert_file)

def create_esl_files ():

	for var_name in variables:
		esl_file = test_dir[0] + var_name + ".esl"

		if var_name == SBAT_name:
		        cert_file = test_dir[2] + var_name + ".csv"
		        format_type = file_to_esl
		else:
		        format_type = cert_to_esl
		        key_file = test_dir[2] + var_name + ".key"
		        cert_file = test_dir[2] + var_name + ".crt"

		generate_esl (var_name, format_type, cert_file, esl_file)

def create_auth_files ():

	for var_by_PK in variable_by_PK:
		auth_file = test_dir[1] + var_by_PK[0] + ".auth"
		PK_key_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".key"
		PK_cert_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".crt"

		if var_by_PK[1] == SBAT_name:
		        cert_file = test_dir[2] + var_by_PK[1] + ".csv"
		        format_type = file_to_auth
		else:
		        format_type = cert_to_auth
		        cert_file = test_dir[2] + var_by_PK[0] + ".crt"

		generate_auth (var_by_PK[1], PK_key_file, PK_cert_file, cert_file, auth_file, format_type, non_force)

	for var_by_KEK in variable_by_KEK:
		auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
		KEK_key_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".key"
		KEK_cert_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".crt"

		if var_by_KEK[1] == SBAT_name:
		        cert_file = test_dir[2] + var_by_KEK[1] + ".csv"
		        format_type = file_to_auth
		else:
		        format_type = cert_to_auth
		        cert_file = test_dir[2] + var_by_KEK[0] + ".crt"

		generate_auth (var_by_KEK[1], KEK_key_file, KEK_cert_file, cert_file, auth_file, format_type, non_force)

def create_reset_auth_files ():

	format_type = auth_reset
	cert_file = ""
	for var_by_PK in variable_by_PK:
		auth_file = test_dir[1] + auth_reset + "_" + var_by_PK[0] + ".auth"
		PK_key_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".key"
		PK_cert_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".crt"
		generate_auth (var_by_PK[1], PK_key_file, PK_cert_file, cert_file, auth_file, format_type, non_force)

	for var_by_KEK in variable_by_KEK:
		auth_file = test_dir[1] + auth_reset + "_" + var_by_KEK[0] + ".auth"
		KEK_key_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".key"
		KEK_cert_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".crt"
		generate_auth (var_by_KEK[1], KEK_key_file, KEK_cert_file, cert_file, auth_file, format_type, non_force)

create_environments ()
create_goldenkey_files ()
create_x509_cert_files ()
create_pkcs7_files ()
create_esl_files ()
create_auth_files ()
create_reset_auth_files ()
