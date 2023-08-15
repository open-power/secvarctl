# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
import unittest
import os
import filecmp
import sys
import argparse
from common import SecvarctlTest

SECTOOLS = ["../bin/secvarctl-dbg", "-m", "guest"]
SECVARPATH = "/sys/firmware/secvar/vars/"
DATAPATH = "./testdata/guest"

auth_files = []
esl_files = []
cert_files = []
pkcs7_files =[]

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

reset_variable_by_PK = [
		         ["reset_KEK_by_PK","KEK","PK"],
		         ["reset_db_by_PK","db","PK"],
		         ["reset_dbx_by_PK","dbx","PK"],
		         ["reset_grubdb_by_PK","grubdb","PK"],
		         ["reset_grubdbx_by_PK","grubdbx","PK"],
		         ["reset_moduledb_by_PK","moduledb","PK"],
		         ["reset_trustedcadb_by_PK","trustedcadb","PK"],
		         ["reset_sbat_by_PK","sbat","PK"]
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

reset_variable_by_KEK = [
		          ["reset_db_by_KEK","db","KEK"],
		          ["reset_dbx_by_KEK","dbx","KEK"],
		          ["reset_grubdb_by_KEK","grubdb","KEK"],
		          ["reset_grubdbx_by_KEK","grubdbx","KEK"],
		          ["reset_moduledb_by_KEK","moduledb","KEK"],
		          ["reset_trustedcadb_by_KEK","trustedcadb","KEK"],
		          ["reset_sbat_by_KEK","sbat","KEK"]
	                ]

variables = ["PK", "KEK", "db", "dbx", "grubdb", "grubdbx", "moduledb", "trustedcadb", "sbat"]
test_dir = [f"{DATAPATH}/eslfiles/", f"{DATAPATH}/authfiles/", f"{DATAPATH}/x509certs/",
            f"{DATAPATH}/goldenKeys/", f"{DATAPATH}/pkcs7files/"]

test_env_path = "./testenv/guest/"
log_dir = "./log/"
gen_dir = "./generated-data/"
SBAT_name = "sbat"

auth_type = "-a"
esl_type = "-e"
cert_type = "-c"
pkcs7_type = "-p"
path_type = "-p"
force = "-f"
non_force = ""
non_write = ""
write = "-w"
empty_path = ""
cert_to_esl = "c:e"
file_to_esl = "f:e"
cert_to_auth = "c:a"
file_to_auth = "f:a"
force = "-f"
non_force = ""
auth_reset = "reset"


def collect_test_data ():
	for file in os.listdir (test_dir[0]):
		if file.endswith (".esl"):
			esl_files.append (test_dir[0] + file)
	for file in os.listdir (test_dir[1]):
		if file.endswith (".auth"):
			auth_files.append (test_dir[1] + file)
	for file in os.listdir (test_dir[2]):
		if file.endswith (".cert"):
			cert_files.append (test_dir[2] + file)
	for file in os.listdir (test_dir[4]):
		if file.endswith (".pkcs7"):
			pkcs7_files.append (test_dir[4] + file)

def compare_two_files (a,b):
	if filecmp.cmp (a,b):
		return True
	else:
		return False

def get_read_command (read_type, file_name):
	if read_type == "":
		read_cmd = SECTOOLS + ["read"]
	else:
		read_cmd = SECTOOLS + ["read", read_type, file_name]

	return read_cmd

def get_validate_command (file_type, file_name):
	if file_type == "":
		validate_cmd = SECTOOLS + ["validate"]
	else:
		validate_cmd = SECTOOLS + ["validate", file_type, file_name]

	return validate_cmd

def get_write_command (variable_name, auth_file, var_path, enforce):
	if enforce == force:
		write_cmd = SECTOOLS + ["write", variable_name, auth_file, "-p", var_path, enforce]
	else:
		write_cmd = SECTOOLS + ["write", variable_name, auth_file, "-p", var_path]

	return write_cmd

def get_verify_command (update_variables, current_variables, var_path, enforce_write):
	if enforce_write == write and current_variables == [] and var_path != "":
		verify_cmd = SECTOOLS + ["verify", "-u"] + update_variables + ["-p", var_path, enforce_write]
	elif enforce_write == write and current_variables != [] and var_path == "":
		verify_cmd = SECTOOLS + ["verify", "-u"] + update_variables + ["-c"] + current_variables + [enforce_write]
	elif enforce_write != write and current_variables == [] and var_path != "":
		verify_cmd = SECTOOLS + ["verify", "-u"] + update_variables + ["-p", var_path]
	elif enforce_write != write and current_variables != [] and var_path == "":
		verify_cmd = SECTOOLS + ["verify", "-u"] + update_variables + ["-c"] + current_variables
	else:
		verify_cmd = SECTOOLS + ["verify", "-u"] + update_variables

	return verify_cmd

def generate_esl (variable_name, format_type, cert_file, esl_file):
	gen_cmd = SECTOOLS + ["generate"] + [format_type, "-i", cert_file, "-o", esl_file, "-n", variable_name]
	return gen_cmd

def generate_auth (variable_name, signer_key_file, signer_cert_file, cert_file, auth_file, format_type, enforce = ""):
	gen_cmd = [format_type, "-k", signer_key_file, "-c", signer_cert_file, "-n", variable_name, "-i", cert_file, "-o", auth_file]
	if enforce == force:
		gen_cmd = gen_cmd + [force]
	return SECTOOLS + ["generate"] + gen_cmd

class Test (SecvarctlTest):
	out = "temp"
	log_dir = "./log/"
	test_env_dir = f"{test_env_path}"
	test_data_dir = f"{DATAPATH}"
	
	def setUp(self):
		self.setupTestEnvironment()
		self.command(["mkdir", "-p", gen_dir])
	
	def test_ppcsecvar_path_read (self):
		out = log_dir + "ppcsecvarspathreadlog.txt"
		#if power sysfs exists read current keys
		if os.path.isdir (SECVARPATH):
			cmd = get_read_command ("", "")
			self.assertEqual (self.getCmdResult(cmd, out), True)
		else:
			with open (out, "w") as f:
				f.write ("POWER SECVAR LOCATION ( "+ SECVARPATH  + " ) DOES NOT EXIST SO NO TESTS RAN\n")
				f.close ();

	def test_generate_esl_files (self):
		out = log_dir + "generatelog.txt"
		for var_name in variables:
		        esl_file = gen_dir + var_name + ".esl"

		        if var_name == SBAT_name:
		                cert_file = test_dir[2] + var_name + ".csv"
		                format_type = file_to_esl
		        else:
		                format_type = cert_to_esl
		                key_file = test_dir[2] + var_name + ".key"
		                cert_file = test_dir[2] + var_name + ".crt"

		        cmd = generate_esl (var_name, format_type, cert_file, esl_file)
		        self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_generate_auth_files (self):
		out = log_dir + "generatelog.txt"
		for var_by_PK in variable_by_PK:
		        auth_file = gen_dir + var_by_PK[0] + ".auth"
		        PK_key_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".key"
		        PK_cert_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".crt"

		        if var_by_PK[1] == SBAT_name:
		                cert_file = test_dir[2] + var_by_PK[1] + ".csv"
		                format_type = file_to_auth
		        else:
		                format_type = cert_to_auth
		                cert_file = test_dir[2] + var_by_PK[0] + ".crt"

		        cmd = generate_auth (var_by_PK[1], PK_key_file, PK_cert_file, cert_file, auth_file, format_type, non_force)
		        self.assertEqual (self.getCmdResult(cmd, out), True)

		for var_by_KEK in variable_by_KEK:
		        auth_file = gen_dir + var_by_KEK[0] + ".auth"
		        KEK_key_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".key"
		        KEK_cert_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".crt"

		        if var_by_KEK[1] == SBAT_name:
		                cert_file = test_dir[2] + var_by_KEK[1] + ".csv"
		                format_type = file_to_auth
		        else:
		                format_type = cert_to_auth
		                cert_file = test_dir[2] + var_by_KEK[0] + ".crt"

		        cmd = generate_auth (var_by_KEK[1], KEK_key_file, KEK_cert_file, cert_file, auth_file, format_type, non_force)
		        self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_generate_reset_auth_files (self):
		out = log_dir + "generatelog.txt"
		format_type = auth_reset
		cert_file = "empty"
		for var_by_PK in variable_by_PK:
		        auth_file = gen_dir + auth_reset + "_" + var_by_PK[0] + ".auth"
		        PK_key_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".key"
		        PK_cert_file = test_dir[3] + var_by_PK[2] + "/" + var_by_PK[2] + ".crt"
		        cmd = generate_auth (var_by_PK[1], PK_key_file, PK_cert_file, cert_file, auth_file, format_type, non_force)
		        self.assertEqual (self.getCmdResult(cmd, out), True)

		for var_by_KEK in variable_by_KEK:
		        auth_file = gen_dir + auth_reset + "_" + var_by_KEK[0] + ".auth"
		        KEK_key_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".key"
		        KEK_cert_file = test_dir[3] + var_by_KEK[2] + "/" + var_by_KEK[2] + ".crt"
		        cmd = generate_auth (var_by_KEK[1], KEK_key_file, KEK_cert_file, cert_file, auth_file, format_type, non_force)
		        self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_read (self):
		out = log_dir + "readlog.txt"
		for cert_file in cert_files:
			cmd = get_read_command (cert_type, cert_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for esl_file in esl_files:
			cmd = get_read_command (esl_type, esl_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for auth_file in auth_files:
			cmd = get_read_command (auth_type, auth_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)

		cmd = get_read_command (path_type, test_env_path)
		self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_validate (self):
		out = log_dir + "validatelog.txt"
		for cert_file in cert_files:
			cmd = get_validate_command (cert_type, cert_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for pkcs7_file in pkcs7_files:
			cmd = get_validate_command (pkcs7_type, pkcs7_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for esl_file in esl_files:
			cmd = get_validate_command (esl_type, esl_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for auth_file in auth_files:
			cmd = get_validate_command (auth_type, auth_file)
			self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_write (self):
		out = log_dir + "writelog.txt"
		for var_by_PK in variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			cmd = get_write_command (var_by_PK[1], auth_file, test_env_path, non_force)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for var_by_KEK in variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			cmd = get_write_command (var_by_KEK[1], auth_file, test_env_path, non_force)
			self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_write_with_force (self):
		out = log_dir + "writelog.txt"
		for var_by_PK in variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			cmd = get_write_command (var_by_PK[1], auth_file, test_env_path, force)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		for var_by_KEK in variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			cmd = get_write_command (var_by_KEK[1], auth_file, test_env_path, force)
			self.assertEqual (self.getCmdResult(cmd, out), True)

	def test_verify (self):
		out = log_dir + "verifylog.txt"
		update_variables = []
		current_variables = []
		current_variables_empty = []
		for var_by_PK in variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			current_var = test_dir[3] + var_by_PK[2] + "/" + "data"
			update_variables.append (var_by_PK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			current_variables.append (var_by_PK[2])
			current_variables.append (current_var)
			cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, empty_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), False)
			update_variables.clear ()
			current_variables.clear ()

		update_variables.clear ()
		current_variables.clear ()
		for var_by_KEK in variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			current_var = test_dir[3] + var_by_KEK[2] + "/" + "data"
			update_variables.append (var_by_KEK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			current_variables.append (var_by_KEK[2])
			current_variables.append (current_var)
			cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, empty_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), False)
			update_variables.clear ()
			current_variables.clear ()

		update_variables.clear ()
		current_variables.clear ()
		for var_by_PK in variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			current_var = test_dir[3] + var_by_PK[1] + "/" + "data"
			update_variables.append (var_by_PK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			current_variables.append (var_by_PK[1])
			current_variables.append (current_var)
			cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, empty_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), False)
		cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, empty_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), False)

		update_variables.clear ()
		current_variables.clear ()
		for var_by_KEK in variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			current_var = test_dir[3] + var_by_KEK[1] + "/" + "data"
			update_variables.append (var_by_KEK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			if current_variables == []:
			        current_variables.append (var_by_KEK[2])
			        current_variables.append (test_dir[3] + var_by_KEK[2] + "/" + "data")
			current_variables.append (var_by_KEK[1])
			current_variables.append (current_var)
			cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, empty_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), False)
		cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables_empty, test_env_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, empty_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, empty_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), False)

	def test_verify_reset_auth (self):
		out = log_dir + "verifylog.txt"
		update_variables = []
		current_variables = []
		for var_by_PK in reset_variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			update_variables.append (var_by_PK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			update_variables.clear ()

		for var_by_KEK in reset_variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			update_variables.append (var_by_KEK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			update_variables.clear ()

		for var_by_PK in reset_variable_by_PK:
			auth_file = test_dir[1] + var_by_PK[0] + ".auth"
			update_variables.append (var_by_PK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), True)

		for var_by_KEK in reset_variable_by_KEK:
			auth_file = test_dir[1] + var_by_KEK[0] + ".auth"
			update_variables.append (var_by_KEK[1])
			update_variables.append (auth_file)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
			cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
			self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, test_env_path, non_write)
		self.assertEqual (self.getCmdResult(cmd, out), True)
		cmd = get_verify_command (update_variables, current_variables, test_env_path, write)
		self.assertEqual (self.getCmdResult(cmd, out), True)

if __name__ == '__main__':

        argParser = argparse.ArgumentParser()
        argParser.add_argument("-m", "--memcheck", type=int, help="enable/disable memory leak check")
        argParser.add_argument("-s", "--secvarctl", help="set secvarctl tool")
        argParser.add_argument("-p", "--secvarpath", help="set secvar path")
        args = argParser.parse_args()

        if args.memcheck != None:
            MEMCHECK = args.memcheck
        if args.secvarctl != None:
            SECTOOLS[0] = args.secvarctl
        if args.secvarpath != None:
            SECVARPATH = args.secvarpath

        del sys.argv[1:]
        collect_test_data ()
        unittest.main()
