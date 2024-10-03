# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
import subprocess
import os
import sys
import time

DATAPATH = os.path.join(os.path.curdir, "testdata", "guest")
ESL_PATH = os.path.join(DATAPATH, "eslfiles")
AUTH_PATH = os.path.join(DATAPATH, "authfiles")
X509_PATH = os.path.join(DATAPATH, "x509certs")
GOLD_PATH = os.path.join(DATAPATH, "goldenKeys")
PKCS7_PATH = os.path.join(DATAPATH, "pkcs7files")


# [nameoffile, var, signing var]
variable_by_PK = [
    ["PK_by_PK", "PK", "PK"],
    ["KEK_by_PK", "KEK", "PK"],
    ["db_by_PK", "db", "PK"],
    ["dbx_by_PK", "dbx", "PK"],
    ["grubdb_by_PK", "grubdb", "PK"],
    ["grubdbx_by_PK", "grubdbx", "PK"],
    ["moduledb_by_PK", "moduledb", "PK"],
    ["trustedcadb_by_PK", "trustedcadb", "PK"],
    ["sbat_by_PK", "sbat", "PK"]
]


variable_by_KEK = [
    ["db_by_KEK", "db", "KEK"],
    ["dbx_by_KEK", "dbx", "KEK"],
    ["grubdb_by_KEK", "grubdb", "KEK"],
    ["grubdbx_by_KEK", "grubdbx", "KEK"],
    ["moduledb_by_KEK", "moduledb", "KEK"],
    ["trustedcadb_by_KEK", "trustedcadb", "KEK"],
    ["sbat_by_KEK", "sbat", "KEK"]
]

variable_list = variable_by_PK + variable_by_KEK

hash_algorithm = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]
x509_hash_algorithm = ["SHA256", "SHA384", "SHA512"]

variables = ["PK", "KEK", "db", "dbx", "grubdb", "grubdbx", "moduledb", "trustedcadb", "sbat"]
sbat_data = ["sbat,1\n", "grub,1\n", "grub.ibm.grub,1\n", "grub.fedora,1"]
SBAT_name = "sbat"

cert_to_esl = "c:e"
file_to_esl = "f:e"
cert_to_auth = "c:a"
file_to_auth = "f:a"
force = "-f"
non_force = ""
auth_reset = "reset"
log_dir = "./log"

if len(sys.argv) > 1:
    secvarctl = [sys.argv[1]]
else:
    secvarctl = ["../bin/secvarctl-dbg"]

secvarctl = secvarctl + ["-m", "guest", "generate"]

# Stores last log of function into log file
def command(args, err=None, out=None):
    return subprocess.call(args, stderr=err, stdout=out)

def create_environments():
    command(["mkdir", "-p", log_dir])
    with open("./log/genlog.txt", "w") as f:
        # TODO: is pre-generating the paths really necessary? Just do it before each operation
        for directory in [ESL_PATH, AUTH_PATH, X509_PATH, GOLD_PATH, PKCS7_PATH]:
            command(["mkdir", "-p", directory], f, f)
        # TODO: move to goldenkey generation
        for var_name in variables:
            command(["mkdir", "-p", os.path.join(GOLD_PATH, var_name)], f, f)

def convert_pem_to_Der(pem_cert_file, der_cert_file):
    command(["openssl", "x509", "-outform", "der", "-in", pem_cert_file, "-out", der_cert_file])

def generate_x509_cert(priv="default.key", pub="default.crt", crtType="-x509", rsa="rsa:2048", sha="-sha256", nodes="-nodes", subj="/C=NC/O=testing corp"):
    command(["openssl", "req", "-new", crtType, "-newkey", rsa, "-keyout", priv, "-out", pub, nodes, sha, "-subj", subj])
    convert_pem_to_Der(pub, pub[:-4] + ".der")
    return

def generate_esl(variable_name, format_type, cert_file, esl_file):
    command(secvarctl + [format_type, "-i", cert_file, "-o", esl_file, "-n", variable_name])

def generate_auth(variable_name, signer_key_file, signer_cert_file, cert_file, auth_file, format_type, enforce=""):
    time.sleep(1)
    cmd = [format_type, "-k", signer_key_file, "-c", signer_cert_file, "-n", variable_name, "-i", cert_file, "-o", auth_file]
    if enforce == force:
        cmd = cmd + [force]
    command(secvarctl + cmd)

def generate_pkcs7(input_file, output_file, sign_cert, sign_key, hash_algo):
    command(["openssl", "cms", "-sign", "-binary", "-in", input_file, "-signer", sign_cert, "-inkey", sign_key, "-out", output_file, "-noattr", "-outform", "DER", "-md", hash_algo])

def create_sbat_file(sbat_file):
    with open(sbat_file, "w") as f:
        for data in sbat_data:
            f.write(data)

def create_size_file(data_file, size_file):
    size = os.path.getsize(data_file)
    with open(size_file, "w") as f:
        f.write(str(size))
        f.close()

def add_timestamp(esl_file, data_file):
    file_object = open(data_file, 'wb')
    t = time.gmtime()
    file_object.write((0).to_bytes(1, byteorder=sys.byteorder))
    file_object.write((t.tm_year).to_bytes(2, byteorder=sys.byteorder))
    file_object.write((t.tm_mon).to_bytes(1, byteorder=sys.byteorder))
    file_object.write((t.tm_mday).to_bytes(1, byteorder=sys.byteorder))
    file_object.write((t.tm_hour).to_bytes(1, byteorder=sys.byteorder))
    file_object.write((t.tm_min).to_bytes(1, byteorder=sys.byteorder))
    file_object.write((t.tm_sec).to_bytes(1, byteorder=sys.byteorder))
    file_object.close()
    os.system("cat " + esl_file + " >> " + data_file)
    os.system("rm -rf " + esl_file)

def create_goldenkey_files():
    # Generate valid pub and private keys
    for var_name in variables:
        esl_file = os.path.join(GOLD_PATH, var_name, "esldata")
        data_file = os.path.join(GOLD_PATH, var_name, "data")
        update_file = os.path.join(GOLD_PATH, var_name, "update")
        size_file = os.path.join(GOLD_PATH, var_name, "size")

        if var_name == SBAT_name:
            cert_file = os.path.join(GOLD_PATH, var_name, f"{var_name}.csv")
            create_sbat_file(cert_file)
            format_type = file_to_esl
        else:
            format_type = cert_to_esl
            key_file = os.path.join(GOLD_PATH, var_name, f"{var_name}.key")
            cert_file = os.path.join(GOLD_PATH, var_name, f"{var_name}.crt")
            generate_x509_cert(key_file, cert_file)

        generate_esl(var_name, format_type, cert_file, esl_file)
        add_timestamp(esl_file, data_file)
        command(["touch", update_file])
        create_size_file(data_file, size_file)

def create_pkcs7_files():
    for hash_alg in hash_algorithm:
        for filename, varname, signer in variable_list:
            if varname != SBAT_name and hash_alg == "SHA256":
                pkcs7_file = os.path.join(PKCS7_PATH, hash_alg + "_" + filename + ".pkcs7")
                key_file = os.path.join(X509_PATH, signer + ".key")
                cert_file = os.path.join(X509_PATH, signer + ".crt")
                var_cert_file = os.path.join(X509_PATH, filename + ".crt")
                generate_pkcs7(var_cert_file, pkcs7_file, cert_file, key_file, hash_alg)


def create_x509_cert_files():
    for var_name in variables:
        if var_name == SBAT_name:
            cert_file = os.path.join(X509_PATH, var_name + ".csv")
            create_sbat_file(cert_file)
        else:
            key_file = os.path.join(X509_PATH, var_name + ".key")
            cert_file = os.path.join(X509_PATH, var_name + ".crt")
            generate_x509_cert(key_file, cert_file)

    for filename, varname, _signer in variable_list:
        if varname != SBAT_name:
            key_file = os.path.join(X509_PATH, filename + ".key")
            cert_file = os.path.join(X509_PATH, filename + ".crt")
            generate_x509_cert(key_file, cert_file)


def create_esl_files():

    for var_name in variables:
        esl_file = os.path.join(ESL_PATH, var_name + ".esl")

        if var_name == SBAT_name:
            cert_file = os.path.join(X509_PATH, var_name + ".csv")
            format_type = file_to_esl
        else:
            format_type = cert_to_esl
            cert_file = os.path.join(X509_PATH, var_name + ".crt")

        generate_esl(var_name, format_type, cert_file, esl_file)

def create_auth_files():
    for filename, varname, signer in variable_list:
        auth_file = os.path.join(AUTH_PATH, filename + ".auth")
        signer_key_file = os.path.join(GOLD_PATH, signer, signer + ".key")
        signer_cert_file = os.path.join(GOLD_PATH, signer, signer + ".crt")

        if varname == SBAT_name:
            cert_file = os.path.join(X509_PATH, varname + ".csv")
            format_type = file_to_auth
        else:
            format_type = cert_to_auth
            cert_file = os.path.join(X509_PATH, filename + ".crt")

        generate_auth(varname, signer_key_file, signer_cert_file, cert_file, auth_file, format_type, non_force)


def create_reset_auth_files():
    format_type = auth_reset
    cert_file = ""
    for filename, varname, signer in variable_list:
        auth_file = os.path.join(AUTH_PATH, auth_reset + "_" + filename + ".auth")
        signer_key_file = os.path.join(GOLD_PATH, signer, signer + ".key")
        signer_cert_file = os.path.join(GOLD_PATH, signer, signer + ".crt")
        generate_auth(varname, signer_key_file, signer_cert_file, cert_file, auth_file, format_type, non_force)


if __name__ == "__main__":
    create_environments()
    create_goldenkey_files()
    create_x509_cert_files()
    create_pkcs7_files()
    create_esl_files()
    create_auth_files()
    create_reset_auth_files()
