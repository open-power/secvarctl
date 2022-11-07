# secvarctl
Suite of tools to manipulate and generate Secure Boot variables on POWER.

The purpose of this tool is to simplify and automate the process of reading and writing secure boot keys.   
`secvarctl` allows the user to communicate, via terminal commands, with the keys efficiently. 

Secure Variables are responsible for loading the target OS/hypervisor during Secure Boot. There are currently four secure variables in the Secure Boot process: The Platform Key (PK), Key Exchange Key (KEK), Database Key (db) and Blocklist Key (dbx).The PK serves as the root key, usually supplied by platform owner, if there is no PK then Secure Boot is not enabled. The PK has authority over all other keys. The KEK is usually provided by the OS vendor and has authority over the db and dbx. The db has authority over the kernels and other user specific firmware. The dbx has authority over kernels and specific firmware that are not to be loaded. 

Updating of these secure variables requires a specific format for success. If updating the PK, KEK or db, an x509 public key must be contained in an EFI Signature List (ESL). If updating the dbx, the binary that is to be banned must be hashed and placed in an ESL. Then, a PKCS7 structure must be generated by signing the new ESL with the private key of a secure variable that has authority over the variable being updated (Example: if updating the db, the new ESL must be signed by either the KEK or PK). Finally, the new ESL must be appended to the generated PKCS7 and the whole structure is then placed into what is called an Auth file (this adds extra header information, timestamp and content size). When the Auth file is generated, the resulting file is ready to be submited. Once submitted, the update is only applied when the POWER machine is rebooted. 

Being that the key management process is rather lengthy and difficult, `secvarctl` was created to simplify these steps.

For more background knowledge on key heirarchy and the Secure Boot process : [IBM Secure Boot on POWER Doc](https://developer.ibm.com/articles/protect-system-firmware-openpower/)

For information on the Secure Variable sysfs : [Secvar Docs](https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-secvar)

For any questions regarding secvarctl, feel free to reach out: [Nick Child](nick.child@ibm.com)



## REQUIREMENTS:  
  -Must be on a POWER machine that supports Secure Boot (for reading and updating secure variables), x86 works for file generation and validation  
  -Mbedtls version 2.14 and above or OpenSSL   
  -GNU Make or CMake    
  -C compiler
	

## BUILDING:  
 |               | Make      | CMake |
 ---             | ----------- | ----------- |
 | Default Build (Mbedtls is cryptolib) | `make [build options]`      | `mkdir build && cd build && cmake [build options] ../ . && cmake --build .`      |
 | Build W OpenSSL as cryptolib | `make OPENSSL=1` | `mkdir build && cd build && cmake -DOPENSSL=1 [build options] ../ . && cmake --build .` |
 | Build W GnuTLS as cryptolib | `GNUTLS=1` | `-DGNUTLS=1` |
 | Static Build | `STATIC=1` | `-DSTATIC=1`|
 | Reduced Size Build | default | `-DSTRIP=1` |
 | Build Without Crypto Write Functions | `CRYPTO_READ_ONLY=1` | `-CRYPTO_READ_ONLY=1` |
 | Build W Specific Mbedtls Library | `CFLAGS="-I<path>/include" LDFLAGS="-L<path>/library"` | `-DCUSTOM_MBEDTLS=<path>` |
 | Build for Coverage Tests | `make [options] secvarctl-cov` | `-DCMAKE_BUILD_TYPE=Coverage` |
 | Build W Debug Symbols | `make DEBUG=1` | default |
 | Install    | `make install`        | `cmake --install .`|
 

  
## FILE/KEY GENERATION:   
   + X509:  
     - `$openssl req –new –x509 –newKey rsa:2048 –keyout <outPrivate.key> -out <outPublic.crt> -nodes –sha256`    
   + Efi Signature list (ESL):  
     - From an x509 : `$secvarctl generate c:e -i <inputCert> -o <out.esl>`  
     - From a hash: `$secvarctl generate h:e -h <hashAlgUsed> -i <inputHash> -o <out.esl>`  
     - From a generic file (hash done internally) : `$secvarctl generate f:e -h <hashAlgToUse> -i <inputFile> -o <out.esl>`   
     - From a sbat file : `$secvarctl generate f:e -i <inputFile> -o <out.esl> -n sbat`
   + Signed Auth File (EXPERIMENTAL):    
     - From an ESL: `$secvarctl generate e:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -i <inputESL> -o <out.auth> `   
     - From an x509 (ESL created internally): `$secvarctl generate c:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -i <inputCert> -o <out.auth> `   
     - From a hash (ESL created internally): `$secvarctl generate h:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -h <hashAlgUsed> -i <inputHash> -o <out.auth> `   
     - From a file (hash->ESL created internally): `$secvarctl generate f:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -h <hashAlgUsed> -i <inputFile> -o <out.auth> `  
     - From a sbat file (ESL created internally): `$secvarctl generate f:a -k <signerPrivate.key> -c <signerPublic.crt> -n sbat -i <inputFile> -o <out.auth> `
     - To create a variable reset file: `$secvarctl generate reset -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -o <out.auth> `


## USAGE:    
  Secvarctl has 5 main commands   
    `./secvarctl read [options] [variable]`    
    `./secvarctl write [options] <variable> <file>`    
    `./secvarctl validate [options] [fileType] <file>`  
     `./secvarctl verify [options] -u {update Variables}`  
     `./secvarctl generate <inputFormat>:<outputFormat> [OPTIONS] -i <inputFile> -o <outputFile` 
## SUB COMMAND USAGE:
    
    READ:
                  ./secvarctl read [options] [variable]
	OPTIONS:
		--usage 
		--help
		-r , raw output
		-f <input.esl> , read from file
		-p </path/to/vars/> , read from path (subdirectories {"PK", "KEK, "db", "dbx", "sbat", "TS"} each with files {"data", "size"} expected)
		[variable] , one of {"PK", "KEK, "db", "dbx", "sbat", "TS"}
		
       The read command will read from the secure variable directory and print out information on their current contents.
       By default, the program assumes the data is an EFI Signature List and prints the contents in human readable form.  
       To print the raw data, use "-r".
       The default secure variable directiory is "/sys/firmware/secvar/vars/"
       To specify a path to the variables, use "-p <newPath>".Expected variable subdirectory names :{"PK", "KEK", "db", "dbx", "sbat", "TS"} with contained data file "<varName>/data"
       If no variable name is given, the program will try to print the data for any variable named one of the following 	{'PK','KEK','db','dbx', 'sbat', 'TS'}
       Type one of the variable names to get info on that key, NOTE does not work when -f option is present NOTE 'TS' variable is not an ESL, it is 4 timestamps (64 bytes total) for each of the other variables
       To read the data of any esl file use "-f <eslFileName>"
       
    WRITE:
                  ./secvarctl write [options] <variable> <file>
	REQUIRED:
		<variable> , one of {"PK", "KEK, "db", "dbx"}
		<file> , an auth file
	OPTIONS:
		--usage 
		--help
		-v , verbose output
		-f , force update, no validation
		-p </path/to/vars/> , write to file in path (subdirectories {"PK", "KEK, "db", "dbx"} each with "update" file expected)
		
       The write command will update the given variable's key value. 
       The new key value is expected to be contained in a Signed Authenticated file signed with a variable with authority over the update variable.
       By default, the write function will validate the format of the auth file. If it is a success the file will be written to the variables "update" file. 
       NOTE: This command does not guarantee that the update will be successful upon reboot (since no signature checks were performed), use the verify command to validate both format and content. 
       The "update" file is expected to be in "<pathToVars>/<variable>/update".
       The "-p <pathToVars>" option is the location of the subdirectories {"PK","KEK", "db", "dbx"} which contain an "update" file, the default path is "/sys/firmware/secvar/vars/" 
       The "-v" option prints process info 
       The "-f" option skips the validation step and immediadetly writes content of "<file>" to "<variable>/update"
       The <variable> requirement is expected to be one of the following {"PK","KEK", "db", "dbx"}
       
    VALIDATE:
                 ./secvarctl validate [options] <file type> <file> 
	REQUIRED:
		<file> , the input file, assumed to be auth file if not specified
		-e <file> , ESL
		-p <file> , PKCS7/Signed Data
		-c <file> , DER or PEM certificate
		-a <file> , DEFAULT,  a signed authenticated file containg a PKCS7 and appended ESL 
	OPTIONS:
		--usage
		--help
		-v , verbose output
		-n <varName> , name of secure boot variable, used when validating CERT/ESL/Auth file.
	
         The validate command will print "SUCCESS" or "FAILURE" depending if the format and basic content requirements are met for the given file
        The default type of "<file>" is an auth file containing a PKCS7/Signed Data and attatched esl.
        ALL KEYS ARE EXPECTED TO BE SHA-256 and RSA 2048, UNLESS DBX FLAG IS GIVEN
	THIS FUNCTION DOES NOT DO ANY COMPARISON AGAINST CURRENT KEYS (use verify for that)
        For extra process and file content information use "-v" for verbose
        To validate a PKCS7 (expected DER), use "-p <file>"
        To validate an Efi Signature List (ESL), use "-e <file>"
        To validate a certificate (x509 in DER or PEM format), use "-c <file>"
	
    VERIFY:
    		./secvarctl verify [options] -u {Update Variables}
	REQUIRED:
		-u {Update Variables} , the updates to be run
	OPTIONAL:
		--usage 
		--help
		-v , verbose output
		-p /path/to/vars/, read from path (subdirectories {"PK", "KEK, "db", "dbx", "TS"} each with files {"data", "size"} expected)
		-w , write updates if verified
		-c {Current Variables}	
	{Update Variables}:
		Format: <varname_1> <file_1> <varname_2> <file_2> ...
		Where <varname> is one of {"PK", "KEK, "db", "dbx"} and <file> is an auth file
		Updates are verified in the order they are submitted
	{Current Variables}:
		Format: <varname_1> <file_1> <varname_2> <file_2> ...
		Where <varname> is one of {"PK", "KEK, "db", "dbx", "TS"} and <file> is an esl file (unless TS)
	
	The verify command will print "SUCCESS" or "FAILURE" if the update files are correctly signed by the current variables or not.
	The "-v" command will give extra information on process information.
	All given update files are expected to be a signed PKCS7/Signed Data authenticated file containing an attatched new ESL. 
	The updates should be signed according to the correct hierarchy rules:
			PK can sign all other keys, (including itself),
			KEK can sign db and dbx, cannot sign PK
			db/dbx cannot sign KEK or PK
			TS holds no power of the variables, only functions to hold the timestamps of the last update for each of the other variables. Cannot be manually updated
	All updates have their format validated before any verification is done.
	The "-p <pathToVars>" option is the location of current variables in the subdirectories {"PK","KEK", "db", "dbx", "TS"} which contain the {"update, "data", "size"} files, the default path is "/sys/firmware/secvar/vars/" defined in secvarctl.h
	The "-c {Current Variables}" option is used to specify the current variables manually. See above for correct format of {Current variables}.
	If the "-w" option is given then, if the verification passes, the updates will be commited to the "update" file of the given variable
      

    GENERATE:
    		./secvarctl generate <inputFormat>:<outputFormat> [OPTIONS] -i <inputFile> -o <outputFile>
    REQUIRED:
       <inputFormat>:<outputFormat> , the type of input file and type of output file seperated by a colon
       -i <input> , input file formatted according to <inputFormat>
	   -o <output> , output file formatted according to <ouputFormat>
	OPTIONAL:
		--usage
		--help
		-v , verbose, gives process info
		-n <varName> , name of secure boot variable, used when generating an auth file, PKCS7, or when the input file contains hashed data rather than x509 (use '-n dbx'), current <varName> are: {'PK','KEK','db','dbx', 'sbat'}
		-f force generation, skips validation of input file, assumes format to be correct
		-t <time> , where <time> is of the format described below. creates a custom timestamp used when generating an auth or PKCS7 file, if not given then current time is used, all times are in UTC
                    format of <time> = 'YYYY-MM-DDThh:mm:ss' where:
                        - 'YYYY' four-digit year
                        - 'MM' two-digit month (01=January, etc.)
                        - 'DD' two-digit day of month (01 through 31)
                        - 'T' appears literally
                        - 'hh' two digits of hour (00 through 23) (am/pm NOT allowed)
                        - 'mm' two digits of minute (00 through 59)
                        - 'ss' two digits of second (00 through 59)
		-h <hashAlg> hash function, used when output or input format is [h]ash, current <hashAlg> are : {'SHA256', 'SHA224', 'SHA1', 'SHA384', 'SHA512'}
		-k <privKey> , private key, used when generating [p]kcs7 or [a]uth file
		-c <certFile> , x509 certificate (PEM), used when generating [p]kcs7 or [a]uth file
		reset , generates a valid variable reset file, replaces <inputFormat>:<outputFormat>. 
			This file is just an auth file with an empty ESL. Required arguments are output file, signer crt/key pair and variable name. 
			No input file required.
        -s <sigFile> raw signature file, replaces -k <privKey> argument when user does not 
            have direct access to private key. User can use their signing framework to generate the signature externally. The file to be signed should be the output of 'secvarctl generate c:x ...' both commands should use the same -n <varName> and -t <timestamp> arguments


	<inputFormat>:
		[h]ash , A file containing only hashed data, use -h <hashAlg> to specifify the hash function used (default SHA256) 
		[c]ert , An x509 certificate, RSA2048 and SHA256 ONLY
		[e]sl , An EFI Signature List
		[p]kcs7 , A PKCS7 file containing signed data
		[a]uth , A signed authensticated file containing a PKCS7 and the new data 
		[f]ile , Generic file, depending on outputFormat follows steps: file->hash->ESL->PKCS7->Auth,  Warning: no format validation will be done
	<outputFormat>:
		[h]ash , A file containing only hashed data, use -h <hashAlg> to specifify the hash function used (default SHA256) 
		[e]sl , An EFI Signature List
		[p]kcs7 , a PKCS7 file containing signed data, must specify secure variable name, public and private keys
		[a]uth , A signed authenticated file containing a PKCS7 and the new data, must specify public and private keys secure variable name
        [x] , A presigned digest file containing only the hash of the new data in ESL format with extra metadata. This format need only be used when the user does not have access to private keys for signing and must send the digest to be signed through an external framework.  

		The generate command is used to generate all the types of files that will be used in the secure variable management process.
		The file formats that can be generated from a certificate is a hash, ESL, PKCS7 and auth file with commands 'c:h', "c:e", "c:p" and "c:a" respectively. 
		All input files are prevalidated to be correctly formatted according to the specified input format, to skip prevalidation use "-f".
		A hash function can be specified with -h <hashAlg>, this is useful when generating a hash or when the input file contains a hash. 
		The "-h <hashAlg>" will not effect the digest algorithm used when generating signed data for a PKCS7 (always SHA256). 
		When generating a signed file (PKCS7 or auth), a public and private key will be needed for signing. 
		A PKCS7 and Auth file can be signed with several signers by adding more ' -k <privKey> -c <cert>' pairs. 
		Additionaly, when generating an Auth file the secure variable name must be given as -n <varName> because it is included in the  message digest. 
		When using the input type '[f]ile' it will be assumed to be a text file and if output file is '[e]sl', '[p]kcs7' or '[a]uth' it will be hashed according to <hashAlg> (default SHA256). 
		To create a variable reset file (one that will remove the current contents of a variable), replace '<inputFormat>:<outputFormat>' with 'reset' and
		supply a variable name, public and private signer files and an output file with '-n <varName> -k <privKey> -c <crtFile> -o <outFile>'
		GENERATION OF PKCS7 AND AUTH FILES ARE IN EXPERIMENTAL DEVELEPOMENT PHASE. THEY HAVE NOT BEEN THOROUGHLY TESTED YET.

      
## License   
The files located in the `external` directory are borrowed files from other packages. They retain their licenses from their respective license headers. For example, the file `external/linux/.clang-format` is protected under GPL-2.0 as specified by its file header and `external/linux/LICENSE` . All other files not in the `external` directory are protected under Apache 2.0, as specified in the `LICENSE` file.
