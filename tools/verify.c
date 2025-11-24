#include "mbedtls/pkcs7.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform.h"
#include <mbedtls/error.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define SIG_MAGIC "~Module signature appended~\n"
#define SIG_MAGIC_SIZE (sizeof(SIG_MAGIC)-1)
#define PKEY_ID_PKCS7 2

struct module_signature {
    uint8_t algo;                           /* Public-key crypto algorithm [0] */
    uint8_t hash;                           /* Digest algorithm [0] */
    uint8_t id_type;                        /* Key identifier type [PKEY_ID_PKCS7] */
    uint8_t signer_len;                     /* Length of signer's name [0] */
    uint8_t key_id_len;                     /* Length of key identifier [0] */
    uint8_t __pad[3];
    uint32_t sig_len;                       /* Length of signature data */
} __attribute__((packed));

#define SIG_METADATA_SIZE (sizeof(struct module_signature))
#define SECVAR_HEADER_LEN 8

static const uint8_t EFI_CERT_X509_GUID[16] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

#pragma pack(push, 1)
typedef struct {
    uint8_t  SignatureType[16];    /* EFI_CERT_X509_GUID */
    uint32_t SignatureListSize;    /* Total size including this header */
    uint32_t SignatureHeaderSize;  /* Usually 0 for X.509 */
    uint32_t SignatureSize;        /* sizeof(EFI_SIGNATURE_DATA) + cert_size */
} EFI_SIGNATURE_LIST;

typedef struct {
    uint8_t  SignatureOwner[16];   /* Owner GUID (often zero) */
    uint8_t  SignatureData[];      /* DER X.509 certificate */
} EFI_SIGNATURE_DATA;
#pragma pack(pop)

/* Maximum file size accepted by read_file() */
#define READ_FILE_MAX (32u * 1024u * 1024u)

/**
 * Reads a file into a dynamically allocated buffer using a grow-loop.
 *
 * @param path  Path to file
 * @param buf   Output: pointer to newly allocated buffer, or NULL if empty
 * @param len   Output: number of bytes read
 * @return 0 on success, -1 on failure
 */
int read_file(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return -1;
    }

    size_t cap = 4096;
    size_t used = 0;
    unsigned char *p = malloc(cap);
    if (!p) {
        perror("Memory allocation failed");
        fclose(f);
        return -1;
    }

    for (;;) {
        size_t n = fread(p + used, 1, cap - used, f);
        used += n;
        if (n == 0) {
            if (ferror(f)) {
                fprintf(stderr, "Read error on %s\n", path);
                free(p);
                fclose(f);
                return -1;
            }
            break;
        }
        if (used == cap) {
            if (cap >= READ_FILE_MAX) {
	        /* Maximum buffer size reached: read one extra byte to detect truncation */
                unsigned char probe;
                if (fread(&probe, 1, 1, f) == 1) {
                    fprintf(stderr, "File too large (> %u bytes): %s\n",
                            READ_FILE_MAX, path);
                    free(p);
                    fclose(f);
                    return -1;
                }
                break;
            }
            cap = (cap * 2 < READ_FILE_MAX) ? cap * 2 : READ_FILE_MAX;
            unsigned char *np = realloc(p, cap);
            if (!np) {
                perror("realloc failed");
                free(p);
                fclose(f);
                return -1;
            }
            p = np;
        }
    }

    fclose(f);

    if (used > 0) {
        unsigned char *np = realloc(p, used);
        if (np)
            p = np;
	/* Shrinking failure is non-fatal; the original buffer remains valid. */
    } else {
        free(p);
        p = NULL;
    }

    *buf = p;
    *len = used;
    return 0;
}

/**
 * Parse ESL and extract all X.509 certificates into cert chain
 * @esl_data, Pointer to the ESL buffer
 * @esl_len, ESL buffer size
 * @chain, Pointer to an initialized mbedtls_x509_crt structure that will
 *	   be populated with the parsed certificate chain
 * @return 0 on success,  negative error code on parse or allocation failure
 */
static int esl_to_cert_chain(const uint8_t *esl_data, size_t esl_len, mbedtls_x509_crt *chain)
{
    size_t offset = 0;
    int parsed = 0;

    printf("Parsing ESL (%zu bytes)...\n", esl_len);
    while (offset + sizeof(EFI_SIGNATURE_LIST) <= esl_len) {
        const EFI_SIGNATURE_LIST *esl_list = (const EFI_SIGNATURE_LIST *)(esl_data + offset);

        uint32_t list_size = le32toh(esl_list->SignatureListSize);
        uint32_t header_size = le32toh(esl_list->SignatureHeaderSize);
        uint32_t sig_size = le32toh(esl_list->SignatureSize);

        if (list_size < sizeof(EFI_SIGNATURE_LIST) || offset + list_size > esl_len) {
            fprintf(stderr, "Invalid ESL list size at offset 0x%zx\n", offset);
            return -1;
        }

        if (header_size > list_size - sizeof(EFI_SIGNATURE_LIST)) {
            fprintf(stderr, "Invalid ESL header size at offset 0x%zx\n", offset);
            return -1;
        }

        /* Only process X.509 certificate lists */
        if (memcmp(esl_list->SignatureType, EFI_CERT_X509_GUID, 16) == 0) {
            printf("Found X.509 ESL at offset 0x%zx (list_size=%u)\n", offset, list_size);

            if (sig_size <= sizeof(((EFI_SIGNATURE_DATA*)0)->SignatureOwner)) {
                fprintf(stderr, "Invalid SignatureSize at offset 0x%zx\n", offset);
                return -1;
            }

            const uint8_t *sig_ptr = esl_data + offset + sizeof(EFI_SIGNATURE_LIST) + header_size;
            const uint8_t *sig_end = esl_data + offset + list_size;
            size_t sig_bytes = list_size - sizeof(EFI_SIGNATURE_LIST) - header_size;

            while (sig_bytes >= sig_size) {
                /* Verify sig_ptr + sig_size stays within this list entry */
                if (sig_ptr + sig_size > sig_end) {
                    fprintf(stderr, "Signature entry overruns list boundary\n");
                    return -1;
                }
                const EFI_SIGNATURE_DATA *sig = (const EFI_SIGNATURE_DATA *)sig_ptr;
                size_t cert_len = sig_size - sizeof(sig->SignatureOwner);

                printf("  Parsing cert %d: %zu bytes\n", parsed + 1, cert_len);
                int ret = mbedtls_x509_crt_parse(chain, sig->SignatureData, cert_len);
                if (ret != 0) {
                    fprintf(stderr, "Failed to parse X.509 cert: -0x%04x\n", -ret);
                    return ret;
                }

                parsed++;
                sig_ptr += sig_size;
                sig_bytes -= sig_size;
            }
            printf("Extracted %d certificates from this list\n", parsed);
        }

        offset += list_size;
    }
    if (parsed == 0) {
        fprintf(stderr, "No X.509 certificates found in ESL\n");
        return -1;
    }

    return 0;
}

/**
 * Load certificate chain from sysfs secvar (grubdb or db)
 * @base_dir, Base directory containing Secure Boot variables
 * @var, Name of the variable to load
 * @chain, Pointer to an initialized mbedtls_x509_crt structure that will
 *	    be populated with the certificates from the variable
 * @return 0 on success, negative error code on I/O or  parse failure.
 */

int load_secvar(const char *base_dir, const char *var, mbedtls_x509_crt *chain)
{
    char path[512];
    unsigned char *esl_buf = NULL;
    size_t esl_len = 0;

    int n = snprintf(path, sizeof(path), "%s/%s/data", base_dir, var);
    if (n < 0 || n >= (int)sizeof(path)) {
        fprintf(stderr, "secvar path too long\n");
        return -1;
    }

    if (read_file(path, &esl_buf, &esl_len) != 0) {
        fprintf(stderr, "Failed to read ESL data from %s\n", path);
        return -1;
    }

    if (esl_len <= SECVAR_HEADER_LEN) {
        fprintf(stderr, "ESL data too small\n");
        free(esl_buf);
        return -1;
    }

    /* Skip header so parser sees EFI_SIGNATURE_LIST */
    const uint8_t *esl_data = esl_buf + SECVAR_HEADER_LEN;
    size_t esl_data_len = esl_len - SECVAR_HEADER_LEN;

    int rc = esl_to_cert_chain(esl_data, esl_data_len, chain);
    free(esl_buf);
    if (rc != 0) {
        fprintf(stderr, "Failed to build certificate chain from ESL\n");
        return -1;
    }

    return 0;
}

/**
 * Extracts an appended PKCS#7 signature and metadata from a signed binary file buffer.
 * @param buf, Pointer to full binary file data
 * @param bufsize, Size of the binary buffer
 * @param content_size, Size of signed content
 * @param pkcs7_sig, pointer to buffer containing extracted PKCS#7 signature
 * @param pkcs7_siglen, pointer to variable receiving signature size
 * @return 0 on success; negative value on error
 */
int extract_appended_signature(const unsigned char *buf, size_t bufsize,
                               size_t *content_size, unsigned char **pkcs7_sig,
                               size_t *pkcs7_siglen)
{
    if (bufsize < SIG_MAGIC_SIZE) {
        fprintf(stderr, "file too short for signature magic\n");
        return -1;
    }
    const unsigned char *magic_offset = buf + bufsize - SIG_MAGIC_SIZE;
    if (memcmp(magic_offset, SIG_MAGIC, SIG_MAGIC_SIZE) != 0) {
        fprintf(stderr, "missing or invalid signature magic\n");
        return -2;
    }
    if (bufsize < SIG_MAGIC_SIZE + SIG_METADATA_SIZE) {
        fprintf(stderr, "file too short for signature metadata\n");
        return -3;
    }

    const unsigned char *meta_offset = magic_offset - SIG_METADATA_SIZE;
    struct module_signature meta;
    memcpy(&meta, meta_offset, SIG_METADATA_SIZE);
    if (meta.id_type != PKEY_ID_PKCS7) {
        fprintf(stderr, "wrong signature type\n");
        return -4;
    }
    uint32_t siglen = ntohl(meta.sig_len);
    if (siglen == 0) {
        fprintf(stderr, "zero-length PKCS#7 signature\n");
        return -5;
    }
    if (bufsize < SIG_MAGIC_SIZE + SIG_METADATA_SIZE + siglen) {
        fprintf(stderr, "file too short for PKCS#7 message\n");
        return -6;
    }
    const unsigned char *pkcs7_offset = meta_offset - siglen;
    *pkcs7_sig = malloc(siglen);
    if (!*pkcs7_sig) {
        perror("memory allocation failed");
        return -7;
    }
    memcpy(*pkcs7_sig, pkcs7_offset, siglen);
    *pkcs7_siglen = siglen;
    *content_size = pkcs7_offset - buf;
    return 0;
}

/** Display usage information **/
static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  Detached signature: %s -d <pkcs7> <binary> (-c <cert> | -s <secvar>)\n", prog);
    printf("  Appended signature: %s -a <binary_with_sig> (-c <cert> | -s <secvar>)\n", prog);
}
/**
 * Verifies a detached PKCS#7 signature
 * @param pkcs7_path, Path to PKCS#7 signature file
 * @param bin_path, Path to original binary file
 * @param cert_chain, Certificate chain
 * @return 0 if signature is valid; 1 on failure or errros
 */
static int verify_detached(const char *pkcs7_path, const char *bin_path, mbedtls_x509_crt *cert_chain)
{
    unsigned char *pkcs7_buf = NULL, *content_buf = NULL;
    size_t pkcs7_len = 0, content_len = 0;
    int ret = 1;
    mbedtls_pkcs7 pkcs7;
    char errbuf[256];

    if (read_file(pkcs7_path, &pkcs7_buf, &pkcs7_len))
        return 1;
    if (pkcs7_len == 0) {
        fprintf(stderr, "Empty PKCS#7 file: %s\n", pkcs7_path);
        return 1;
    }

    if (read_file(bin_path, &content_buf, &content_len)) {
        free(pkcs7_buf);
        return 1;
    }
    if (content_len == 0) {
        fprintf(stderr, "Empty binary file: %s\n", bin_path);
        free(pkcs7_buf);
        return 1;
    }

    mbedtls_pkcs7_init(&pkcs7);

    ret = mbedtls_pkcs7_parse_der(&pkcs7, pkcs7_buf, pkcs7_len);
    if (ret < 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to parse PKCS7 structure: -0x%04x %s\n", -ret, errbuf);
        goto out;
    }

    mbedtls_x509_crt *cert = cert_chain;
    int cert_idx = 1;

    ret = -1; /* default: no cert matched */
    while (cert != NULL) {
        printf("Trying certificate %d...\n", cert_idx);

        ret = mbedtls_pkcs7_signed_data_verify(&pkcs7, cert, content_buf, content_len);
        if (ret == 0) {
            printf("Success: CMS PKCS7 signature Verified with cert %d\n", cert_idx);
            goto out;
        } else {
            fprintf(stderr, "Failed: PKCS7 Signature verification failed. -0x%04x\n", -ret);
        }
        cert = cert->next;
        cert_idx++;
    }
out:
    free(pkcs7_buf);
    free(content_buf);
    mbedtls_pkcs7_free(&pkcs7);
    return (ret == 0) ? 0 : 1;
}
/** 
 * Verifies an appended PKCS#7 signature
 * @param bin_path, Path to binary file with appended signature
 * @param cert_chain, Certificate chain
 * @return 0 if signature is valid; 1 on failure or errors
 */
static int verify_appended(const char *bin_path, mbedtls_x509_crt *cert_chain)
{
    unsigned char *buf = NULL, *pkcs7_sig = NULL;
    size_t bufsize = 0, content_len = 0, pkcs7_siglen = 0;
    int ret = 1;
    mbedtls_pkcs7 pkcs7;
    char errbuf[256];

    if (read_file(bin_path, &buf, &bufsize))
        return 1;
    if (bufsize == 0) {
        fprintf(stderr, "Empty binary file: %s\n", bin_path);
        return 1;
    }

    ret = extract_appended_signature(buf, bufsize, &content_len, &pkcs7_sig, &pkcs7_siglen);
    if (ret != 0) {
        fprintf(stderr, "Failed to extract appended signature (error %d)\n", ret);
        free(buf);
        return 1;
    }

    mbedtls_pkcs7_init(&pkcs7);

    ret = mbedtls_pkcs7_parse_der(&pkcs7, pkcs7_sig, pkcs7_siglen);
    if (ret < 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "Failed to parse PKCS7 structure: -0x%04x %s\n", -ret, errbuf);
        goto out;
    }

    mbedtls_x509_crt *cert = cert_chain;
    int cert_idx = 1;

    ret = -1; /* default: no cert matched */
    while (cert != NULL) {
        printf("Trying certificate %d...\n", cert_idx);

        ret = mbedtls_pkcs7_signed_data_verify(&pkcs7, cert, buf, content_len);
        if (ret == 0) {
            printf("Success: Appended CMS PKCS7 Signature Verified with cert %d\n", cert_idx);
            goto out;
        } else {
            fprintf(stderr, "Failed: PKCS7 Signature verification failed. -0x%04x\n", -ret);
        }
        cert = cert->next;
        cert_idx++;
    }

out:
    free(buf);
    free(pkcs7_sig);
    mbedtls_pkcs7_free(&pkcs7);
    return (ret == 0) ? 0 : 1;
}

/* --------- main --------- */
int main(int argc, char *argv[])
{
    if (argc < 5) {
        usage(argv[0]);
        return 1;
    }

    int detached = 0, appended = 0;
    const char *pkcs7_path = NULL;
    const char *bin_path = NULL;
    const char *cert_file = NULL;
    const char *secvar = NULL;
    char errbuf[256];

    /* Basic mode selection: -d or -a must be argv[1] */
    if (strncmp(argv[1], "-d", 2) == 0 && argv[1][2] == '\0') {
        detached = 1;
        pkcs7_path = argv[2];
        bin_path = argv[3];
    } else if (strncmp(argv[1], "-a", 2) == 0 && argv[1][2] == '\0') {
        appended = 1;
        bin_path = argv[2];
    } else {
        usage(argv[0]);
        return 1;
    }

    /* Expect either -c <cert> or -s <secvar> */
    if (detached) {
        if (argc != 6) {
            usage(argv[0]);
            return 1;
        }
        if (strcmp(argv[4], "-c") == 0) {
            cert_file = argv[5];
        } else if (strcmp(argv[4], "-s") == 0) {
            secvar = argv[5];
        } else {
            usage(argv[0]);
            return 1;
        }
    } else if (appended) {
        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }
        if (strcmp(argv[3], "-c") == 0) {
            cert_file = argv[4];
        } else if (strcmp(argv[3], "-s") == 0) {
            secvar = argv[4];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    mbedtls_x509_crt cert_chain;
    mbedtls_x509_crt_init(&cert_chain);

    int ret;
    ret = psa_crypto_init();
    if (ret != 0) {
        fprintf(stderr, "psa_crypto_init() failed: -0x%04x\n", -ret);
        mbedtls_x509_crt_free(&cert_chain);
        return 1;
    }
    if (secvar) {
        ret = load_secvar("/sys/firmware/secvar/vars", secvar, &cert_chain);
        if (ret != 0) {
            fprintf(stderr, "Failed to load certificates from secvar %s\n", secvar);
            mbedtls_x509_crt_free(&cert_chain);
            return 1;
        }
    } else if (cert_file) {
        ret = mbedtls_x509_crt_parse_file(&cert_chain, cert_file);
        if (ret != 0) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "Failed to load certificate file %s: -0x%04x %s\n", cert_file, -ret, errbuf);
            mbedtls_x509_crt_free(&cert_chain);
            return 1;
        }
    } else {
        usage(argv[0]);
        mbedtls_x509_crt_free(&cert_chain);
        return 1;
    }

    if (detached)
        ret = verify_detached(pkcs7_path, bin_path, &cert_chain);
    else
        ret = verify_appended(bin_path, &cert_chain);

    mbedtls_x509_crt_free(&cert_chain);
    mbedtls_psa_crypto_free();
    return ret;
}
