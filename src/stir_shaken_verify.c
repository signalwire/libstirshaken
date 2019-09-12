#include "stir_shaken.h"

#undef BUFSIZE
#define BUFSIZE 1024*8

int stir_shaken_do_verify_data_file(const char *data_filename, const char *signature_filename, EVP_PKEY *public_key)
{
    BIO *in = NULL, *inp = NULL, *bmd = NULL, *sigbio = NULL, *bio_err = NULL;
    const EVP_MD    *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int r = -1, sanity = 5000;
    int siglen = 0, res = -1;
    unsigned char *buf = NULL;
    unsigned char *sigbuf = NULL;
    EVP_MD_CTX *ctx = NULL;

    const char      *digest_name = "sha256";
    int             i = 0;


    if (!data_filename || !signature_filename || !public_key) {
        goto err;
    }

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    buf = malloc(BUFSIZE);
    if (!buf) {
        goto err;
    }
    memset(buf, 0, BUFSIZE);
    
    md = EVP_get_digestbyname(digest_name);
    if (!md) {
        
		// TODO remove
		printf("STIR-Shaken: Cannot get %s digest\n", digest_name);
        goto err;
    }
    
    in = BIO_new(BIO_s_file());
    bmd = BIO_new(BIO_f_md());
    if ((in == NULL) || (bmd == NULL)) {
        
		// TODO remove
		printf("STIR-Shaken: Cannot get SSL'e BIOs...\n");
        goto err;
    }

    if (!BIO_get_md_ctx(bmd, &mctx)) {
        
		// TODO remove
		printf("STIR-Shaken: Error getting context\n");
        goto err;
    }

    r = EVP_DigestVerifyInit(mctx, &pctx, md, NULL, public_key);
    if (!r) {
        
		// TODO remove
		printf("STIR-Shaken: Error setting context\n");
        goto err;
    }
    
    sigbio = BIO_new_file(signature_filename, "rb");
    if (sigbio == NULL) {
        
		// TODO remove
		printf("STIR-Shaken: Error opening signature file\n");
		// TODO remove
        goto err;
    }
    siglen = EVP_PKEY_size(public_key);
    sigbuf = malloc(siglen);
    siglen = BIO_read(sigbio, sigbuf, siglen);
    BIO_free(sigbio);
    if (siglen <= 0) {
        
		// TODO remove
		printf("STIR-Shaken: Error reading signature\n");
        ERR_print_errors(bio_err);
        goto err;
    }

    inp = BIO_push(bmd, in);
    
    if (BIO_read_filename(in, data_filename) <= 0) {
        
		// TODO remove
		printf("STIR-Shaken: Error reading data file\n");
        ERR_print_errors(bio_err);
        goto err;
    }

    // Do fp

    for (;sanity--;) {
        i = BIO_read(inp, (char *)buf, BUFSIZE);
        if (i < 0) {
            
			// TODO remove
			printf("STIR-Shaken: Read Error\n");
            ERR_print_errors(bio_err);
            goto err;
        }
        if (i == 0) {
            break;
        }
    }
    BIO_get_md_ctx(inp, &ctx);
    i = EVP_DigestVerifyFinal(ctx, sigbuf, (unsigned int)siglen);
    if (i > 0) {
		
		// TODO remove
        printf("STIR-Shaken: Verified OK\n");
        res = 0;
    } else if (i == 0) {
		
		// TODO remove
        printf("STIR-Shaken: Signature/data failed verification\n");
        res = 1;
    } else {
		
		// TODO remove
        printf("STIR-Shaken: Error Verifying Data\n");
        res = 2;
        ERR_print_errors(bio_err);
    }

    if (buf) {
        free(buf);
    }
    if (sigbuf) {
        free(sigbuf);
    }
    if (bio_err) {
        BIO_free(bio_err);
    }
    if (in) {
        BIO_free(in);
    }
    if (bmd) {
        BIO_free(bmd);
    }
    return res;

err:
    if (sigbuf) {
        free(sigbuf);
    }
    if (buf) {
        free(buf);
    }
    if (bio_err) {
        BIO_free(bio_err);
    }
    if (in) {
        BIO_free(in);
    }
    if (bmd) {
        BIO_free(bmd);
    }
    return -1;
}


static int stir_shaken_verify_data_with_cert(const char *data, size_t datalen, const unsigned char *signature, size_t siglen, stir_shaken_cert_t *cert)
{
    EVP_PKEY *pkey = NULL;

    // Get EVP_PKEY public key from cert
    if (!cert || !cert->x || !(pkey = X509_get_pubkey(cert->x))) {
        return -1;
    }

    return stir_shaken_do_verify_data(data, datalen, signature, siglen, pkey);
}


stir_shaken_status_t stir_shaken_verify_with_cert(const char *identity_header, stir_shaken_cert_t *cert)
{
    char *challenge = NULL;
    unsigned char signature[BUFSIZE] = {0};
    char *b = NULL, *e = NULL, *se = NULL, *sig = NULL;
    int len = 0, challenge_len = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

    if (!identity_header || !cert) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    
    // Identity header is in the form header_base64.payload_base64.signature_base64
    // (TODO docs do not say signature is Base64 encoded, but I do that)
    // Data (challenge) to verify signature is "header_base64.payload_base64"

    b = strchr(identity_header, '.');
    if (!b || (b + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    e = strchr(b + 1, '.');
    if (!e || (e + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    se = strchr(e + 1, ';');
    if (!se || (se + 1 == strchr(identity_header, '\0'))) {
        return STIR_SHAKEN_STATUS_FALSE;
    }

    len = e - identity_header;
    challenge_len = len;
    challenge = malloc(challenge_len);
    if (!challenge) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    memcpy(challenge, identity_header, challenge_len);
    
    len = se - e;
    sig = malloc(len);
    if (!sig) {
		goto fail;
    }
    memcpy(sig, e + 1, len);
    sig[len - 1] = '\0';

    len = stir_shaken_b64_decode(sig, (char*)signature, BUFSIZE); // decode signature from SIP Identity Header (cause we encode it Base64, TODO confirm, they don't Base 64 cause ES256 would produce ASCII maybe while our current signature is not printable and of different length, something is not right with our signature, oh dear),
    // alternatively we would do signature = stir_shaken_core_strdup(stir_shaken_globals.pool, e + 1);
    
    if (stir_shaken_verify_data_with_cert(challenge, challenge_len, signature, len - 1, cert) != 0) { // len - 1 cause _b64_decode appends '\0' and counts it
        goto fail;
    }

    status = STIR_SHAKEN_STATUS_OK;

fail:
	if (challenge) {
		free(challenge);
		challenge = NULL;
	}
	if (sig) {
		free(sig);
		sig = NULL;
	}
	return status;
}

static size_t curl_callback(void *contents, size_t size, size_t nmemb, void *p)
{
	char *m = NULL;
	size_t realsize = size * nmemb;
	mem_chunk_t *mem = (mem_chunk_t *) p;

	printf("STIR-Shaken: CURL: Download progress: got %zu bytes (%zu total)\n", realsize, mem->size);

	m = realloc(mem->mem, mem->size + realsize + 1);
	if(!m) {
		printf("STIR-Shaken: realloc returned NULL\n");
		return 0;
	}

	mem->mem = m;
	memcpy(&(mem->mem[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->mem[mem->size] = 0;

	return realsize;
}

stir_shaken_status_t stir_shaken_download_cert(const char *url, mem_chunk_t *chunk)
{
	CURL *curl_handle = NULL;
	CURLcode res = 0;
    stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	chunk->mem = malloc(1);
	chunk->size = 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);

	// Some pple say, some servers don't like requests that are made without a user-agent field, so we provide one.
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		
		// TODO remove
		printf("STIR-Shaken: Download: Error in CURL: %s\n", curl_easy_strerror(res));
        status = STIR_SHAKEN_STATUS_FALSE;

	} else {

		// TODO remove
		printf("STIR-Shaken: Download: Got %zu bytes\n", chunk->size);
        status = STIR_SHAKEN_STATUS_OK;
	}

	curl_easy_cleanup(curl_handle);
	curl_global_cleanup();

	return status;
}

void stir_shaken_cert_configure(stir_shaken_cert_t *cert, char *install_path, char *install_url)
{
	char b[500] = {0};
	int c = strlen(install_path);
	int d = strlen(install_url);
	int e = 0;

	if (cert) {

		cert->install_path = malloc(c + 1);
		cert->install_url = malloc(d + 1);
		if (!cert->install_path || !cert->install_url) return;
		memcpy(cert->install_path, install_path, c);
		memcpy(cert->install_url, install_url, d);
		cert->install_path[c] = '\0';
		cert->install_url[d] = '\0';
	
		snprintf(b, 500, "%s%s", cert->install_url, cert->name);
		e = strlen(b);
		cert->access = malloc(e + 1);
		memcpy(cert->access, b, e);
		cert->access[e] = '\0';
	}
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

stir_shaken_status_t stir_shaken_download_cert_to_file(const char *url, const char *file)
{
	CURL *curl;
	FILE *fp;
	CURLcode res = CURLE_FAILED_INIT;
	curl = curl_easy_init();
	if (curl) {
		fp = fopen(file,"wb");
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		/* always cleanup */
		curl_easy_cleanup(curl);
		fclose(fp);
	}

	if (res != CURLE_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}
	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_verify(const char *sih, const char *cert_url)
{
	stir_shaken_cert_t cert = {0};
    mem_chunk_t chunk = { .mem = NULL, .size = 0};
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	
	if (!sih || !cert_url) {
		goto fail;
	}

	// TODO remove
	printf("STIR-Shaken: Verify: cert URL is: %s\n", cert_url);

	// Download cert

	// TODO remove
	printf("STIR-Shaken: Verify: downloading cert...\n");

	if (stir_shaken_download_cert(cert_url, &chunk) != STIR_SHAKEN_STATUS_OK) {
		printf("STIR-Shaken: Verify: error downloading\n");
		goto fail;
	}

	// Load into X509

	// TODO remove
	printf("STIR-Shaken: Verify: loading cert from memory into X509...\n");

    if (stir_shaken_load_cert_from_mem(&cert.x, chunk.mem, chunk.size) != STIR_SHAKEN_STATUS_OK) {
	
		// TODO remove
		printf("STIR-Shaken: Verify: error loading cert\n");
		goto fail;
    }
	
	// TODO copy cert into cert.body
	cert.body = malloc(chunk.size);
	if (!cert.body) {
	
		// TODO remove
		printf("STIR-Shaken: Verify: out of memory\n");
		goto fail;
	}
	memcpy(cert.body, chunk.mem, chunk.size);
	cert.len = chunk.size;

	// Verify signature
	
	// TODO remove
	printf("STIR-Shaken: Verify: checking signature...\n");

	if (stir_shaken_verify_with_cert(sih, &cert) != STIR_SHAKEN_STATUS_OK) {
		printf("STIR-Shaken: Verify: FAIL (spoofed)\n");
		goto fail;
	}

	// TODO remove
	printf("STIR-Shaken: Verify: PASS\n");
    
	status = STIR_SHAKEN_STATUS_OK;

fail:
    if (chunk.mem) {
        free(chunk.mem);
		chunk.mem = NULL;
    }
	// TODO remove
	printf("STIR-Shaken: Verify: FAIL\n");
	return status;
}
