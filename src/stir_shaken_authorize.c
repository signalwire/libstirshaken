#include "stir_shaken.h"


stir_shaken_status_t stir_shaken_cert_configure(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, const char *name, const char *install_dir, const char *install_url)
{
    char a[500] = {0};
    char b[500] = {0};
    int c = 0;
    int d = 0;
    int n = 0;
    int e = 0;


    stir_shaken_clear_error(ss);

    if (!cert) {
        stir_shaken_set_error(ss, "Cert configure: Cert not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }


	// TODO check if dirs exist

    // Cert's installation dir

    if (install_dir) {

        c = strlen(install_dir);
        cert->install_dir = malloc(c + 5);
        if (!cert->install_dir) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->install_dir, 0, c + 5);
        e = snprintf(b, 500, "%s/", install_dir);
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->install_dir, b, e);
        stir_shaken_remove_multiple_adjacent(cert->install_dir, '/');
    }

    // Cert's installation URL

    if (install_url) {
    
        d = strlen(install_url);
        cert->install_url = malloc(d + 15);
        if (!cert->install_url) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->install_url, 0, d + 15);
        e = snprintf(b, 500, "%s/", install_url);
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->install_url, b, e);
        if (strstr(cert->install_url, "http://") == cert->install_url) {
            stir_shaken_remove_multiple_adjacent(cert->install_url + 7, '/');
        } else {
            stir_shaken_remove_multiple_adjacent(cert->install_url, '/');
        }
    }

    // Cert's full name

    if (name) {
        
        n = strlen(name);

        cert->original_name = strdup(name);
        
        memcpy(a, name, n + 1);
        cert->basename = strdup(basename(a));

        cert->full_name = malloc(c + n + 5);
        if (!cert->full_name) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->full_name, 0, c + n + 5);
        if (install_dir) {
            memcpy(a, name, n + 1);
            e = snprintf(b, 500, "%s/%s", install_dir, basename(a));
        } else {
            e = snprintf(b, 500, "%s", basename(a));
        }
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->full_name, b, e);
        stir_shaken_remove_multiple_adjacent(cert->full_name, '/');

        // Cert's publicly accessible URL
        cert->public_url = malloc(d + n + 5);
        if (!cert->public_url) {
            stir_shaken_set_error(ss, "Cert configure: Cannot allocate memory", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memset(cert->public_url, 0, d + n + 5);
        if (install_url) {
            e = snprintf(b, 500, "%s/%s", install_url, cert->name);
        } else {
            e = snprintf(b, 500, "%s", cert->name);
        }
        if (e >= 500) {
            stir_shaken_set_error(ss, "Cert configure: Buffer too short", STIR_SHAKEN_ERROR_GENERAL);
            return STIR_SHAKEN_STATUS_FALSE;
        }
        memcpy(cert->public_url, b, e);
        if (strstr(cert->public_url, "http://") == cert->public_url) {
            stir_shaken_remove_multiple_adjacent(cert->public_url + 7, '/');
        } else {
            stir_shaken_remove_multiple_adjacent(cert->public_url, '/');
        }
    }

    return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_install_cert(stir_shaken_context_t *ss, stir_shaken_cert_t *cert)
{
	BIO *out = NULL;
	int i = 0;
	char			err_buf[STIR_SHAKEN_ERROR_BUF_LEN] = { 0 };

	stir_shaken_clear_error(ss);

    if (!cert) {
		stir_shaken_set_error(ss, "Cert not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }
    
	if (!cert->x) {
		stir_shaken_set_error(ss, "X509 cert not set", STIR_SHAKEN_ERROR_SSL);
        return STIR_SHAKEN_STATUS_FALSE;
    }
	
	if (!cert->full_name) {
        
		stir_shaken_set_error(ss, "Cert's @full_name not set. Where should I create the cert? How would others verify the call if I don't know where to place the certificate? Please configure certificate.", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }

	if (stir_shaken_file_exists(cert->full_name) == STIR_SHAKEN_STATUS_OK) {
		stir_shaken_file_remove(cert->full_name);
	}

	out = BIO_new(BIO_s_file());
	if (!out) goto fail;
	i = BIO_write_filename(out, (char*) cert->full_name);
	if (i == 0) {
		
		sprintf(err_buf, "Failed to redirect bio to file %s. Does dir %s exist?", cert->full_name, cert->install_dir);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL);
		goto fail;
	}

	i = PEM_write_bio_X509(out, cert->x);
	if (i == 0) {
	
		sprintf(err_buf, "Failed to write certificate to file %s. Does dir %s exist?", cert->full_name, cert->install_dir);
		stir_shaken_set_error(ss, err_buf, STIR_SHAKEN_ERROR_SSL);
		goto fail;
	}

	BIO_free_all(out);
	out = NULL;

	return STIR_SHAKEN_STATUS_OK;

fail:
	if (out) {
		BIO_free_all(out);
	}
	
	stir_shaken_set_error_if_clear(ss, "Failed to install cert", STIR_SHAKEN_ERROR_GENERAL);

	return STIR_SHAKEN_STATUS_FALSE;
}
