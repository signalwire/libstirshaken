#include "stir_shaken.h"


stir_shaken_status_t stir_shaken_cert_configure(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, const char *name, const char *install_dir, const char *install_url)
{
    stir_shaken_clear_error(ss);

    if (!cert) {
        stir_shaken_set_error(ss, "Cert configure: Cert not set", STIR_SHAKEN_ERROR_GENERAL);
        return STIR_SHAKEN_STATUS_FALSE;
    }

	if (name) {
        strncpy(cert->name, name, STIR_SHAKEN_BUFLEN);
	}

    if (install_dir) {
		snprintf(cert->install_dir, STIR_SHAKEN_BUFLEN, "%s/", install_dir);
        stir_shaken_remove_multiple_adjacent(cert->install_dir, '/');
    }

    if (install_url) {
    
		snprintf(cert->install_url, STIR_SHAKEN_BUFLEN, "%s", install_url);
        
		if (strstr(cert->install_url, "http://") == cert->install_url) {
            stir_shaken_remove_multiple_adjacent(cert->install_url + 7, '/');
        } else {
            stir_shaken_remove_multiple_adjacent(cert->install_url, '/');
        }
    }

    if (name) {
        
		if (install_dir) {
			snprintf(cert->full_name, STIR_SHAKEN_BUFLEN, "%s/%s", install_dir, cert->name);
		} else {
			strncpy(cert->full_name, cert->name, STIR_SHAKEN_BUFLEN);
		}
        stir_shaken_remove_multiple_adjacent(cert->full_name, '/');

        snprintf(cert->full_name_text, STIR_SHAKEN_BUFLEN, "%s.text", cert->full_name);

        if (install_url) {
            snprintf(cert->public_url, STIR_SHAKEN_BUFLEN, "%s/%s", install_url, cert->name);
        } else {
            snprintf(cert->public_url, STIR_SHAKEN_BUFLEN, "%s", cert->name);
        }
        
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
