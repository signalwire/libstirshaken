#include "stir_shaken.h"


stir_shaken_globals_t stir_shaken_globals;
stir_shaken_status_t	(*stir_shaken_make_http_req)(stir_shaken_context_t *ss, stir_shaken_http_req_t *http_req) = stir_shaken_make_http_req_real;

static void stir_shaken_init(void)
{
    stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_NOTHING);
    return;
}

stir_shaken_status_t stir_shaken_do_init(stir_shaken_context_t *ss, const char *ca_dir, const char *crl_dir, int loglevel)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	ks_init();

	if (stir_shaken_globals.initialised) {
		stir_shaken_set_error(ss, "Already initialised", STIR_SHAKEN_ERROR_GENERAL);
		status = STIR_SHAKEN_STATUS_NOOP;
		goto err;
	}

	stir_shaken_globals.loglevel = loglevel;
	
	if (pthread_mutexattr_init(&stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error(ss, "Init mutex attr failed", STIR_SHAKEN_ERROR_GENERAL);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto err;
	}

	pthread_mutexattr_settype(&stir_shaken_globals.attr, PTHREAD_MUTEX_RECURSIVE);
	
	if (pthread_mutex_init(&stir_shaken_globals.mutex, &stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error(ss, "Init mutex failed", STIR_SHAKEN_ERROR_GENERAL);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto err;
	}

	// TODO CA list and CRL will be passed here
	status = stir_shaken_init_ssl(ss, ca_dir, crl_dir);
	if (status != STIR_SHAKEN_STATUS_OK && status != STIR_SHAKEN_STATUS_NOOP) {
	
		stir_shaken_set_error_if_clear(ss, "Init SSL failed\n", STIR_SHAKEN_ERROR_GENERAL);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto err;
	}

    stir_shaken_make_http_req = stir_shaken_make_http_req_real;

	stir_shaken_globals.initialised = 1;
	return STIR_SHAKEN_STATUS_OK;

err:
    ks_shutdown();
    return status;
}

static void stir_shaken_deinit(void)
{
    return stir_shaken_do_deinit();
}

void stir_shaken_do_deinit(void)
{
    pthread_mutex_lock(&stir_shaken_globals.mutex);

    if (stir_shaken_globals.initialised == 0) {
        return;
    }

    stir_shaken_globals.initialised = 0;

    // TODO deinit settings (path, etc)

    stir_shaken_deinit_ssl();

    pthread_mutex_unlock(&stir_shaken_globals.mutex);
    pthread_mutex_destroy(&stir_shaken_globals.mutex);
    pthread_mutexattr_destroy(&stir_shaken_globals.attr);

    ks_shutdown();
}

stir_shaken_status_t stir_shaken_dir_exists(const char *path)
{
    struct stat sb;

    if (path && stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return STIR_SHAKEN_STATUS_OK;
    }

    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_dir_create(const char *path)
{
    if (path && mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) == 0) {
        return STIR_SHAKEN_STATUS_OK;
    }

    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_dir_create_recursive(const char *path)
{
    char	*p = NULL, *tmp = NULL;
    size_t	len = 0;

    if (!path) {
        return STIR_SHAKEN_STATUS_FALSE;
    }

    len = strlen(path);
    tmp = malloc(len + 1);
    if (!tmp) {
        return STIR_SHAKEN_STATUS_FALSE;
    }
    memcpy(tmp, path, len);
    tmp[len] = '\0';

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++) {

        if (*p == '/') {

            *p = 0;

            if (stir_shaken_dir_exists(tmp) == STIR_SHAKEN_STATUS_FALSE) {

                if (mkdir(tmp, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) != 0 && errno != EEXIST) {
                    goto fail;
                }
            }

            *p = '/';
        }
    }

	if (stir_shaken_dir_exists(tmp) == STIR_SHAKEN_STATUS_FALSE) {
		if (mkdir(tmp, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) != 0 && errno != EEXIST) {
			goto fail;
		}
	}

    if (tmp) {
        free(tmp);
        tmp = NULL;
    }

    return STIR_SHAKEN_STATUS_OK;

fail:
    if (tmp) {
        free(tmp);
        tmp = NULL;
    }
    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_file_exists(const char *path)
{
    struct stat sb;

    if (path && stat(path, &sb) == 0 && S_ISREG(sb.st_mode)) {
        return STIR_SHAKEN_STATUS_OK;
    }

    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_file_remove(const char *path)
{
    if (remove(path) == 0) {
        return STIR_SHAKEN_STATUS_OK;
    }

    return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_save_to_file(stir_shaken_context_t *ss, const char *data, const char *name)
{
    FILE			*fp = NULL;
    size_t			datalen = 0;

    if (!data || stir_shaken_zstr(name)) {
        return STIR_SHAKEN_STATUS_TERM;
    }

    datalen = strlen(data);

    fp = fopen(name, "w");
    if (!fp) {
        stir_shaken_set_error(ss, "Can't open file for writing", STIR_SHAKEN_ERROR_FILE_OPEN);
        return STIR_SHAKEN_STATUS_RESTART;
    }

    if (datalen != fwrite(data, 1, datalen, fp)) {
        fclose(fp);
        stir_shaken_set_error(ss, "Error writing to file", STIR_SHAKEN_ERROR_FILE_WRITE);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    fclose(fp);
    return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_append_to_file(stir_shaken_context_t *ss, const char *data, const char *name)
{
    FILE			*fp = NULL;
    size_t			datalen = 0;

    if (!data || stir_shaken_zstr(name)) {
        return STIR_SHAKEN_STATUS_TERM;
    }

    datalen = strlen(data);

    fp = fopen(name, "a");
    if (!fp) {
        stir_shaken_set_error(ss, "Can't open file for writing", STIR_SHAKEN_ERROR_FILE_OPEN);
        return STIR_SHAKEN_STATUS_RESTART;
    }

    if (datalen != fwrite(data, 1, datalen, fp)) {
        fclose(fp);
        stir_shaken_set_error(ss, "Error writing to file", STIR_SHAKEN_ERROR_FILE_WRITE);
        return STIR_SHAKEN_STATUS_FALSE;
    }

    fclose(fp);
    return STIR_SHAKEN_STATUS_OK;
}

static const char stir_shaken_b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64BUFFLEN 1024

stir_shaken_status_t stir_shaken_b64_encode(unsigned char *in, size_t ilen, unsigned char *out, size_t olen)
{
    int y = 0, bytes = 0;
    size_t x = 0;
    unsigned int b = 0, l = 0;

    for (x = 0; x < ilen; x++) {
        b = (b << 8) + in[x];
        l += 8;

        while (l >= 6) {
            out[bytes++] = stir_shaken_b64_table[(b >> (l -= 6)) % 64];
            if (bytes >= (int)olen - 1) {
                goto end;
            }
            if (++y != 72) {
                continue;
            }
            /* out[bytes++] = '\n'; */
            y = 0;
        }
    }

    if (l > 0) {
        out[bytes++] = stir_shaken_b64_table[((b % 16) << (6 - l)) % 64];
    }
    if (l != 0) {
        while (l < 6 && bytes < (int)olen - 1) {
            out[bytes++] = '=', l += 2;
        }
    }

end:

    out[bytes] = '\0';

    return STIR_SHAKEN_STATUS_OK;
}

size_t stir_shaken_b64_decode(const char *in, char *out, size_t olen)
{
    char l64[256];
    int b = 0, c, l = 0, i;
    const char *ip;
    char *op = out;
    size_t ol = 0;

    for (i = 0; i < 256; i++) {
        l64[i] = -1;
    }

    for (i = 0; i < 64; i++) {
        l64[(int) stir_shaken_b64_table[i]] = (char) i;
    }

    for (ip = in; ip && *ip; ip++) {
        c = l64[(int) *ip];
        if (c == -1) {
            continue;
        }

        b = (b << 6) + c;
        l += 6;

        while (l >= 8) {
            op[ol++] = (char) ((b >> (l -= 8)) % 256);
            if (ol >= olen - 2) {
                goto end;
            }
        }
    }

end:

    op[ol++] = '\0';

    return ol;
}

char* stir_shaken_remove_multiple_adjacent(char *in, char what)
{
    char *ip = in, *op = in;

    if (!in) return NULL;

    do {

        *op = *ip;
        ++ip;

        // TODO extend for multichar path separators
        while (*op == what && *ip == what) {
            ++ip;
        };

        ++op;
    } while (*ip != '\0');

    *op = '\0';

    return in;
}

char* stir_shaken_get_dir_path(const char *path)
{
    char *p = NULL, *res = NULL, *p1 = NULL, *p2 = NULL;
    const char *dname = NULL;
    const char *bname = NULL;
    int len = 0;

    if (!path) return NULL;

    if (!(p1 = strdup(path))) return NULL;
    dname = dirname(p1);

    if (!(p2 = strdup(path))) {
        free(p1);
        return NULL;
    }

    bname = basename(p2);

    len = strlen(dname) + 1 + strlen(bname) + 1 + 1;

    p = malloc(len);
    if (!p) {
        free(p1);
        free(p2);
        return NULL;
    }

    // TODO use path separator variable, and extend for multichar path separators
    sprintf(p, "%s/%s/", dname, bname);

    free(p1);
    free(p2);

    return stir_shaken_remove_multiple_adjacent(p, '/');
}

char* stir_shaken_make_complete_path(char *buf, int buflen, const char *dir, const char *file, const char *path_separator)
{
    int e = 0;

    if (!buf || !dir || !file || (buflen < strlen(dir) + 1 + strlen(file) + 1)) return NULL;

    e = snprintf(buf, buflen, "%s%s%s", dir, path_separator, file);
    if (e >= buflen) {
        return NULL;
    }

    // TODO extend for multichar path separators
    return stir_shaken_remove_multiple_adjacent(buf, *path_separator);
}

const char* stir_shaken_path_to_base_file_name(const char *path)
{
    char *p = NULL;
    return ((p = strrchr(path, '/')) ? ++p : path);
}

// Return 1 if string is NULL or empty (0-length) [i.e. has no content: "\0"] 
int stir_shaken_zstr(const char *str)
{
    if (!str || (0 == strlen(str)))
        return 1;
    return 0;
}

static void shift_errors(stir_shaken_context_t *ss) {
    if (!ss) return;
    strncpy(ss->e.err_buf5, ss->e.err_buf4, STIR_SHAKEN_ERROR_BUF_LEN);
    strncpy(ss->e.err_buf4, ss->e.err_buf3, STIR_SHAKEN_ERROR_BUF_LEN);
    strncpy(ss->e.err_buf3, ss->e.err_buf2, STIR_SHAKEN_ERROR_BUF_LEN);
    strncpy(ss->e.err_buf2, ss->e.err_buf1, STIR_SHAKEN_ERROR_BUF_LEN);
    strncpy(ss->e.err_buf1, ss->e.err_buf0, STIR_SHAKEN_ERROR_BUF_LEN);
}

void stir_shaken_do_set_error(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line)
{
    int i = 0, j = 0;

    if (!ss) return;

    shift_errors(ss);

    memset(ss->e.err_buf0, 0, STIR_SHAKEN_ERROR_BUF_LEN);
    sprintf(ss->e.err_buf0, "%s:%d: [error_code: %d] ", file, line, error);
    i = strlen(ss->e.err_buf0);

    while ((i < STIR_SHAKEN_ERROR_BUF_LEN - 1) && (description[j] != '\0')) {
        ss->e.err_buf0[i] = description[j];
        ++i;
        ++j;
    }

    ss->e.err_buf0[i] = '\0';
    ss->e.error = error;
    ss->e.got_error = 1;
}

void stir_shaken_do_set_error_if_clear(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line)
{
    if (ss) {

        if (!ss->e.got_error) {
            stir_shaken_do_set_error(ss, description, error, file, line);
        }
    }
}

void stir_shaken_clear_error(stir_shaken_context_t *ss)
{
    if (!ss) return;
    memset(&ss->e, 0, sizeof(ss->e));
}

uint8_t stir_shaken_is_error_set(stir_shaken_context_t *ss)
{
    if (!ss) return 0;
    return (ss->e.got_error ? 1 : 0);
}

static const char* stir_shaken_get_error_string(stir_shaken_context_t *ss)
{
    if (!ss) return NULL;

    if (stir_shaken_is_error_set(ss)) {

        if (!stir_shaken_zstr(ss->e.err_buf5)) {
            snprintf(ss->e.err, sizeof(ss->e.err), "Error stack (top to bottom, outermost first - deepest last):\n[ERR 0] %s\n[ERR 1] %s\n[ERR 2] %s\n[ERR 3] %s\n[ERR 4] %s\n[ERR 5] %s\n", ss->e.err_buf0, ss->e.err_buf1, ss->e.err_buf2, ss->e.err_buf3, ss->e.err_buf4, ss->e.err_buf5);
        } else if (!stir_shaken_zstr(ss->e.err_buf4)) {
            snprintf(ss->e.err, sizeof(ss->e.err), "Error stack (top to bottom, outermost first - deepest last):\n[ERR 0] %s\n[ERR 1] %s\n[ERR 2] %s\n[ERR 3] %s\n[ERR 4] %s\n", ss->e.err_buf0, ss->e.err_buf1, ss->e.err_buf2, ss->e.err_buf3, ss->e.err_buf4);
        } else if (!stir_shaken_zstr(ss->e.err_buf3)) {
            snprintf(ss->e.err, sizeof(ss->e.err), "Error stack (top to bottom, outermost first - deepest last):\n[ERR 0] %s\n[ERR 1] %s\n[ERR 2] %s\n[ERR 3] %s\n", ss->e.err_buf0, ss->e.err_buf1, ss->e.err_buf2, ss->e.err_buf3);
        } else if (!stir_shaken_zstr(ss->e.err_buf2)) {
            snprintf(ss->e.err, sizeof(ss->e.err), "Error stack (top to bottom, outermost first - deepest last):\n[ERR 0] %s\n[ERR 1] %s\n[ERR 2] %s\n", ss->e.err_buf0, ss->e.err_buf1, ss->e.err_buf2);
        } else if (!stir_shaken_zstr(ss->e.err_buf1)) {
            snprintf(ss->e.err, sizeof(ss->e.err), "Error stack (top to bottom), outermost first - deepest last:\n[ERR 0] %s\n[ERR 1] %s\n", ss->e.err_buf0, ss->e.err_buf1);
        } else {
            snprintf(ss->e.err, sizeof(ss->e.err), "[ERR 0] %s\n", ss->e.err_buf0);
        }

        return ss->e.err;
    }

    return "No description provided";
}

stir_shaken_error_t stir_shaken_get_error_code(stir_shaken_context_t *ss)
{
    if (!stir_shaken_is_error_set(ss)) {
        // This function must always be called with ss pointer set and only if error has been set,
        // otherwise will return spurious results.
        return STIR_SHAKEN_ERROR_GENERAL;
    }

    return ss->e.error;
}

const char* stir_shaken_get_error(stir_shaken_context_t *ss, stir_shaken_error_t *error)
{
    if (!ss || !stir_shaken_is_error_set(ss)) return NULL;
    if (error) {
        *error = stir_shaken_get_error_code(ss);
    }
    return stir_shaken_get_error_string(ss);
}

void stir_shaken_destroy_callback_arg(stir_shaken_callback_arg_t *arg)
{
	if (!arg) return;
	stir_shaken_destroy_cert(&arg->cert);
	memset(arg, 0, sizeof(*arg));
}

void stir_shaken_destroy_context(stir_shaken_context_t *ss)
{
	if (!ss) return;
	stir_shaken_clear_error(ss);
	stir_shaken_destroy_callback_arg(&ss->callback_arg);
	memset(ss, 0, sizeof(*ss));
}

size_t stir_shaken_hash_hash(size_t hashsize, size_t key)
{
    if (hashsize < 1) return 0;
    return key % hashsize;
}

stir_shaken_hash_entry_t* stir_shaken_hash_entry_find(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key)
{
    size_t idx = 0;
    stir_shaken_hash_entry_t *e = NULL;

    if (!hash || hashsize < 1) return NULL;

    idx = stir_shaken_hash_hash(hashsize, key);
    e = hash[idx];

    do {	
        if (e && e->key == key)
            return e;
    } while (e && (e = e->next));

    return NULL;
}

stir_shaken_hash_entry_t* stir_shaken_hash_entry_create(size_t key, void *data, int datalen, void *dctor, int hash_copy_type)
{
    stir_shaken_hash_entry_t *entry = NULL;

    entry = malloc(sizeof(stir_shaken_hash_entry_t));
    if (!entry)
        return NULL;
    memset(entry, 0, sizeof(*entry));

    entry->key = key;
    if ((hash_copy_type == STIR_SHAKEN_HASH_TYPE_SHALLOW) || (hash_copy_type == STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE)) {
        entry->data = data;
    } else {
        if (!(entry->data = malloc(datalen))) {
            free(entry);
            return NULL;
        }
        memcpy(entry->data, data, datalen);
    }
    entry->dctor = dctor;
    entry->next = NULL;

    return entry;
}

void stir_shaken_hash_entry_destroy(stir_shaken_hash_entry_t *e, int hash_copy_type)
{
    if (!e) return;
    if (e->dctor) {
        e->dctor(e->data);
        e->dctor = NULL;
    }
    if (e->data) {
        if (hash_copy_type == STIR_SHAKEN_HASH_TYPE_DEEP || hash_copy_type == STIR_SHAKEN_HASH_TYPE_SHALLOW_AUTOFREE) {
            free(e->data);
        }
        e->data = NULL;
    }
    free(e);
}

stir_shaken_hash_entry_t* stir_shaken_hash_entry_add(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key, void *data, int datalen, stir_shaken_hash_entry_destructor dctor, int hash_copy_type)
{
    size_t idx = 0;
    stir_shaken_hash_entry_t *e = NULL, *entry = NULL;

    if (!hash || hashsize < 1) return NULL;

    e = stir_shaken_hash_entry_find(hash, hashsize, key);
    if (e)
        return NULL;

    entry = stir_shaken_hash_entry_create(key, data, datalen, dctor, hash_copy_type);
    if (!entry)
        return NULL;

    idx = stir_shaken_hash_hash(hashsize, key);

    if (hash[idx] == NULL) {
        hash[idx] = entry;
    } else {

        e = hash[idx];

        while (e->next) {
            e = e->next;
        };
        e->next = entry;
    }

    return entry;
}

stir_shaken_status_t stir_shaken_hash_entry_remove(stir_shaken_hash_entry_t **hash, size_t hashsize, size_t key, int hash_copy_type)
{
    size_t idx = 0;
    stir_shaken_hash_entry_t *e = NULL, *prev = NULL;

    if (!hash || hashsize < 1) return STIR_SHAKEN_STATUS_TERM;

    idx = stir_shaken_hash_hash(hashsize, key);
    e = hash[idx];

    do {
        if (!e) return STIR_SHAKEN_STATUS_FALSE;		
        if (e->key == key) {
            if (prev) {
                prev->next = e->next;
            } else {
                hash[idx] = e->next;
            }
            stir_shaken_hash_entry_destroy(e, hash_copy_type);
            return STIR_SHAKEN_STATUS_OK;
        }
        prev = e;
    } while ((e = e->next));

    return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_hash_destroy_branch(stir_shaken_hash_entry_t *entry, int hash_copy_type)
{
    stir_shaken_hash_entry_t *e = NULL, *prev = NULL;

    if (!entry) return;

    e = entry;

    do {
        prev = e;
        e = e->next;
        stir_shaken_hash_entry_destroy(prev, hash_copy_type);
    } while (e);
}

void stir_shaken_hash_destroy(stir_shaken_hash_entry_t **hash, size_t hashsize, int hash_copy_type)
{
    size_t idx = 0;
    stir_shaken_hash_entry_t *e = NULL;

    if (!hash || hashsize < 1) return;

    while (idx < hashsize) {
        e = hash[idx];
        stir_shaken_hash_destroy_branch(e, hash_copy_type);
        hash[idx] = NULL;
        ++idx;
    }
    memset(hash, 0, sizeof(stir_shaken_hash_entry_t*) * hashsize);
}

size_t stir_shaken_key_hash(unsigned char *pub_raw, size_t pub_raw_len, size_t hashsize)
{
	size_t i = 0;
	size_t hash = 0;

	while (i < pub_raw_len) {

		hash += pub_raw[i];
		hash %= hashsize;
		++i;
	}

	return hash;
}

stir_shaken_status_t stir_shaken_is_key_trusted(stir_shaken_context_t *ss, EVP_PKEY *pkey, stir_shaken_hash_entry_t **trusted_keys, size_t hashsize)
{
    stir_shaken_hash_entry_t *e = NULL;
	EVP_PKEY *candidate_pkey = NULL;
	size_t i = 0;
	size_t hash = 0;
	unsigned char	candidate_pub_raw[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int				candidate_pub_raw_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;
	unsigned char	pub_raw[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int				pub_raw_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;


    if (STIR_SHAKEN_STATUS_OK != stir_shaken_pubkey_to_raw(ss, pkey, pub_raw, &pub_raw_len)) {
		stir_shaken_set_error(ss, "Can't get raw public key from EVP_PKEY", STIR_SHAKEN_ERROR_EVP_PKEY_TO_RAW);
		return STIR_SHAKEN_STATUS_ERR;
	}

	hash = stir_shaken_key_hash(pub_raw, pub_raw_len, hashsize);

	e = stir_shaken_hash_entry_find(trusted_keys, hashsize, hash);
	if (!e) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	candidate_pkey = e->data;

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_pubkey_to_raw(ss, candidate_pkey, candidate_pub_raw, &candidate_pub_raw_len)) {
		stir_shaken_set_error(ss, "Can't get raw public key from EVP_PKEY", STIR_SHAKEN_ERROR_EVP_PKEY_TO_RAW);
		return STIR_SHAKEN_STATUS_ERR;
	}

	// Raw memory check
	if (pub_raw_len != candidate_pub_raw_len || (0 != memcmp(pub_raw, candidate_pub_raw, pub_raw_len))) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	// Let SSL confirm
	if (!EVP_PKEY_cmp(pkey, candidate_pkey)) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_is_cert_trusted(stir_shaken_context_t *ss, stir_shaken_cert_t *cert, stir_shaken_hash_entry_t **trusted_keys, size_t hashsize)
{
	X509		*x = NULL;
	EVP_PKEY	*pkey = NULL;

	if (!cert || !cert->x) {
		stir_shaken_set_error(ss, "X509 missing", STIR_SHAKEN_ERROR_X509_MISSING);
		return STIR_SHAKEN_STATUS_ERR;
	}

	pkey = X509_get_pubkey(cert->x);
	if (!pkey) {
		stir_shaken_set_error(ss, "Can't load EVP_PKEY from X509", STIR_SHAKEN_ERROR_LOAD_EVP_PKEY);
		goto fail;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_is_key_trusted(ss, pkey, trusted_keys, hashsize)) {
		stir_shaken_set_error(ss, "Key not found in trusted keys", STIR_SHAKEN_ERROR_PA_NOT_TRUSTED);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	EVP_PKEY_free(pkey);

	return STIR_SHAKEN_STATUS_OK;

fail:

	if (pkey) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return STIR_SHAKEN_STATUS_ERR;
}

void stir_shaken_evp_pkey_hash_entry_dctor(void *o)
{
	EVP_PKEY *pkey = (EVP_PKEY *) o;
	if (!pkey) return;
	EVP_PKEY_free(pkey);
}

stir_shaken_status_t stir_shaken_add_cert_trusted(stir_shaken_context_t *ss, X509 *x, stir_shaken_hash_entry_t **trusted_keys, size_t hashsize)
{
	EVP_PKEY	*pkey = NULL;
	size_t hash = 0;
	unsigned char	pub_raw[STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN] = { 0 };
	int				pub_raw_len = STIR_SHAKEN_PUB_KEY_RAW_BUF_LEN;


	if (!x || !trusted_keys) {
		stir_shaken_set_error(ss, "Bad params", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_ERR;
	}

	pkey = X509_get_pubkey(x);
	if (!pkey) {
		stir_shaken_set_error(ss, "Can't load EVP_PKEY from X509", STIR_SHAKEN_ERROR_LOAD_EVP_PKEY);
		goto fail;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_pubkey_to_raw(ss, pkey, pub_raw, &pub_raw_len)) {
		stir_shaken_set_error(ss, "Can't get raw public key from EVP_PKEY", STIR_SHAKEN_ERROR_EVP_PKEY_TO_RAW);
		goto fail;
	}

	hash = stir_shaken_key_hash(pub_raw, pub_raw_len, hashsize);

	if (!stir_shaken_hash_entry_add(trusted_keys, hashsize, hash, pkey, sizeof(pkey), stir_shaken_evp_pkey_hash_entry_dctor, STIR_SHAKEN_HASH_TYPE_SHALLOW)) {
		stir_shaken_set_error(ss, "Cannot add to hash", STIR_SHAKEN_ERROR_PA_ADD);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:

	if (pkey) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return STIR_SHAKEN_STATUS_ERR;
}

stir_shaken_status_t stir_shaken_add_cert_trusted_from_file(stir_shaken_context_t *ss, char *file_name, stir_shaken_hash_entry_t **trusted_keys, size_t hashsize)
{
	X509		*x = NULL;


	x = stir_shaken_load_x509_from_file(ss, file_name);
	if (!x) {
		stir_shaken_set_error(ss, "Can't load X509 from file", STIR_SHAKEN_ERROR_LOAD_X509);
		return STIR_SHAKEN_STATUS_ERR;
	}

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_add_cert_trusted(ss, x, trusted_keys, hashsize)) {
		stir_shaken_set_error(ss, "Cannot add cert to trusted keys", STIR_SHAKEN_ERROR_PA_ADD);
		X509_free(x);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	X509_free(x);

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_default_callback(stir_shaken_callback_arg_t *arg)
{
	if (!arg) return STIR_SHAKEN_STATUS_TERM;

	switch (arg->action) {

		case STIR_SHAKEN_CALLBACK_ACTION_CERT_FETCH_ENQUIRY:
			// Default behaviour for certificate fetch enquiry is to request downloading
			return STIR_SHAKEN_STATUS_NOT_HANDLED;

		default:
			return STIR_SHAKEN_STATUS_NOT_HANDLED;
	}

	return STIR_SHAKEN_STATUS_NOT_HANDLED;
}

time_t stir_shaken_time_elapsed_s(time_t ts, time_t now)
{
    if (ts >= now) return 0;
    return now - ts;
}

stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line)
{
    fprintif(STIR_SHAKEN_LOGLEVEL_HIGH, "FAIL: %s. %s:%d\n", reason, file, line);
    return STIR_SHAKEN_STATUS_FALSE;
}
