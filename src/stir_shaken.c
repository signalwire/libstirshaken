#include "stir_shaken.h"


stir_shaken_globals_t stir_shaken_globals;


static void stir_shaken_init(void)
{
	stir_shaken_do_init(NULL, NULL, NULL);
	return;
}

stir_shaken_status_t stir_shaken_do_init(stir_shaken_context_t *ss, const char *ca_dir, const char *crl_dir)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (stir_shaken_globals.initialised) {
		stir_shaken_set_error(ss, "Already initialised", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_NOOP;
	}
	
	if (pthread_mutexattr_init(&stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error(ss, "Init mutex attr failed", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	pthread_mutexattr_settype(&stir_shaken_globals.attr, PTHREAD_MUTEX_RECURSIVE);
	
	if (pthread_mutex_init(&stir_shaken_globals.mutex, &stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error(ss, "Init mutex failed", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	// TODO CA list and CRL will be passed here
	status = stir_shaken_init_ssl(ss, ca_dir, crl_dir);
	if (status != STIR_SHAKEN_STATUS_OK && status != STIR_SHAKEN_STATUS_NOOP) {
	
		stir_shaken_set_error_if_clear(ss, "Init SSL failed\n", STIR_SHAKEN_ERROR_GENERAL);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_globals.initialised = 1;
	return STIR_SHAKEN_STATUS_OK;
}

static void stir_shaken_deinit(void)
{
	return stir_shaken_do_deinit();
}

void stir_shaken_do_deinit(void)
{
	if (stir_shaken_globals.initialised == 0) {
		return;
	}
	
	stir_shaken_globals.initialised = 0;

	// TODO deinit settings (path, etc)
	
	stir_shaken_deinit_ssl();

	pthread_mutex_unlock(&stir_shaken_globals.mutex);
	pthread_mutex_destroy(&stir_shaken_globals.mutex);
	pthread_mutexattr_destroy(&stir_shaken_globals.attr);
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

				if (mkdir(tmp, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) != 0) {
					goto fail;
				}
			}

			*p = '/';
		}
	}

	if (mkdir(tmp, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) != 0) {
		goto fail;
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

	if (!(p2 = strdup(path))) return NULL;
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

// Return 1 if string is NULL or empty (0-length)
int stir_shaken_zstr(const char *str)
{
	if (!str || (0 == strlen(str)))
		return 1;
	return 0;
}

void stir_shaken_do_set_error(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line)
{
	int i = 0, j = 0;

	if (!ss) return;
	memset(ss->err_buf, 0, STIR_SHAKEN_ERROR_BUF_LEN);
	sprintf(ss->err_buf, "%s:%d\t", file, line);
	i = strlen(ss->err_buf);

	while ((i < STIR_SHAKEN_ERROR_BUF_LEN - 1) && (description[j] != '\0')) {
		ss->err_buf[i] = description[j];
		++i;
		++j;
	}

	ss->err_buf[i] = '\0';
	ss->error = error;
	ss->got_error = 1;
}

void stir_shaken_do_set_error_if_clear(stir_shaken_context_t *ss, const char *description, stir_shaken_error_t error, char *file, int line)
{
	if (ss) {

		if (!ss->got_error) {
			stir_shaken_do_set_error(ss, description, error, file, line);
		}
	}
}

void stir_shaken_clear_error(stir_shaken_context_t *ss)
{
	if (!ss) return;
	memset(ss, 0, sizeof(*ss));
}

uint8_t stir_shaken_is_error_set(stir_shaken_context_t *ss)
{
	if (!ss) return 0;
	return (ss->got_error ? 1 : 0);
}

static const char* stir_shaken_get_error_string(stir_shaken_context_t *ss)
{
	if (!ss) return NULL;
	if (stir_shaken_is_error_set(ss)) {
		return ss->err_buf;
	}
	return "No description provided";
}

stir_shaken_error_t stir_shaken_get_error_code(stir_shaken_context_t *ss)
{
	if (!ss || !stir_shaken_is_error_set(ss)) {
		// This function must always be called with ss pointer set and only if error has been set,
		// otherwise will return spurious results.
		return STIR_SHAKEN_ERROR_GENERAL;
	}

	return ss->error;
}

const char* stir_shaken_get_error(stir_shaken_context_t *ss, stir_shaken_error_t *error)
{
	if (!ss || !stir_shaken_is_error_set(ss)) return NULL;
	if (error) {
		*error = stir_shaken_get_error_code(ss);
	}
	return stir_shaken_get_error_string(ss);
}

stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line)
{
	printf("FAIL: %s. %s:%d\n", reason, file, line);
	return STIR_SHAKEN_STATUS_FALSE;
}
