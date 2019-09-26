#include "stir_shaken.h"


stir_shaken_globals_t stir_shaken_globals;

// Must be called locked
stir_shaken_status_t stir_shaken_settings_set_path(const char *path)
{
	char *p = NULL;

	if (stir_shaken_globals.settings.path) {

		free((void*)stir_shaken_globals.settings.path);
	}

	p = malloc(strlen(path) + 1);
	if (!p) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	memcpy(p, path, strlen(path));
	p[strlen(path)] = '\0';
	stir_shaken_globals.settings.path = p;

	return STIR_SHAKEN_STATUS_OK;
}


static void stir_shaken_init(void)
{
	stir_shaken_do_init(NULL);
	return;
}

stir_shaken_status_t stir_shaken_do_init(stir_shaken_context_t *ss)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	// TODO remove
	printf("STIR-Shaken: init\n");
	
	if (pthread_mutexattr_init(&stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error_string(ss, "init mutex attr failed");
		return STIR_SHAKEN_STATUS_FALSE;
	}

	pthread_mutexattr_settype(&stir_shaken_globals.attr, PTHREAD_MUTEX_RECURSIVE);
	
	if (pthread_mutex_init(&stir_shaken_globals.mutex, &stir_shaken_globals.attr) != 0) {
		
		stir_shaken_set_error_string(ss, "init mutex failed");
		return STIR_SHAKEN_STATUS_FALSE;
	}

	status = stir_shaken_init_ssl(ss);
	if (status != STIR_SHAKEN_STATUS_OK) {
	
		stir_shaken_set_error_string(ss, "init SSL failed\n");
		return STIR_SHAKEN_STATUS_FALSE;
	}

	stir_shaken_globals.initialised = 1;
}

static void stir_shaken_deinit(void)
{
	return stir_shaken_do_deinit();
}

void stir_shaken_do_deinit(void)
{
	// TODO remove
	printf("STIR-Shaken: deinit\n");

	if (stir_shaken_globals.initialised == 0) {
		printf("STIR-Shaken: deinit skipped, already done\n");
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

void stir_shaken_set_error_string(stir_shaken_context_t *ss, const char *err)
{
	int i = 0;

	if (!ss) return;
	
	memset(ss->err_buf, 0, STIR_SHAKEN_ERROR_BUF_LEN);

	while ((i < STIR_SHAKEN_ERROR_BUF_LEN - 1) && (err[i] != '\0')) {
		ss->err_buf[i] = err[i];
		++i;
	}

	ss->err_buf[i] = '\0';
	ss->got_error = 1;
}

void stir_shaken_set_error_string_if_clear(stir_shaken_context_t *ss, const char *err)
{
	if (ss) {

		if (!ss->got_error) {
			stir_shaken_set_error_string(ss, err);
		}
	}
}

void stir_shaken_clear_error_string(stir_shaken_context_t *ss)
{
	if (!ss) return;

	memset(ss->err_buf, 0, STIR_SHAKEN_ERROR_BUF_LEN);
	ss->got_error = 0;
}

stir_shaken_status_t stir_shaken_test_die(const char *reason, const char *file, int line)
{
	printf("FAIL: %s. %s:%d\n", reason, file, line);
	return STIR_SHAKEN_STATUS_FALSE;
}
