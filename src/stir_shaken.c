#include "stir_shaken.h"


switch_stir_shaken_globals_t stir_shaken_globals;

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
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	// TODO remove
	printf("STIR-Shaken: init\n");
	
	if (pthread_mutexattr_init(&stir_shaken_globals.attr) != 0) {
		
		// TODO remove
		printf("STIR-Shaken: init mutex attr failed\n");
		return;
	}

	pthread_mutexattr_settype(&stir_shaken_globals.attr, PTHREAD_MUTEX_RECURSIVE);
	
	if (pthread_mutex_init(&stir_shaken_globals.mutex, &stir_shaken_globals.attr) != 0) {
		
		// TODO remove
		printf("STIR-Shaken: init mutex failed\n");
		return;
	}

	status = stir_shaken_init_ssl();
	if (status != STIR_SHAKEN_STATUS_OK) {
	
		// TODO remove
		printf("STIR-Shaken: init SSL failed\n");
		return;
	}

	stir_shaken_globals.initialised = 1;
}

static void stir_shaken_deinit(void)
{
	// TODO remove
	printf("STIR-Shaken: deinit\n");
	
	stir_shaken_globals.initialised = 0;

	// TODO deinit settings (path, etc)
	
	stir_shaken_free_ssl();

	pthread_mutex_unlock(&stir_shaken_globals.mutex);
	pthread_mutex_destroy(&stir_shaken_globals.mutex);
	pthread_mutexattr_destroy(&stir_shaken_globals.attr);
}
