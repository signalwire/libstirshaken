#include <stir_shaken.h>

const char *path = "./test/run";


#define PRINT_SHAKEN_ERROR_IF_SET \
	if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: '%s'\n", error_description); \
		printf("Error code is: '%d'\n", error_code); \
	}

void funny_and_useless(void *o)
{
	fprintf(stderr, "Funny and useless destructor ;~)\n");
}

stir_shaken_status_t stir_shaken_unit_test_hash(void)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_hash_entry_t* sessions[STI_CA_SESSIONS_MAX] = { 0 }, *e = NULL;
	size_t spc = 0;

	spc = 0;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 1;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 12;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");

	spc = 133;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 500;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 1234;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 7777;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 10000;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e == NULL, "Err, entry should not be found...");
	
	spc = 0;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 1;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 12;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 133;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 500;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 1234;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 7777;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 10000;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK != stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should not be removed...");
	
	spc = 0;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 1;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 12;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 133;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");

	spc = 500;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 1234;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 7777;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 10000;
	stir_shaken_assert(NULL != stir_shaken_hash_entry_add(sessions, STI_CA_SESSIONS_MAX, spc, calloc(1, 10), funny_and_useless), "Err, entry not added...");
	
	spc = 0;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 1;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 12;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");

	spc = 133;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 500;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 1234;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 7777;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 10000;
	e = stir_shaken_hash_entry_find(sessions, STI_CA_SESSIONS_MAX, spc);
	stir_shaken_assert(e != NULL, "Err, entry should be found...");
	
	spc = 0;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 1;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 12;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 133;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 500;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 1234;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 7777;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");
	
	spc = 10000;
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_hash_entry_remove(sessions, STI_CA_SESSIONS_MAX, spc), "Err, entry should be removed...");

	// cleanup
	stir_shaken_hash_destroy(sessions, STI_CA_SESSIONS_MAX);	

	return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	stir_shaken_assert(STIR_SHAKEN_STATUS_OK == stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH), "Cannot init lib");

	if (stir_shaken_dir_exists(path) != STIR_SHAKEN_STATUS_OK) {

		if (stir_shaken_dir_create_recursive(path) != STIR_SHAKEN_STATUS_OK) {

			printf("ERR: Cannot create test dir\n");
			return -1;
		}
	}

	if (stir_shaken_unit_test_hash() != STIR_SHAKEN_STATUS_OK) {

		printf("Fail\n");
		return -2;
	}

	stir_shaken_do_deinit();

	printf("OK\n");

	return 0;
}
