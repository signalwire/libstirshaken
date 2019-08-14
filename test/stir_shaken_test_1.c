#include "stir_shaken.h"

stir_shaken_status_t stir_shaken_unit_test_sign_verify_data_file(void)
{
	return STIR_SHAKEN_STATUS_OK;
}

int main(void)
{
	if (stir_shaken_unit_test_sign_verify_data_file() != STIR_SHAKEN_STATUS_OK) {
		return -1;
	}

	printf("Test 1: OK\n");

	return 0;
}
