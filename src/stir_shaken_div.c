#include "stir_shaken.h"

static int stir_shaken_header_value_is_safe(const char *s)
{
	if (!s) return 1;
	return !strchr(s, '\r') && !strchr(s, '\n');
}

static const char *stir_shaken_identity_key_or_default(const char *key)
{
	return stir_shaken_zstr(key) ? "tn" : key;
}

static stir_shaken_status_t stir_shaken_validate_identity_key(stir_shaken_context_t *ss, const char *key)
{
	if (stir_shaken_zstr(key)) return STIR_SHAKEN_STATUS_OK;
	if (!strcmp(key, "tn") || !strcmp(key, "uri")) return STIR_SHAKEN_STATUS_OK;

	stir_shaken_set_error(ss, "Identity key must be 'tn' or 'uri'", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
	return STIR_SHAKEN_STATUS_FALSE;
}

static int stir_shaken_is_sip_token_char(char c)
{
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '!' || c == '%' ||
		c == '*' || c == '_' || c == '+' || c == '`' ||
		c == '\'' || c == '~';
}

static int stir_shaken_div_reason_is_sip_token(const char *reason)
{
	const char *p = NULL;

	if (stir_shaken_zstr(reason)) return 0;

	for (p = reason; *p; p++) {
		if (!stir_shaken_is_sip_token_char(*p)) return 0;
	}

	return 1;
}

static int stir_shaken_div_reason_is_quoted_string(const char *reason)
{
	size_t i = 0;
	size_t len = 0;
	int escaped = 0;

	if (stir_shaken_zstr(reason) || reason[0] != '"') return 0;

	len = strlen(reason);
	if (len < 2 || reason[len - 1] != '"') return 0;

	for (i = 1; i < len - 1; i++) {
		if (escaped) {
			escaped = 0;
			continue;
		}
		if (reason[i] == '\\') {
			escaped = 1;
			continue;
		}
		if (reason[i] == '"') return 0;
	}

	return !escaped;
}

static stir_shaken_status_t stir_shaken_validate_div_reason(stir_shaken_context_t *ss, const char *reason)
{
	static const char *valid_reasons[] = {
		"unknown",
		"user-busy",
		"no-answer",
		"unavailable",
		"unconditional",
		"time-of-day",
		"do-not-disturb",
		"deflection",
		"follow-me",
		"out-of-service",
		"away",
	};
	size_t i = 0;

	if (stir_shaken_zstr(reason)) {
		stir_shaken_set_error(ss, "DIV PASSporT @reason is missing", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!stir_shaken_header_value_is_safe(reason)) {
		stir_shaken_set_error(ss, "DIV PASSporT @reason is unsafe", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	for (i = 0; i < sizeof(valid_reasons) / sizeof(valid_reasons[0]); i++) {
		if (!strcmp(reason, valid_reasons[i])) return STIR_SHAKEN_STATUS_OK;
	}

	if (stir_shaken_div_reason_is_sip_token(reason) || stir_shaken_div_reason_is_quoted_string(reason)) {
		return STIR_SHAKEN_STATUS_OK;
	}

	stir_shaken_set_error(ss, "DIV PASSporT @reason is invalid", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
	return STIR_SHAKEN_STATUS_FALSE;
}

static stir_shaken_status_t stir_shaken_json_get_string_dup(stir_shaken_context_t *ss, ks_json_t *obj, const char *key, char **out)
{
	ks_json_t *item = NULL;
	const char *value = NULL;
	int num = 0;

	if (!obj || !key || !out) return STIR_SHAKEN_STATUS_TERM;

	item = ks_json_get_object_item(obj, key);
	if (!item) return STIR_SHAKEN_STATUS_FALSE;

	if (ks_json_type_get(item) == KS_JSON_TYPE_STRING) {
		ks_json_value_string(item, &value);
		if (stir_shaken_zstr(value)) return STIR_SHAKEN_STATUS_FALSE;
		*out = strdup(value);
	} else if (ks_json_type_get(item) == KS_JSON_TYPE_NUMBER) {
		ks_json_value_number_int(item, &num);
		*out = malloc(20);
		if (*out) snprintf(*out, 20, "%d", num);
	} else {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!*out) {
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_get_identity_dup(stir_shaken_context_t *ss, ks_json_t *obj, char **key_out, char **val_out)
{
	char *val = NULL;
	const char *key = NULL;

	if (!obj || !key_out || !val_out) return STIR_SHAKEN_STATUS_TERM;

	if (ks_json_type_get(obj) == KS_JSON_TYPE_ARRAY) {
		obj = ks_json_get_array_item(obj, 0);
		if (!obj) {
			stir_shaken_set_error(ss, "Identity array is empty", STIR_SHAKEN_ERROR_PASSPORT_ARRAY_ITEM);
			return STIR_SHAKEN_STATUS_FALSE;
		}
	}

	if (STIR_SHAKEN_STATUS_OK == stir_shaken_json_get_string_dup(ss, obj, "tn", &val)) {
		key = "tn";
	} else if (STIR_SHAKEN_STATUS_OK == stir_shaken_json_get_string_dup(ss, obj, "uri", &val)) {
		key = "uri";
	} else {
		stir_shaken_set_error(ss, "Identity object has neither @tn nor @uri", STIR_SHAKEN_ERROR_PASSPORT_ORIG_FORM);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	*key_out = strdup(key);
	if (!*key_out) {
		free(val);
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}
	*val_out = val;
	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_validate_dest(stir_shaken_context_t *ss, ks_json_t *dest)
{
	const char *keys[] = { "tn", "uri" };
	uint32_t values = 0;
	uint32_t i = 0;

	if (!dest || ks_json_type_get(dest) != KS_JSON_TYPE_OBJECT) {
		stir_shaken_set_error(ss, "DIV PASSporT @dest must be an object", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	for (i = 0; i < 2; i++) {
		ks_json_t *arr = ks_json_get_object_item(dest, keys[i]);
		int size = 0;
		int j = 0;

		if (!arr) continue;
		if (ks_json_type_get(arr) != KS_JSON_TYPE_ARRAY) {
			stir_shaken_set_error(ss, "DIV PASSporT @dest identity must be an array", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
			return STIR_SHAKEN_STATUS_FALSE;
		}

		size = ks_json_get_array_size(arr);
		for (j = 0; j < size; j++) {
			ks_json_t *item = ks_json_get_array_item(arr, j);
			const char *value = NULL;

			if (!item || ks_json_type_get(item) != KS_JSON_TYPE_STRING) {
				stir_shaken_set_error(ss, "DIV PASSporT @dest values must be strings", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
				return STIR_SHAKEN_STATUS_FALSE;
			}
			ks_json_value_string(item, &value);
			if (stir_shaken_zstr(value)) {
				stir_shaken_set_error(ss, "DIV PASSporT @dest value is empty", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
				return STIR_SHAKEN_STATUS_FALSE;
			}
			values++;
		}
	}

	if (!values) {
		stir_shaken_set_error(ss, "DIV PASSporT @dest is missing tn or uri values", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_dest_contains(stir_shaken_context_t *ss, ks_json_t *dest, const char *expected_key, const char *expected_val)
{
	ks_json_t *arr = NULL;
	int size = 0;
	int i = 0;

	if (!dest || ks_json_type_get(dest) != KS_JSON_TYPE_OBJECT) {
		stir_shaken_set_error(ss, "DIV PASSporT @dest must be an object", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	expected_key = stir_shaken_identity_key_or_default(expected_key);
	if (stir_shaken_validate_identity_key(ss, expected_key) != STIR_SHAKEN_STATUS_OK || stir_shaken_zstr(expected_val)) {
		stir_shaken_set_error(ss, "DIV PASSporT expected destination is invalid", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	arr = ks_json_get_object_item(dest, expected_key);
	if (!arr || ks_json_type_get(arr) != KS_JSON_TYPE_ARRAY) {
		stir_shaken_set_error(ss, "DIV PASSporT @dest does not contain expected identity type", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	size = ks_json_get_array_size(arr);
	for (i = 0; i < size; i++) {
		ks_json_t *item = ks_json_get_array_item(arr, i);
		const char *value = NULL;

		if (!item || ks_json_type_get(item) != KS_JSON_TYPE_STRING) continue;
		ks_json_value_string(item, &value);
		if (value && !strcmp(value, expected_val)) return STIR_SHAKEN_STATUS_OK;
	}

	stir_shaken_set_error(ss, "DIV PASSporT @dest does not match expected destination", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
	return STIR_SHAKEN_STATUS_FALSE;
}

static stir_shaken_status_t stir_shaken_json_add_identity_object(stir_shaken_context_t *ss, ks_json_t *parent, const char *name, const char *key, const char *val)
{
	ks_json_t *obj = NULL;

	if (stir_shaken_zstr(val)) {
		stir_shaken_set_error(ss, "Identity value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	obj = ks_json_create_object();
	if (!obj) {
		stir_shaken_set_error(ss, "Failed to create identity JSON object", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

	key = stir_shaken_identity_key_or_default(key);
	ks_json_add_string_to_object(obj, key, val);
	ks_json_add_item_to_object(parent, name, obj);

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_json_add_dest_object(stir_shaken_context_t *ss, ks_json_t *parent, const char *key, const char **vals, uint32_t vals_count)
{
	ks_json_t *dest = NULL;
	ks_json_t *arr = NULL;
	uint32_t i = 0;

	if (!vals || vals_count == 0) {
		stir_shaken_set_error(ss, "Destination value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_3);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	dest = ks_json_create_object();
	arr = ks_json_create_array();
	if (!dest || !arr) {
		if (dest) ks_json_delete(&dest);
		if (arr) ks_json_delete(&arr);
		stir_shaken_set_error(ss, "Failed to create dest JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_DEST);
		return STIR_SHAKEN_STATUS_ERR;
	}

	for (i = 0; i < vals_count; i++) {
		if (stir_shaken_zstr(vals[i])) {
			ks_json_delete(&arr);
			ks_json_delete(&dest);
			stir_shaken_set_error(ss, "Destination value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_4);
			return STIR_SHAKEN_STATUS_FALSE;
		}
		ks_json_add_string_to_array(arr, vals[i]);
	}

	key = stir_shaken_identity_key_or_default(key);
	ks_json_add_item_to_object(dest, key, arr);
	ks_json_add_item_to_object(parent, "dest", dest);

	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_div_passport_jwt_init(stir_shaken_context_t *ss, jwt_t *jwt, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	ks_json_t *json = NULL;
	ks_json_t *div = NULL;
	char *jstr = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;

	if (!jwt || !params) {
		stir_shaken_set_error(ss, "DIV PASSporT: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (stir_shaken_zstr(params->x5u) || stir_shaken_zstr(params->orig_val) || !params->dest_vals || params->dest_vals_count == 0 || stir_shaken_zstr(params->div_val) || !params->iat) {
		stir_shaken_set_error(ss, "DIV PASSporT: required field missing", STIR_SHAKEN_ERROR_BAD_PARAMS_2);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!stir_shaken_header_value_is_safe(params->x5u) || !stir_shaken_header_value_is_safe(params->reason) || !stir_shaken_header_value_is_safe(params->hi)) {
		stir_shaken_set_error(ss, "DIV PASSporT: unsafe header or claim value", STIR_SHAKEN_ERROR_BAD_PARAMS_3);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (stir_shaken_validate_identity_key(ss, params->orig_key) != STIR_SHAKEN_STATUS_OK ||
		stir_shaken_validate_identity_key(ss, params->dest_key) != STIR_SHAKEN_STATUS_OK ||
		stir_shaken_validate_identity_key(ss, params->div_key) != STIR_SHAKEN_STATUS_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (!stir_shaken_zstr(params->reason) && stir_shaken_validate_div_reason(ss, params->reason) != STIR_SHAKEN_STATUS_OK) {
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (jwt_add_header(jwt, "ppt", STIR_SHAKEN_PPT_DIV) != 0 ||
		jwt_add_header(jwt, "typ", "passport") != 0 ||
		jwt_add_header(jwt, "x5u", params->x5u) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add JOSE headers", STIR_SHAKEN_ERROR_JWT_ADD_HEADERS_JSON);
		return STIR_SHAKEN_STATUS_ERR;
	}

	if (key && keylen && jwt_set_alg(jwt, JWT_ALG_ES256, key, keylen) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to set ES256", STIR_SHAKEN_ERROR_JWT_SET_ALG_ES256_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

	json = ks_json_create_object();
	if (!json) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to create payload JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_1);
		return STIR_SHAKEN_STATUS_ERR;
	}

	ks_json_add_number_to_object(json, "iat", params->iat);

	if ((status = stir_shaken_json_add_identity_object(ss, json, "orig", params->orig_key, params->orig_val)) != STIR_SHAKEN_STATUS_OK) goto done;
	if ((status = stir_shaken_json_add_dest_object(ss, json, params->dest_key, params->dest_vals, params->dest_vals_count)) != STIR_SHAKEN_STATUS_OK) goto done;

	div = ks_json_create_object();
	if (!div) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to create div JSON", STIR_SHAKEN_ERROR_KSJSON_CREATE_OBJECT_JSON_2);
		status = STIR_SHAKEN_STATUS_ERR;
		goto done;
	}

	ks_json_add_string_to_object(div, stir_shaken_identity_key_or_default(params->div_key), params->div_val);
	if (!stir_shaken_zstr(params->hi)) ks_json_add_string_to_object(div, "hi", params->hi);
	if (!stir_shaken_zstr(params->reason)) ks_json_add_string_to_object(div, "reason", params->reason);
	ks_json_add_item_to_object(json, "div", div);
	div = NULL;

	jstr = ks_json_print_unformatted(json);
	if (!jstr) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to print payload JSON", STIR_SHAKEN_ERROR_PASSPORT_JWT_PRINT_JSON);
		status = STIR_SHAKEN_STATUS_TERM;
		goto done;
	}

	if (jwt_add_grants_json(jwt, jstr) != 0) {
		stir_shaken_set_error(ss, "DIV PASSporT: failed to add grants JSON", STIR_SHAKEN_ERROR_PASSPORT_JWT_ADD_GRANTS_JSON);
		status = STIR_SHAKEN_STATUS_TERM;
		goto done;
	}

done:
	if (div) ks_json_delete(&div);
	if (json) ks_json_delete(&json);
	if (jstr) free(jstr);
	return status;
}

void stir_shaken_div_passport_params_destroy(stir_shaken_div_passport_params_t *params)
{
	uint32_t i = 0;

	if (!params) return;
	free((char *) params->x5u);
	free((char *) params->orig_key);
	free((char *) params->orig_val);
	free((char *) params->dest_key);
	if (params->dest_vals) {
		for (i = 0; i < params->dest_vals_count; i++) free((char *) params->dest_vals[i]);
		free((char **) params->dest_vals);
	}
	free((char *) params->div_key);
	free((char *) params->div_val);
	free((char *) params->hi);
	free((char *) params->reason);
	memset(params, 0, sizeof(*params));
}

stir_shaken_passport_t *stir_shaken_div_passport_create(stir_shaken_context_t *ss, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	stir_shaken_passport_t *passport = NULL;

	passport = malloc(sizeof(*passport));
	if (!passport) {
		stir_shaken_set_error(ss, "Can't allocate DIV PASSporT", STIR_SHAKEN_ERROR_MEM_PASSPORT);
		return NULL;
	}
	memset(passport, 0, sizeof(*passport));

	passport->jwt = stir_shaken_passport_jwt_create_new(ss);
	if (!passport->jwt) goto fail;

	if (stir_shaken_div_passport_jwt_init(ss, passport->jwt, params, key, keylen) != STIR_SHAKEN_STATUS_OK) goto fail;

	return passport;

fail:
	stir_shaken_passport_destroy(&passport);
	return NULL;
}

stir_shaken_status_t stir_shaken_div_authenticate_keep_passport(stir_shaken_context_t *ss, char **sih, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen, stir_shaken_passport_t **passport_out)
{
	stir_shaken_passport_t *passport = NULL;

	if (!sih) {
		stir_shaken_set_error(ss, "DIV authenticate: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_4);
		return STIR_SHAKEN_STATUS_TERM;
	}

	passport = stir_shaken_div_passport_create(ss, params, key, keylen);
	if (!passport) {
		stir_shaken_set_error(ss, "Failed to create DIV PASSporT", STIR_SHAKEN_ERROR_PASSPORT_CREATE_1);
		return STIR_SHAKEN_STATUS_TERM;
	}

	*sih = stir_shaken_jwt_sip_identity_create(ss, passport, key, keylen);
	if (!*sih) {
		stir_shaken_passport_destroy(&passport);
		stir_shaken_set_error(ss, "Failed to create DIV SIP Identity Header", STIR_SHAKEN_ERROR_SIH_CREATE);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	if (passport_out) {
		*passport_out = passport;
	} else {
		stir_shaken_passport_destroy(&passport);
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_div_authenticate(stir_shaken_context_t *ss, char **sih, stir_shaken_div_passport_params_t *params, unsigned char *key, uint32_t keylen)
{
	return stir_shaken_div_authenticate_keep_passport(ss, sih, params, key, keylen, NULL);
}

stir_shaken_status_t stir_shaken_sih_parse(stir_shaken_context_t *ss, const char *sih, stir_shaken_parsed_identity_t *out)
{
	const char *semi = NULL;
	const char *p = NULL;
	size_t token_len = 0;

	if (!sih || !out || strchr(sih, '\r') || strchr(sih, '\n')) {
		stir_shaken_set_error(ss, "SIP Identity parse: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_5);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	memset(out, 0, sizeof(*out));
	semi = strchr(sih, ';');
	if (!semi || semi == sih) {
		stir_shaken_set_error(ss, "SIP Identity parse: malformed header", STIR_SHAKEN_ERROR_PASSPORT_MALFORMED);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	token_len = (size_t) (semi - sih);
	out->passport_token = malloc(token_len + 1);
	if (!out->passport_token) {
		stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
		return STIR_SHAKEN_STATUS_TERM;
	}
	memcpy(out->passport_token, sih, token_len);
	out->passport_token[token_len] = '\0';

	p = semi + 1;
	while (*p) {
		const char *eq = strchr(p, '=');
		const char *next = strchr(p, ';');
		size_t key_len = 0;
		size_t val_len = 0;
		const char *val = NULL;
		char **slot = NULL;

		if (!next) next = p + strlen(p);
		if (!eq || eq > next) {
			p = *next ? next + 1 : next;
			continue;
		}

		key_len = (size_t) (eq - p);
		val = eq + 1;
		val_len = (size_t) (next - val);

		if (key_len == 4 && !strncmp(p, "info", key_len)) slot = &out->info;
		else if (key_len == 3 && !strncmp(p, "alg", key_len)) slot = &out->alg;
		else if (key_len == 3 && !strncmp(p, "ppt", key_len)) slot = &out->ppt;

		if (slot && !*slot) {
			if (val_len >= 2 && val[0] == '<' && val[val_len - 1] == '>') {
				val++;
				val_len -= 2;
			}
			*slot = malloc(val_len + 1);
			if (!*slot) {
				stir_shaken_sih_parse_destroy(out);
				stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
				return STIR_SHAKEN_STATUS_TERM;
			}
			memcpy(*slot, val, val_len);
			(*slot)[val_len] = '\0';
		}

		p = *next ? next + 1 : next;
	}

	return STIR_SHAKEN_STATUS_OK;
}

void stir_shaken_sih_parse_destroy(stir_shaken_parsed_identity_t *parsed)
{
	if (!parsed) return;
	free(parsed->passport_token);
	free(parsed->info);
	free(parsed->alg);
	free(parsed->ppt);
	memset(parsed, 0, sizeof(*parsed));
}

stir_shaken_status_t stir_shaken_passport_decode_noverify(stir_shaken_context_t *ss, const char *passport_token, stir_shaken_passport_t **passport_out)
{
	jwt_t *jwt = NULL;
	stir_shaken_passport_t *passport = NULL;

	if (!passport_token || !passport_out) {
		stir_shaken_set_error(ss, "PASSporT decode: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_6);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (jwt_decode(&jwt, passport_token, NULL, 0) != 0) {
		stir_shaken_set_error(ss, "PASSporT decode: invalid JWT", STIR_SHAKEN_ERROR_JWT_DECODE_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	passport = stir_shaken_passport_create(ss, NULL, NULL, 0);
	if (!passport) {
		jwt_free(jwt);
		return STIR_SHAKEN_STATUS_TERM;
	}

	if (!stir_shaken_jwt_move_to_passport(ss, jwt, passport)) {
		jwt_free(jwt);
		stir_shaken_passport_destroy(&passport);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	*passport_out = passport;
	return STIR_SHAKEN_STATUS_OK;
}

static stir_shaken_status_t stir_shaken_extract_dest_selection(stir_shaken_context_t *ss, ks_json_t *dest, const char *selected_key, const char *selected_val, char **key_out, char **val_out)
{
	const char *keys[] = { "tn", "uri" };
	uint32_t total = 0;
	uint32_t i = 0;
	const char *sole_key = NULL;
	const char *sole_val = NULL;

	for (i = 0; i < 2; i++) {
		ks_json_t *arr = ks_json_get_object_item(dest, keys[i]);
		int size = 0;
		int j = 0;

		if (!arr) continue;
		if (ks_json_type_get(arr) != KS_JSON_TYPE_ARRAY) {
			stir_shaken_set_error(ss, "Original @dest must use array form", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
			return STIR_SHAKEN_STATUS_FALSE;
		}

		size = ks_json_get_array_size(arr);
		for (j = 0; j < size; j++) {
			ks_json_t *item = ks_json_get_array_item(arr, j);
			const char *value = NULL;

			if (!item || ks_json_type_get(item) != KS_JSON_TYPE_STRING) continue;
			ks_json_value_string(item, &value);
			if (!stir_shaken_zstr(value)) {
				total++;
				sole_key = keys[i];
				sole_val = value;
			}

			if (!stir_shaken_zstr(selected_val) && !strcmp(selected_val, value) && (stir_shaken_zstr(selected_key) || !strcmp(selected_key, keys[i]))) {
				*key_out = strdup(keys[i]);
				*val_out = strdup(value);
				if (!*key_out || !*val_out) {
					free(*key_out);
					free(*val_out);
					*key_out = NULL;
					*val_out = NULL;
					stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
					return STIR_SHAKEN_STATUS_TERM;
				}
				return STIR_SHAKEN_STATUS_OK;
			}
		}
	}

	if (stir_shaken_zstr(selected_val) && total == 1) {
		*key_out = strdup(sole_key);
		*val_out = strdup(sole_val);
		if (!*key_out || !*val_out) {
			free(*key_out);
			free(*val_out);
			*key_out = NULL;
			*val_out = NULL;
			stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
			return STIR_SHAKEN_STATUS_TERM;
		}
		return STIR_SHAKEN_STATUS_OK;
	}

	if (stir_shaken_zstr(selected_val) && total > 1) {
		stir_shaken_set_error(ss, "Original @dest has multiple values; selected original destination is required", STIR_SHAKEN_ERROR_BAD_PARAMS_7);
	} else {
		stir_shaken_set_error(ss, "Selected original destination is not present in original @dest", STIR_SHAKEN_ERROR_BAD_PARAMS_8);
	}
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stir_shaken_div_params_from_original_sih(stir_shaken_context_t *ss, const char *original_sih, const char *div_x5u, const char *new_dest_key, const char **new_dest_vals, uint32_t new_dest_vals_count, const char *selected_original_dest_key, const char *selected_original_dest_val, stir_shaken_div_passport_params_t *out)
{
	stir_shaken_parsed_identity_t parsed = { 0 };
	stir_shaken_passport_t *passport = NULL;
	char *orig_json = NULL;
	char *dest_json = NULL;
	ks_json_t *orig = NULL;
	ks_json_t *dest = NULL;
	uint32_t i = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (!out || stir_shaken_zstr(div_x5u) || !new_dest_vals || new_dest_vals_count == 0) {
		stir_shaken_set_error(ss, "DIV params from SIH: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_9);
		return STIR_SHAKEN_STATUS_TERM;
	}

	memset(out, 0, sizeof(*out));
	if (stir_shaken_sih_parse(ss, original_sih, &parsed) != STIR_SHAKEN_STATUS_OK) goto done;
	if (parsed.ppt && strcmp(parsed.ppt, STIR_SHAKEN_PPT_SHAKEN)) {
		stir_shaken_set_error(ss, "Original SIP Identity header is not SHAKEN", STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT);
		goto done;
	}
	if (stir_shaken_passport_decode_noverify(ss, parsed.passport_token, &passport) != STIR_SHAKEN_STATUS_OK) goto done;
	if (stir_shaken_passport_validate_headers_and_grants(ss, passport) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error_if_clear(ss, "Original SIP Identity header is not a valid SHAKEN PASSporT", STIR_SHAKEN_ERROR_PASSPORT_INVALID_1);
		goto done;
	}

	orig_json = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	dest_json = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	if (!orig_json || !dest_json) {
		stir_shaken_set_error(ss, "Original PASSporT missing @orig or @dest", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	orig = ks_json_parse(orig_json);
	dest = ks_json_parse(dest_json);
	if (!orig || !dest) {
		stir_shaken_set_error(ss, "Failed to parse original PASSporT claims", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	out->x5u = strdup(div_x5u);
	out->dest_key = strdup(stir_shaken_identity_key_or_default(new_dest_key));
	out->dest_vals = calloc(new_dest_vals_count, sizeof(*out->dest_vals));
	out->dest_vals_count = new_dest_vals_count;
	out->iat = (uint32_t) stir_shaken_passport_get_grant_int(ss, passport, "iat");
	if (!out->x5u || !out->dest_key || !out->dest_vals || !out->iat) {
		stir_shaken_set_error(ss, "DIV params from SIH: required value missing", STIR_SHAKEN_ERROR_BAD_PARAMS_10);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto fail_out;
	}

	for (i = 0; i < new_dest_vals_count; i++) {
		if (stir_shaken_zstr(new_dest_vals[i])) {
			stir_shaken_set_error(ss, "DIV params from SIH: new destination missing", STIR_SHAKEN_ERROR_BAD_PARAMS_11);
			status = STIR_SHAKEN_STATUS_FALSE;
			goto fail_out;
		}
		out->dest_vals[i] = strdup(new_dest_vals[i]);
		if (!out->dest_vals[i]) {
			stir_shaken_set_error(ss, "Out of memory", STIR_SHAKEN_ERROR_MEM_ID);
			status = STIR_SHAKEN_STATUS_TERM;
			goto fail_out;
		}
	}

	status = stir_shaken_json_get_identity_dup(ss, orig, (char **) &out->orig_key, (char **) &out->orig_val);
	if (status != STIR_SHAKEN_STATUS_OK) goto fail_out;

	status = stir_shaken_extract_dest_selection(ss, dest, selected_original_dest_key, selected_original_dest_val, (char **) &out->div_key, (char **) &out->div_val);
	if (status != STIR_SHAKEN_STATUS_OK) goto fail_out;

	status = STIR_SHAKEN_STATUS_OK;
	goto done;

fail_out:
	stir_shaken_div_passport_params_destroy(out);

done:
	if (orig) ks_json_delete(&orig);
	if (dest) ks_json_delete(&dest);
	if (orig_json) free(orig_json);
	if (dest_json) free(dest_json);
	stir_shaken_passport_destroy(&passport);
	stir_shaken_sih_parse_destroy(&parsed);
	return status;
}

stir_shaken_status_t stir_shaken_div_passport_validate_headers(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	const char *h = NULL;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	h = stir_shaken_passport_get_header(ss, passport, "alg");
	if (!h || strcmp(h, "ES256")) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @alg should be 'ES256'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_ALG);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "ppt");
	if (!h || strcmp(h, STIR_SHAKEN_PPT_DIV)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @ppt should be 'div'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_PPT);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "typ");
	if (!h || strcmp(h, "passport")) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @typ should be 'passport'", STIR_SHAKEN_ERROR_PASSPORT_INVALID_TYP);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	h = stir_shaken_passport_get_header(ss, passport, "x5u");
	if (stir_shaken_zstr(h)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @x5u is missing", STIR_SHAKEN_ERROR_PASSPORT_INVALID_X5U);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	return STIR_SHAKEN_STATUS_OK;
}

stir_shaken_status_t stir_shaken_div_passport_validate_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	char *orig = NULL;
	char *dest = NULL;
	char *div = NULL;
	char *opt = NULL;
	ks_json_t *orig_json = NULL;
	ks_json_t *dest_json = NULL;
	ks_json_t *div_json = NULL;
	ks_json_t *reason_json = NULL;
	ks_json_t *hi_json = NULL;
	char *identity_key = NULL;
	char *identity_val = NULL;
	long int iat = 0;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;

	if (!passport) return STIR_SHAKEN_STATUS_TERM;

	errno = 0;
	iat = stir_shaken_passport_get_grant_int(ss, passport, "iat");
	if (errno == ENOENT || iat == 0) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @iat is missing", STIR_SHAKEN_ERROR_PASSPORT_INVALID_IAT);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	orig = stir_shaken_passport_get_grants_json(ss, passport, "orig");
	dest = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	div = stir_shaken_passport_get_grants_json(ss, passport, "div");
	opt = stir_shaken_passport_get_grants_json(ss, passport, "opt");

	if (stir_shaken_zstr(orig) || stir_shaken_zstr(dest) || stir_shaken_zstr(div)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. required grant missing", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	orig_json = ks_json_parse(orig);
	dest_json = ks_json_parse(dest);
	div_json = ks_json_parse(div);
	if (!orig_json || !dest_json || !div_json) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. required grant is malformed JSON", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	status = stir_shaken_json_get_identity_dup(ss, orig_json, &identity_key, &identity_val);
	if (status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @orig must contain tn or uri", STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIG);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}
	free(identity_key);
	free(identity_val);
	identity_key = NULL;
	identity_val = NULL;

	status = stir_shaken_json_validate_dest(ss, dest_json);
	if (status != STIR_SHAKEN_STATUS_OK) {
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	status = stir_shaken_json_get_identity_dup(ss, div_json, &identity_key, &identity_val);
	if (status != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @div must contain tn or uri", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	reason_json = ks_json_get_object_item(div_json, "reason");
	if (reason_json) {
		const char *reason = NULL;
		if (ks_json_type_get(reason_json) != KS_JSON_TYPE_STRING) {
			stir_shaken_set_error(ss, "DIV PASSporT Invalid. @reason must be a string", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
			status = STIR_SHAKEN_STATUS_FALSE;
			goto done;
		}
		ks_json_value_string(reason_json, &reason);
		if (stir_shaken_validate_div_reason(ss, reason) != STIR_SHAKEN_STATUS_OK) {
			status = STIR_SHAKEN_STATUS_FALSE;
			goto done;
		}
	}

	hi_json = ks_json_get_object_item(div_json, "hi");
	if (hi_json && ks_json_type_get(hi_json) != KS_JSON_TYPE_STRING) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @hi must be a string", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
		goto done;
	}

	if (!stir_shaken_zstr(opt)) {
		stir_shaken_set_error(ss, "DIV PASSporT Invalid. @opt is not allowed for ppt=div", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		status = STIR_SHAKEN_STATUS_FALSE;
	}

done:
	if (identity_key) free(identity_key);
	if (identity_val) free(identity_val);
	if (orig_json) ks_json_delete(&orig_json);
	if (dest_json) ks_json_delete(&dest_json);
	if (div_json) ks_json_delete(&div_json);
	if (orig) free(orig);
	if (dest) free(dest);
	if (div) free(div);
	if (opt) free(opt);
	return status;
}

stir_shaken_status_t stir_shaken_div_passport_validate_headers_and_grants(stir_shaken_context_t *ss, stir_shaken_passport_t *passport)
{
	if (stir_shaken_div_passport_validate_headers(ss, passport) != STIR_SHAKEN_STATUS_OK) return STIR_SHAKEN_STATUS_FALSE;
	return stir_shaken_div_passport_validate_grants(ss, passport);
}

stir_shaken_status_t stir_shaken_div_passport_validate_dest(stir_shaken_context_t *ss, stir_shaken_passport_t *passport, const char *expected_key, const char *expected_val)
{
	char *dest = NULL;
	ks_json_t *dest_json = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (!passport || stir_shaken_zstr(expected_val)) {
		stir_shaken_set_error(ss, "DIV PASSporT destination validation: bad params", STIR_SHAKEN_ERROR_BAD_PARAMS_1);
		return STIR_SHAKEN_STATUS_FALSE;
	}

	dest = stir_shaken_passport_get_grants_json(ss, passport, "dest");
	if (stir_shaken_zstr(dest)) {
		stir_shaken_set_error(ss, "DIV PASSporT destination validation: @dest missing", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		goto done;
	}

	dest_json = ks_json_parse(dest);
	if (!dest_json) {
		stir_shaken_set_error(ss, "DIV PASSporT destination validation: @dest malformed", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		goto done;
	}

	status = stir_shaken_json_dest_contains(ss, dest_json, expected_key, expected_val);

done:
	if (dest_json) ks_json_delete(&dest_json);
	if (dest) free(dest);
	return status;
}

stir_shaken_status_t stir_shaken_div_validate_chain_claims(stir_shaken_context_t *ss, stir_shaken_passport_t *original, stir_shaken_passport_t *div)
{
	char *orig_orig = NULL;
	char *div_orig = NULL;
	char *orig_dest = NULL;
	char *div_claim = NULL;
	ks_json_t *orig_orig_json = NULL;
	ks_json_t *div_orig_json = NULL;
	ks_json_t *orig_dest_json = NULL;
	ks_json_t *div_claim_json = NULL;
	char *orig_key = NULL;
	char *orig_val = NULL;
	char *div_orig_key = NULL;
	char *div_orig_val = NULL;
	char *div_key = NULL;
	char *div_val = NULL;
	char *selected_key = NULL;
	char *selected_val = NULL;
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_FALSE;

	if (!original || !div) return STIR_SHAKEN_STATUS_TERM;
	if (stir_shaken_div_passport_validate_headers_and_grants(ss, div) != STIR_SHAKEN_STATUS_OK) return STIR_SHAKEN_STATUS_FALSE;

	orig_orig = stir_shaken_passport_get_grants_json(ss, original, "orig");
	orig_dest = stir_shaken_passport_get_grants_json(ss, original, "dest");
	div_orig = stir_shaken_passport_get_grants_json(ss, div, "orig");
	div_claim = stir_shaken_passport_get_grants_json(ss, div, "div");
	if (!orig_orig || !orig_dest || !div_orig || !div_claim) {
		stir_shaken_set_error(ss, "DIV chain Invalid. required claim missing", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	orig_orig_json = ks_json_parse(orig_orig);
	orig_dest_json = ks_json_parse(orig_dest);
	div_orig_json = ks_json_parse(div_orig);
	div_claim_json = ks_json_parse(div_claim);
	if (!orig_orig_json || !orig_dest_json || !div_orig_json || !div_claim_json) {
		stir_shaken_set_error(ss, "DIV chain Invalid. required claim is malformed JSON", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	if (stir_shaken_json_get_identity_dup(ss, orig_orig_json, &orig_key, &orig_val) != STIR_SHAKEN_STATUS_OK ||
		stir_shaken_json_get_identity_dup(ss, div_orig_json, &div_orig_key, &div_orig_val) != STIR_SHAKEN_STATUS_OK ||
		strcmp(orig_key, div_orig_key) || strcmp(orig_val, div_orig_val)) {
		stir_shaken_set_error(ss, "DIV chain Invalid. @orig mismatch", STIR_SHAKEN_ERROR_PASSPORT_INVALID_ORIG);
		goto done;
	}

	if (stir_shaken_json_get_identity_dup(ss, div_claim_json, &div_key, &div_val) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "DIV chain Invalid. @div missing original destination", STIR_SHAKEN_ERROR_PASSPORT_GRANTS_INVALID);
		goto done;
	}

	if (stir_shaken_extract_dest_selection(ss, orig_dest_json, div_key, div_val, &selected_key, &selected_val) != STIR_SHAKEN_STATUS_OK) {
		stir_shaken_set_error(ss, "DIV chain Invalid. @div destination is not in original @dest", STIR_SHAKEN_ERROR_PASSPORT_INVALID_DEST);
		goto done;
	}

	status = STIR_SHAKEN_STATUS_OK;

done:
	if (selected_key) free(selected_key);
	if (selected_val) free(selected_val);
	if (div_key) free(div_key);
	if (div_val) free(div_val);
	if (div_orig_key) free(div_orig_key);
	if (div_orig_val) free(div_orig_val);
	if (orig_key) free(orig_key);
	if (orig_val) free(orig_val);
	if (orig_orig_json) ks_json_delete(&orig_orig_json);
	if (div_orig_json) ks_json_delete(&div_orig_json);
	if (orig_dest_json) ks_json_delete(&orig_dest_json);
	if (div_claim_json) ks_json_delete(&div_claim_json);
	if (orig_orig) free(orig_orig);
	if (orig_dest) free(orig_dest);
	if (div_orig) free(div_orig);
	if (div_claim) free(div_claim);
	return status;
}
