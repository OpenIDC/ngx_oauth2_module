/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

#include <stdlib.h>

#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/nginx.h>
#include <oauth2/oauth2.h>
#include <oauth2/version.h>

extern ngx_module_t ngx_oauth2_module;

typedef struct ngx_oauth2_claims_hash_s {
	ngx_hash_keys_arrays_t keys;
	ngx_hash_t             h;
} ngx_oauth2_claims_hash_t;

typedef struct ngx_oauth2_cfg_t {
	ngx_http_complex_value_t source_token;
	oauth2_cfg_token_verify_t *verify;
	ngx_conf_t *cf;
	ngx_array_t *requirements;
	oauth2_log_t *log;
} ngx_oauth2_cfg_t;

static ngx_int_t ngx_oauth2_init_hash(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims);
static ngx_int_t ngx_oauth2_init_keys(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims);

static inline ngx_str_t chr_to_ngx_str(ngx_pool_t *p, const char *k)
{
	ngx_str_t in  = {strlen(k), (u_char *)k};
	ngx_str_t out = {in.len, ngx_pstrdup(p, &in)};
	return out;
}

static inline char *ngx_str_to_chr(ngx_pool_t *p, const ngx_str_t *str)
{
	char *s = ngx_pnalloc(p, str->len + 1);
	if (s) {
		memcpy(s, str->data, str->len);
		s[str->len] = '\0';
	}
	return s;
}

static inline char *chr_to_chr(ngx_pool_t *p, const char *str)
{
	ngx_str_t s = {strlen(str), (u_char *)str};
	return ngx_str_to_chr(p, &s);
}

static void ngx_oauth2_cleanup(void *data)
{
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)data;
	if (cfg->verify)
		oauth2_cfg_token_verify_free(NULL, cfg->verify);
	if (cfg->log) {
		oauth2_log_free(cfg->log);
	}
}

static void *ngx_oauth2_create_loc_conf(ngx_conf_t *cf)
{
	ngx_oauth2_cfg_t *cfg = NULL;
	ngx_pool_cleanup_t *cln = NULL;
	oauth2_log_sink_t *sink;

	cfg = ngx_pcalloc(cf->pool, sizeof(ngx_oauth2_cfg_t));
	if (!cfg) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMEM,
				   "ngx_oauth2_create_loc_conf: out of memory "
				   "allocating location configuration");
		return NULL;
	}
	cfg->log = NULL;
	cfg->cf = cf;
	cfg->requirements = NULL;
	cfg->verify = NULL;
	cfg->source_token.flushes = NULL;
	cfg->source_token.lengths = NULL;
	cfg->source_token.value.data = NULL;
	cfg->source_token.value.len = 0;
	cfg->source_token.values = NULL;

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (!cln) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMEM,
				   "ngx_oauth2_create_loc_conf: out of memory "
				   "allocating cleanup handler");
		return NULL;
	}

	cln->handler = ngx_oauth2_cleanup;
	cln->data = cfg;

	sink = oauth2_log_sink_create(OAUTH2_LOG_INFO, oauth2_nginx_log,
				      cf->log);
	if (!sink) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, NGX_ENOMEM,
				   "ngx_oauth2_create_loc_conf: out of memory "
				   "allocating log sink");
		return cfg;
	}
	cfg->log = oauth2_log_init(OAUTH2_LOG_INFO, sink);
	if (!cfg->log) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, NGX_ENOMEM,
				   "ngx_oauth2_create_loc_conf: out of memory "
				   "allocating logger");
		oauth2_mem_free(sink);
		return cfg;
	}

	return cfg;
}

static char *ngx_oauth2_merge_loc_conf(ngx_conf_t *cf, void *parent,
				       void *child)
{
	ngx_oauth2_cfg_t *prev = parent;
	ngx_oauth2_cfg_t *cfg = child;

	cfg->cf = cf;
	cfg->verify = cfg->verify
			  ? oauth2_cfg_token_verify_clone(NULL, cfg->verify)
			  : oauth2_cfg_token_verify_clone(NULL, prev->verify);

	if (!cfg->requirements) {
		// No requirements were set in the child. Copy those of the
		// parent. If the child has its own requirements then do not
		// override them with the parent's.
		cfg->requirements = prev->requirements;
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_oauth2_claim_variable(ngx_http_request_t *r,
					   ngx_http_variable_value_t *v,
					   uintptr_t s)
{
	ngx_oauth2_claims_hash_t *claims;
	const char *value;

	ngx_str_t key = {strlen((const char *)s), (u_char *)s};

	claims = (ngx_oauth2_claims_hash_t *)
		ngx_http_get_module_ctx(r, ngx_oauth2_module);
	if (!claims) {
		v->not_found = 1;
		return NGX_OK;
	}

	value = (const char *)ngx_hash_find(&claims->h,
					    ngx_hash_key(key.data, key.len),
					    key.data, key.len);
	if (value) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "ngx_oauth2_claim_variable: %V=%s", &key, value);
		v->data         = (u_char *)value;
		v->len          = strlen(value);
		v->no_cacheable = 1;
		v->not_found    = 0;
	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "ngx_oauth2_claim_variable: %V=(null)", &key);
		v->not_found    = 1;
	}

	return NGX_OK;
}

static char *ngx_oauth2_set_claim(ngx_conf_t *cf, ngx_command_t *cmd,
				  void *conf)
{
	// ngx_http_core_loc_conf_t *clcf = NULL;
	// ngx_http_compile_complex_value_t ccv;
	ngx_str_t *value;
	ngx_http_variable_t *v;

	value = cf->args->elts;

	if (value[2].len <= 1 || value[2].data[0] != '$') {
		static const size_t MAX_BUF = 128;
		char buf[MAX_BUF];
		int n = snprintf(buf, sizeof(buf), "Invalid variable name %.*s",
				 (int)value[2].len, value[2].data);
		ngx_str_t msg = {n, (u_char *)&buf[0]};
		char *s = ngx_str_to_chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}

	value[2].len--;
	value[2].data++;

	v = ngx_http_add_variable(cf, &value[2], NGX_HTTP_VAR_CHANGEABLE);
	if (!v) {
		// avoid rv = "...", as it would be an implicit cast
		// from const char * to char *
		ngx_str_t msg = ngx_string("ngx_http_add_variable failed");
		char *rv = ngx_str_to_chr(cf->pool, &msg);
		return rv ? rv : NGX_CONF_ERROR;
	}

	v->get_handler = ngx_oauth2_claim_variable;
	char *claim = ngx_str_to_chr(cf->pool, &value[1]);
	if (!claim) {
		// avoid rv = "...", as it would be an implicit cast
		// from const char * to char *
		ngx_str_t msg = ngx_string("Out of memory");
		char *rv = ngx_str_to_chr(cf->pool, &msg);
		return rv ? rv : NGX_CONF_ERROR;
	}
	v->data = (uintptr_t)claim;

	return NGX_CONF_OK;
}

static char *
ngx_oauth2_set_token_verify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	char *rv;
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)conf;
	ngx_str_t *value = cf->args->elts;
	ngx_http_compile_complex_value_t ccv;
	int rc;
	char *v1 = NULL, *v2 = NULL, *v3 = NULL;

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
	ccv.cf            = cf;
	ccv.value         = &value[1];
	ccv.complex_value = &cfg->source_token;

	rc = ngx_http_compile_complex_value(&ccv);
	if (NGX_OK != rc) {
		static const size_t MAX_BUF = 128;
		char buf[MAX_BUF];
		int n = snprintf(buf, sizeof(buf), "Error %d compiling "
				 "expression %.*s", rc, (int)value[1].len,
				 value[1].data);
		ngx_str_t msg = {n, (u_char *)&buf[0]};
		char *s = ngx_str_to_chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}

	if (cf->args->nelts > 2) {
		v1 = oauth2_strndup((const char *)value[2].data,
				    (size_t)value[2].len);
		if (!v1) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	if (cf->args->nelts > 3) {
		v2 = oauth2_strndup((const char *)value[3].data,
				    (size_t)value[3].len);
		if (!v1) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	if (cf->args->nelts > 4) {
		v3 = oauth2_strndup((const char *)value[4].data,
				    (size_t)value[4].len);
		if (!v1) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}

	rv = oauth2_cfg_token_verify_add_options(NULL, &cfg->verify, v1, v2, v3);

	oauth2_mem_free(v3);
	oauth2_mem_free(v2);
	oauth2_mem_free(v1);

	return rv;
}

static char *
ngx_oauth2_set_passphrase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	const char *rv;
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)cf;
	ngx_str_t *value = cf->args->elts;
	char *v1 = NULL;

	if (cf->args->nelts > 1) {
		v1 = oauth2_strndup((const char *)value[1].data,
				    (size_t)value[1].len);
		if (!v1) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	rv = oauth2_crypto_passphrase_set(cfg->log, NULL, v1);
        oauth2_mem_free(v1);
	if (rv) {
		char *s = chr_to_chr(cf->pool, rv);
		return s ? s : NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}

static char *
ngx_oauth2_set_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	char *rv;
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)cf;
	ngx_str_t *value = cf->args->elts;
	char *v1 = NULL, *v2 = NULL;

	if (cf->args->nelts > 1) {
		v1 = oauth2_strndup((const char *)value[1].data,
				    (size_t)value[1].len);
		if (!v1) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	if (cf->args->nelts > 2) {
		v2 = oauth2_strndup((const char *)value[2].data,
				    (size_t)value[2].len);
		if (!v2) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	rv = oauth2_cfg_set_cache(cfg->log, NULL, v1, v2);
        oauth2_mem_free(v1);
	return rv;
}

static char *
ngx_oauth2_set_require(ngx_conf_t *cf, ngx_command_t *cmd, void *cnf) {
	if (!cnf) {
		ngx_str_t msg = ngx_string("Out of memory");
		char *s = ngx_str_to_chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)cnf;
	if (!cf->args) {
		ngx_str_t msg = ngx_string("Out of memory");
		char *s = ngx_str_to_chr(cf->pool, &msg);
		return s ? s : NGX_CONF_ERROR;
	}

	if (!cfg->requirements) {
		cfg->requirements =
			ngx_array_create(cf->pool, cf->args->nelts,
					 sizeof(ngx_http_complex_value_t));
		if (!cfg->requirements) {
			ngx_str_t msg = ngx_string("Out of memory");
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}
	for (unsigned int i = 1; i < cf->args->nelts; ++i) {
		ngx_http_complex_value_t *val;
		ngx_http_compile_complex_value_t ccv;
		ngx_str_t *var;
		int rc;

		var = (ngx_str_t *)cf->args->elts + i;
		// no allocation here because we've already dimensioned the
		// array upon its creation
		val = (ngx_http_complex_value_t *)
			ngx_array_push(cfg->requirements);

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf            = cf;
		ccv.value         = var;
		ccv.complex_value = val;

		rc = ngx_http_compile_complex_value(&ccv);
		if (NGX_OK != rc) {
			static const size_t MAX_BUF = 128;
			char buf[MAX_BUF];
			int n = snprintf(buf, sizeof(buf), "Error %d compiling "
					 "expression %.*s", rc, (int)var->len,
					 var->data);
			ngx_str_t msg = {n, (u_char *)&buf[0]};
			char *s = ngx_str_to_chr(cf->pool, &msg);
			return s ? s : NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

static ngx_command_t ngx_oauth2_commands[] = {
    {
	    ngx_string("OAuth2CryptoPassphrase"),
	    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |
	    NGX_CONF_TAKE1,
	    ngx_oauth2_set_passphrase, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL
    },
    {
	    ngx_string("OAuth2Cache"),
	    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |
	    NGX_CONF_TAKE12,
	    ngx_oauth2_set_cache, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL
    },
    {
	    ngx_string("OAuth2TokenVerify"),
	    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |
	    NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
	    ngx_oauth2_set_token_verify, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL
    },
    {
	    ngx_string("OAuth2Require"),
	    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |
	    NGX_CONF_TAKE1 | NGX_CONF_TAKE2 | NGX_CONF_TAKE3 | NGX_CONF_TAKE4 |
	    NGX_CONF_TAKE5 | NGX_CONF_TAKE6 | NGX_CONF_TAKE7,
	    ngx_oauth2_set_require, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL
    },
    {
	    ngx_string("OAuth2Claim"),
	    NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF |
	    NGX_CONF_TAKE2,
	    ngx_oauth2_set_claim, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL
    },
    ngx_null_command
};

static ngx_int_t ngx_oauth2_post_config(ngx_conf_t *cf);

// clang-format off

static ngx_http_module_t ngx_oauth2_module_ctx = {
		NULL,						/* preconfiguration              */
		ngx_oauth2_post_config,		/* postconfiguration             */

		NULL,						/* create main configuration     */
		NULL,						/* init main configuration       */

		NULL,						/* create server configuration   */
		NULL,						/* merge server configuration    */

		ngx_oauth2_create_loc_conf,	/* create location configuration */
		ngx_oauth2_merge_loc_conf	/* merge location configuration  */
};

ngx_module_t ngx_oauth2_module = {
		NGX_MODULE_V1,
		&ngx_oauth2_module_ctx,	/* module context    */
		ngx_oauth2_commands,	/* module directives */
		NGX_HTTP_MODULE,		/* module type       */
		NULL,					/* init master       */
		NULL,					/* init module       */
		NULL,					/* init process      */
		NULL,					/* init thread       */
		NULL,					/* exit thread       */
		NULL,					/* exit process      */
		NULL,					/* exit master       */
		NGX_MODULE_V1_PADDING
};
// clang-format on

static ngx_int_t ngx_oauth2_handler(ngx_http_request_t *r);

static ngx_int_t ngx_oauth2_post_config(ngx_conf_t *cf)
{
	ngx_int_t rv = NGX_ERROR;
	ngx_http_handler_pt *h = NULL;
	ngx_http_core_main_conf_t *cmcf = NULL;
	ngx_oauth2_cfg_t *cfg = NULL;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
		goto end;

	*h = ngx_oauth2_handler;

	cfg = (ngx_oauth2_cfg_t *)ngx_http_conf_get_module_loc_conf(
	    cf, ngx_oauth2_module);

	if (cfg == NULL)
		goto end;

	// TODO: once verify has post config
	//	if (oauth2_cfg_verify_post_config(NULL, cfg->cfg) == false)
	//		goto end;

	rv = NGX_OK;

end:

	return rv;
}

static ngx_int_t ngx_set_target_variable(ngx_oauth2_claims_hash_t *claims,
					 oauth2_nginx_request_context_t *ctx,
					 const char *k, const char *v)
{
	ngx_str_t key = chr_to_ngx_str(claims->keys.pool, k);
	if (!key.data) {
		return NGX_ERROR;
	}

	const char *value = chr_to_chr(claims->keys.pool, v);
	if (!value) {
		return NGX_ERROR;
	}

	return ngx_hash_add_key(&claims->keys, &key, (char *)value,
				NGX_HASH_READONLY_KEY);
}

// TODO: generalize/callback part of this (at least the looping and encoding is
// generic)
static ngx_int_t ngx_set_target_variables(ngx_http_request_t *r,
					  oauth2_nginx_request_context_t *ctx,
					  json_t *json_token)
{
	void *iter;
	const char *key;
	json_t *value;
	ngx_oauth2_claims_hash_t *claims;
	int rc;

	claims = (ngx_oauth2_claims_hash_t *)
		ngx_http_get_module_ctx(r, ngx_oauth2_module);
	if (!claims) {
		claims = ngx_palloc(r->pool, sizeof(*claims));
		if (!claims) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log,
				      NGX_ENOMEM, "ngx_set_target_variables: "
				      "error allocating claims hash");
			return NGX_ERROR;
		}

		rc = ngx_oauth2_init_keys(r->pool, claims);
		if (NGX_OK != rc) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				      "ngx_set_target_variables: error %d "
				      "initializing hash keys", rc);
			return rc;
		}

		ngx_http_set_ctx(r, claims, ngx_oauth2_module);
	}

	iter = json_object_iter(json_token);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (json_is_string(value)) {
			rc = ngx_set_target_variable(claims, ctx, key,
						     json_string_value(value));
		} else {
			const char *val = oauth2_json_encode(ctx->log, value,
							     JSON_ENCODE_ANY);
			rc = ngx_set_target_variable(claims, ctx, key, val);
			oauth2_mem_free((char *)val);
		}

		if (NGX_OK != rc) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				      "ngx_set_target_variables: error %d "
				      "setting value of key %s in claims hash",
				      rc, key);
			return rc;
		}

		iter = json_object_iter_next(json_token, iter);
	}

	rc = ngx_oauth2_init_hash(r->pool, claims);
	if (NGX_OK != rc) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "ngx_set_target_variables: error %d initializing "
			      "claims hash", rc);
		return rc;
	}
	return NGX_OK;
}

static ngx_int_t
ngx_oauth2_check_requirement(ngx_http_request_t *r,
			     oauth2_nginx_request_context_t *ctx,
			     ngx_http_complex_value_t *cv) {
	ngx_str_t v;
	ngx_int_t rc = ngx_http_complex_value(r, cv, &v);
	if (NGX_OK != rc) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error %d "
			      "evaluating expression %*.s", rc,
			      (int)cv->value.len, cv->value.data);
		return NGX_ERROR;
	}

	return 1 == v.len && '1' == *v.data ? NGX_OK : NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_oauth2_check_requirements(ngx_http_request_t *r,
			      oauth2_nginx_request_context_t *ctx,
			      ngx_oauth2_cfg_t *cfg) {
	if (!cfg->requirements) {
		return NGX_OK;
	}

	for (unsigned int i = 0; i < cfg->requirements->nelts; ++i) {
		ngx_http_complex_value_t *cv =
			(ngx_http_complex_value_t *)cfg->requirements->elts + i;
		int rc = ngx_oauth2_check_requirement(r, ctx, cv);
		if (NGX_OK != rc) {
			return rc;
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_oauth2_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
	// bool rc = false;
	oauth2_nginx_request_context_t *ctx = NULL;
	ngx_oauth2_cfg_t *cfg;
	ngx_str_t ngx_source_token;
	char *source_token = NULL;
	json_t *json_payload = NULL;

	if (r != r->main) {
		// Do not goto end because ctx is not yet built and ctx->log
		// would segfault
		return NGX_DECLINED;
	}

	cfg = (ngx_oauth2_cfg_t *)
		ngx_http_get_module_loc_conf(r, ngx_oauth2_module);
	if (!cfg) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ENOMEM,
			      "ngx_oauth2_handler: error allocating request "
			      "context");
		return NGX_ERROR;
	}

	if (!cfg->verify) {
		// This is an unhandled path. There was no OAuth2TokenVerify
		// conf directive in this location.
		return NGX_DECLINED;
	}

	ctx = oauth2_nginx_request_context_init(r);
	if (!ctx) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "ngx_oauth2_handler: error initializing request "
			      "context");
		return NGX_ERROR;
	}

	ngx_str_null(&ngx_source_token);

	rv = ngx_http_complex_value(r, &cfg->source_token, &ngx_source_token);
	if (NGX_OK != rv) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "ngx_oauth2_handler: error %d evaluating "
			      "expression %*.s", rv,
			      (int)cfg->source_token.value.len,
			      cfg->source_token.value.data);
		rv = NGX_ERROR;
		goto end;
	}

	if (ngx_source_token.len == 0) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "ngx_oauth2_handler: empty token");
		rv = NGX_HTTP_UNAUTHORIZED;
		goto end;
	}

	source_token = oauth2_strndup((const char *)ngx_source_token.data,
				      ngx_source_token.len);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "ngx_oauth2_handler: enter: source_token=%s, "
		       "initial_request=%d", source_token, (r != r->main));

	if (!oauth2_token_verify(ctx->log, ctx->request, cfg->verify,
				 source_token, &json_payload)) {
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
			      "ngx_oauth2_handler: token %s could not be "
			      "verified", source_token);
		rv = NGX_HTTP_UNAUTHORIZED;
		goto end;
	}

	ngx_log_debug1(NGX_LOG_DEBUG, r->connection->log, 0,
		       "ngx_oauth2_handler: json_payload=%p", json_payload);

	rv = ngx_set_target_variables(r, ctx, json_payload);
	if (NGX_OK != rv) {
		goto end;
	}

	rv = ngx_oauth2_check_requirements(r, ctx, cfg);

end:
	if (source_token)
		oauth2_mem_free(source_token);
	if (json_payload)
		json_decref(json_payload);

	// hereafter we destroy the log object...
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "Leave: %d", rv);

	if (ctx)
		oauth2_nginx_request_context_free(ctx);

	return rv;
}

static ngx_int_t ngx_oauth2_init_keys(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims)
{
	claims->keys.pool      = pool;
	claims->keys.temp_pool = pool;

	return ngx_hash_keys_array_init(&claims->keys, NGX_HASH_SMALL);
}

static ngx_int_t ngx_oauth2_init_hash(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims)
{
	ngx_hash_init_t init;

	init.hash        = &claims->h;
	init.key         = ngx_hash_key;
	init.max_size    = 64;
	init.bucket_size = ngx_align(64, ngx_cacheline_size);
	init.name        = "claims";
	init.pool        = pool;
	init.temp_pool   = pool;

	return ngx_hash_init(&init, claims->keys.keys.elts,
			     claims->keys.keys.nelts);
}
