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

#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/nginx.h>
#include <oauth2/oauth2.h>
#include <oauth2/version.h>

typedef struct ngx_oauth2_claims_hash_s {
	ngx_hash_keys_arrays_t keys;
	ngx_hash_t h;
} ngx_oauth2_claims_hash_t;

typedef struct ngx_oauth2_cfg_t {
	ngx_http_complex_value_t source_token;
	oauth2_cfg_token_verify_t *verify;
	ngx_conf_t *cf;
	// TODO:
	oauth2_log_t *log;
} ngx_oauth2_cfg_t;

static void ngx_oauth2_cleanup(void *data)
{
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)data;
	if (cfg->verify)
		oauth2_cfg_token_verify_free(NULL, cfg->verify);
}

static void *ngx_oauth2_create_loc_conf(ngx_conf_t *cf)
{
	ngx_oauth2_cfg_t *cfg = NULL;
	ngx_pool_cleanup_t *cln = NULL;

	cfg = ngx_pcalloc(cf->pool, sizeof(ngx_oauth2_cfg_t));
	cfg->log = NULL;
	cfg->cf = cf;
	cfg->verify = NULL;
	cfg->source_token.flushes = NULL;
	cfg->source_token.lengths = NULL;
	cfg->source_token.value.data = NULL;
	cfg->source_token.value.len = 0;
	cfg->source_token.values = NULL;

	// TODO: correct level
	// oauth2_log_t *log = oauth2_log_init(OAUTH2_LOG_TRACE1, NULL);

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
		goto end;

	cln->handler = ngx_oauth2_cleanup;
	cln->data = cfg;

end:

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

	return NGX_CONF_OK;
}

static inline ngx_str_t chr_to_ngx_str(ngx_pool_t *p, const char *k)
{
	ngx_str_t in = {strlen(k), (u_char *)k};
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

static char *ngx_oauth2_set_claim(ngx_conf_t *cf, ngx_command_t *cmd,
				  void *conf);

// ngx_oauth2_cfg_set_token_verify
OAUTH2_NGINX_CFG_FUNC_START(oauth2, ngx_oauth2_cfg_t, token_verify)
int rc = NGX_OK;
ngx_http_compile_complex_value_t ccv;

ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
ccv.cf = cf;
ccv.value = &value[1];
ccv.complex_value = &cfg->source_token;

rc = ngx_http_compile_complex_value(&ccv);
if (rc != NGX_OK) {
	static const size_t MAX_BUF = 128;
	char buf[MAX_BUF];
	int n = snprintf(buf, sizeof(buf),
			 "Error %d compiling "
			 "expression %.*s",
			 rc, (int)value[1].len, value[1].data);
	ngx_str_t msg = {n, (u_char *)&buf[0]};
	char *s = ngx_str_to_chr(cf->pool, &msg);
	return s ? s : NGX_CONF_ERROR;
}

char *v1 = cf->args->nelts > 2 ? oauth2_strndup((const char *)value[2].data,
						(size_t)value[2].len)
			       : NULL;
char *v2 = cf->args->nelts > 3 ? oauth2_strndup((const char *)value[3].data,
						(size_t)value[3].len)
			       : NULL;
char *v3 = cf->args->nelts > 4 ? oauth2_strndup((const char *)value[4].data,
						(size_t)value[4].len)
			       : NULL;

rv = oauth2_cfg_token_verify_add_options(NULL, &cfg->verify, v1, v2, v3);

oauth2_mem_free(v3);
oauth2_mem_free(v2);
oauth2_mem_free(v1);
OAUTH2_NGINX_CFG_FUNC_END(cf, rv)

OAUTH2_NGINX_CFG_FUNC_ARGS1(oauth2, ngx_oauth2_cfg_t, passphrase,
			    oauth2_crypto_passphrase_set, NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS2(oauth2, ngx_oauth2_cfg_t, cache,
			    oauth2_cfg_set_cache, NULL)

static ngx_command_t ngx_oauth2_commands[] = {
    OAUTH2_NGINX_CMD(1, oauth2, "OAuth2CryptoPassphrase", passphrase),
    OAUTH2_NGINX_CMD(12, oauth2, "OAuth2Cache", cache),
    OAUTH2_NGINX_CMD(3 | NGX_CONF_TAKE4, oauth2, "OAuth2TokenVerify",
		     token_verify),
    OAUTH2_NGINX_CMD(2, oauth2, "OAuth2Claim", claim), ngx_null_command};

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

static ngx_int_t ngx_oauth2_claim_variable(ngx_http_request_t *r,
					   ngx_http_variable_value_t *v,
					   uintptr_t data)
{
	ngx_oauth2_claims_hash_t *claims = NULL;
	const char *value = NULL;

	ngx_str_t key = {strlen((const char *)data), (u_char *)data};

	claims = (ngx_oauth2_claims_hash_t *)ngx_http_get_module_ctx(
	    r, ngx_oauth2_module);
	if (!claims) {
		v->not_found = 1;
		return NGX_OK;
	}

	value = (const char *)ngx_hash_find(
	    &claims->h, ngx_hash_key(key.data, key.len), key.data, key.len);
	if (value) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "ngx_oauth2_claim_variable: %V=%s", &key, value);
		v->data = (u_char *)value;
		v->len = strlen(value);
		v->no_cacheable = 1;
		v->not_found = 0;
	} else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			       "ngx_oauth2_claim_variable: %V=(null)", &key);
		v->not_found = 1;
	}

	return NGX_OK;
}

static char *ngx_oauth2_set_claim(ngx_conf_t *cf, ngx_command_t *cmd,
				  void *conf)
{
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
		ngx_str_t msg = ngx_string("ngx_http_add_variable failed");
		char *rv = ngx_str_to_chr(cf->pool, &msg);
		return rv ? rv : NGX_CONF_ERROR;
	}

	v->get_handler = ngx_oauth2_claim_variable;
	char *claim = ngx_str_to_chr(cf->pool, &value[1]);
	if (!claim) {
		ngx_str_t msg = ngx_string("Out of memory");
		char *rv = ngx_str_to_chr(cf->pool, &msg);
		return rv ? rv : NGX_CONF_ERROR;
	}
	v->data = (uintptr_t)claim;

	return NGX_CONF_OK;
}

static ngx_int_t ngx_set_target_variable(ngx_oauth2_claims_hash_t *claims,
					 oauth2_nginx_request_context_t *ctx,
					 const char *k, const char *v)
{
	ngx_str_t key = chr_to_ngx_str(claims->keys.pool, k);
	if (!key.data)
		return NGX_ERROR;

	const char *value = chr_to_chr(claims->keys.pool, v);
	if (!value)
		return NGX_ERROR;

	return ngx_hash_add_key(&claims->keys, &key, (char *)value,
				NGX_HASH_READONLY_KEY);
}

static ngx_int_t ngx_oauth2_init_keys(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims)
{
	claims->keys.pool = pool;
	claims->keys.temp_pool = pool;

	return ngx_hash_keys_array_init(&claims->keys, NGX_HASH_SMALL);
}

static ngx_int_t ngx_oauth2_init_hash(ngx_pool_t *pool,
				      ngx_oauth2_claims_hash_t *claims)
{
	ngx_hash_init_t init;

	init.hash = &claims->h;
	init.key = ngx_hash_key;
	init.max_size = 64;
	init.bucket_size = ngx_align(64, ngx_cacheline_size);
	init.name = "claims";
	init.pool = pool;
	init.temp_pool = pool;

	return ngx_hash_init(&init, claims->keys.keys.elts,
			     claims->keys.keys.nelts);
}

// TODO: generalize/callback part of this (at least the looping and encoding is
// generic)
static ngx_int_t ngx_set_target_variables(ngx_http_request_t *r,
					  oauth2_nginx_request_context_t *ctx,
					  json_t *json_token)
{
	void *iter = NULL;
	const char *key = NULL;
	json_t *value = NULL;
	ngx_oauth2_claims_hash_t *claims = NULL;
	int rc = NGX_OK;

	claims = (ngx_oauth2_claims_hash_t *)ngx_http_get_module_ctx(
	    r, ngx_oauth2_module);
	if (!claims) {
		claims = ngx_palloc(r->pool, sizeof(*claims));
		if (!claims) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log,
				      NGX_ENOMEM,
				      "ngx_set_target_variables: "
				      "error allocating claims hash");
			return NGX_ERROR;
		}

		rc = ngx_oauth2_init_keys(r->pool, claims);
		if (NGX_OK != rc) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				      "ngx_set_target_variables: error %d "
				      "initializing hash keys",
				      rc);
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
			      "claims hash",
			      rc);
		return rc;
	}

	return NGX_OK;
}

static ngx_int_t ngx_oauth2_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
	// bool rc = false;
	oauth2_nginx_request_context_t *ctx = NULL;
	ngx_oauth2_cfg_t *cfg = NULL;
	ngx_str_t ngx_source_token;
	char *source_token = NULL;
	json_t *json_payload = NULL;

	if (r != r->main)
		// do not goto end because ctx->log is not available
		return NGX_DECLINED;

	cfg = (ngx_oauth2_cfg_t *)ngx_http_get_module_loc_conf(
	    r, ngx_oauth2_module);
	if (cfg == NULL) {
		ngx_log_error(
		    NGX_LOG_ERR, r->connection->log, NGX_ENOMEM,
		    "ngx_oauth2_handler: error allocating request context");
		return NGX_ERROR;
	}

	if (cfg->verify == NULL)
		// unhandled path: no OAuth2TokenVerify directive in this
		// location.
		return NGX_DECLINED;

	ctx = oauth2_nginx_request_context_init(r);
	if (ctx == NULL) {
		ngx_log_error(
		    NGX_LOG_ERR, r->connection->log, 0,
		    "ngx_oauth2_handler: error initializing request context");
		return NGX_ERROR;
	}

	// TODO: if we have a verify post config, call it here
	// ...

	ngx_str_null(&ngx_source_token);
	rv = ngx_http_complex_value(r, &cfg->source_token, &ngx_source_token);
	if (rv != NGX_OK) {
		ngx_log_error(
		    NGX_LOG_ERR, r->connection->log, 0,
		    "ngx_oauth2_handler: error %d evaluating expression %*.s",
		    rv, (int)cfg->source_token.value.len,
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

	oauth2_debug(ctx->log, "enter: source_token=%s, initial_request=%d",
		     source_token, (r != r->main));

	if (oauth2_token_verify(ctx->log, ctx->request, cfg->verify,
				source_token, &json_payload) == false) {
		oauth2_warn(ctx->log, "Token could not be verified.");
		rv = NGX_HTTP_UNAUTHORIZED;
		goto end;
	}

	oauth2_debug(ctx->log, "json_payload=%p", json_payload);

	rv = ngx_set_target_variables(r, ctx, json_payload);

end:

	if (source_token)
		oauth2_mem_free(source_token);
	if (json_payload)
		json_decref(json_payload);

	// hereafter we destroy the log object...
	oauth2_debug(ctx->log, "leave: %d", rv);

	if (ctx)
		oauth2_nginx_request_context_free(ctx);

	return rv;
}
