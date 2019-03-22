/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include <stdlib.h>

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

typedef struct ngx_oauth_claim_t {
	char *name;
	char *value;
	struct ngx_oauth_claim_t *next;
} ngx_oauth_claim_t;

typedef struct ngx_oauth2_cfg_t {
	ngx_http_complex_value_t source_token;
	oauth2_cfg_token_verify_t *verify;
	ngx_conf_t *cf;
	ngx_oauth_claim_t *claims;
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

	cfg = ngx_pnalloc(cf->pool, sizeof(ngx_oauth2_cfg_t));
	cfg->cf = cf;

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

static ngx_int_t ngx_oauth2_claim_variable(ngx_http_request_t *r,
					   ngx_http_variable_value_t *v,
					   uintptr_t data)
{
	ngx_oauth_claim_t *claim = (ngx_oauth_claim_t *)data;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "ngx_oauth2_claim_variable: %s=%s",
		       claim && claim->name ? claim->name : "(null)",
		       claim && claim->value ? claim->value : "(null)");

	if (claim && claim->value) {
		v->len = strlen(claim->value);
		v->data = ngx_palloc(r->pool, v->len);
		ngx_memcpy(v->data, claim->value, v->len);
	}

	if (v->len) {
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
	} else {
		v->not_found = 1;
	}

	return NGX_OK;
}

static char *ngx_oauth2_claim_command(ngx_conf_t *cf, ngx_command_t *cmd,
				      void *conf)
{
	char *rv = NGX_CONF_ERROR;
	// ngx_http_core_loc_conf_t *clcf = NULL;
	ngx_oauth2_cfg_t *cfg = (ngx_oauth2_cfg_t *)conf;
	// ngx_http_compile_complex_value_t ccv;
	ngx_str_t *value = NULL;
	ngx_http_variable_t *v;
	ngx_oauth_claim_t *claim = NULL, *ptr = NULL;

	value = cf->args->elts;

	claim = ngx_pnalloc(cf->pool, sizeof(ngx_oauth_claim_t));
	claim->name = oauth2_strndup((const char *)value[1].data, value[1].len);
	claim->value = NULL;

	if (value[2].data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				   "invalid variable name \"%V\"", &value[2]);
		goto end;
	}

	value[2].len--;
	value[2].data++;

	v = ngx_http_add_variable(cf, &value[2], 0);
	if (v == NULL) {
		rv = "ngx_http_add_variable failed";
		goto end;
	}

	v->get_handler = ngx_oauth2_claim_variable;
	v->data = (uintptr_t)claim;

	claim->next = NULL;
	if (cfg->claims == NULL) {
		cfg->claims = claim;
	} else {
		for (ptr = cfg->claims; ptr->next; ptr = ptr->next)
			;
		ptr->next = claim;
	}

	rv = NGX_CONF_OK;

end:

	return rv;
}

// ngx_oauth2_cfg_set_token_verify
OAUTH2_NGINX_CFG_FUNC_START(ngx_oauth2_cfg_t, dummy, oauth2_cfg, token_verify)
ngx_http_compile_complex_value_t ccv;

ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
ccv.cf = cf;
ccv.value = &value[1];
ccv.complex_value = &cfg->source_token;
// TODO: check return value
ngx_http_compile_complex_value(&ccv);

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

#define NGINX_OAUTH2_CMD_TAKE(nargs, primitive, member)                        \
	OAUTH2_NGINX_CMD_TAKE##nargs(oauth2_cfg, primitive, member)

// clang-format off
static ngx_command_t ngx_oauth2_commands[] = {
	NGINX_OAUTH2_CMD_TAKE(34, "OAuth2TokenVerify", token_verify),
	{
		ngx_string("OAuth2Claim"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_oauth2_claim_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_int_t ngx_oauth2_post_config(ngx_conf_t *cf);

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

static void ngx_set_target_variable(ngx_oauth2_cfg_t *cfg,
				    oauth2_nginx_request_context_t *ctx,
				    const char *key, const char *val)
{
	ngx_oauth_claim_t *ptr = NULL;
	ptr = cfg->claims;
	while (ptr) {
		if (strcmp(ptr->name, key) == 0)
			break;
		ptr = ptr->next;
	}
	if (ptr) {
		ptr->value = oauth2_strdup(val);
	}
}

// TODO: generalize/callback part of this (at least the looping and encoding is
// generic)
static void ngx_set_target_variables(ngx_oauth2_cfg_t *cfg,
				     oauth2_nginx_request_context_t *ctx,
				     json_t *json_token)
{
	void *iter = NULL;
	const char *key = NULL;
	json_t *value = NULL;
	char *val = NULL;
	iter = json_object_iter(json_token);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (json_is_string(value)) {
			val = oauth2_strdup(json_string_value(value));
		} else {
			val = oauth2_json_encode(ctx->log, value,
						 JSON_ENCODE_ANY);
		}

		ngx_set_target_variable(cfg, ctx, key, val);

		if (val)
			oauth2_mem_free(val);
		iter = json_object_iter_next(json_token, iter);
	}
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
		goto end;

	cfg = (ngx_oauth2_cfg_t *)ngx_http_get_module_loc_conf(
	    r, ngx_oauth2_module);
	if (cfg == NULL) {
		oauth2_warn(ctx->log,
			    "ngx_http_get_module_loc_conf returned NULL");
		rv = NGX_ERROR;
		goto end;
	}

	ctx = oauth2_nginx_request_context_init(r);
	if (ctx == NULL) {
		oauth2_warn(ctx->log,
			    "oauth2_nginx_request_context_init returned NULL");
		rv = NGX_ERROR;
		goto end;
	}

	// TODO: if we have a verify post config, call it here
	// ...

	if (ngx_http_complex_value(r, &cfg->source_token, &ngx_source_token) !=
	    NGX_OK) {
		oauth2_warn(
		    ctx->log,
		    "ngx_http_complex_value failed to obtain source_token");
		rv = NGX_ERROR;
		goto end;
	}

	if (ngx_source_token.len == 0) {
		oauth2_debug(ctx->log,
			     "ngx_http_complex_value ngx_source_token.len=0");
		// needed for non-handled paths
		// TODO: return an error if there was any config for this path?
		goto end;
	}

	source_token = oauth2_strndup((const char *)ngx_source_token.data,
				      ngx_source_token.len);

	oauth2_debug(ctx->log, "enter: source_token=%s, initial_request=%d",
		     source_token, (r != r->main));

	if (oauth2_token_verify(ctx->log, cfg->verify, source_token,
				&json_payload) == false) {
		oauth2_warn(ctx->log, "Token could not be verified.");
		// TODO: return HTTP 401 unauthorized
		rv = NGX_ERROR;
		goto end;
	}

	oauth2_debug(ctx->log, "json_payload=%p", json_payload);

	ngx_set_target_variables(cfg, ctx, json_payload);

	rv = NGX_OK;

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
