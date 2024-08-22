/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

typedef struct ngx_oauth2_cfg_t {
	ngx_http_complex_value_t source_token;
	oauth2_cfg_token_verify_t *verify;
	ngx_conf_t *cf;
	ngx_array_t *requirements;
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
	cfg->requirements = NULL;
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
	if (cfg->requirements == NULL)
		/* no requirements were set in the child, copy those of the
		 * parent; if the child has its own requirements then do not
		 * override them with the parent's */
		cfg->requirements = prev->requirements;
	cfg->verify = cfg->verify
			  ? oauth2_cfg_token_verify_clone(NULL, cfg->verify)
			  : oauth2_cfg_token_verify_clone(NULL, prev->verify);

	return NGX_CONF_OK;
}

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
	char *s = oauth2_nginx_str2chr(cf->pool, &msg);
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

OAUTH2_NGINX_CFG_FUNC_RET1(oauth2, ngx_oauth2_cfg_t, require,
			   nginx_oauth2_set_require, requirements)

OAUTH2_NGINX_CFG_FUNC_ARGS1(oauth2, ngx_oauth2_cfg_t, passphrase,
			    oauth2_crypto_passphrase_set, NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS2(oauth2, ngx_oauth2_cfg_t, cache,
			    oauth2_cfg_set_cache, NULL)

ngx_module_t ngx_oauth2_module;
OAUTH2_NGINX_CMD_SET_IMPL(oauth2, claim)

static ngx_command_t ngx_oauth2_commands[] = {
    OAUTH2_NGINX_CMD(1, oauth2, "OAuth2CryptoPassphrase", passphrase),
    OAUTH2_NGINX_CMD(12, oauth2, "OAuth2Cache", cache),
    OAUTH2_NGINX_CMD(3 | NGX_CONF_TAKE4, oauth2, "OAuth2TokenVerify",
		     token_verify),
    OAUTH2_NGINX_CMD(123 | NGX_CONF_TAKE4 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6 |
			 NGX_CONF_TAKE7,
		     oauth2, "OAuth2Require", require),
    OAUTH2_NGINX_CMD(2, oauth2, "OAuth2Claim", claim),
    ngx_null_command};

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

static ngx_int_t ngx_oauth2_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
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

	rv = oauth2_nginx_set_target_variables(ngx_oauth2_module, ctx,
					       json_payload);
	if (rv != NGX_OK)
		goto end;

	rv = nginx_oauth2_check_requirements(ctx, cfg->requirements);

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
