# ngx_oauth2_module
An module for the NGINX web server which makes NGINX operate as an
OAuth 2.0 Resource Server, validating OAuth 2.0 bearer access tokens and setting headers/environment
variables based on the validation results.

## Configuration 

```
OAuth2TokenVerify [ introspect | jwk_uri | metadata | jwk | plain | base64 | base64url | hex | pem | pubkey | eckey_uri ] <value> <options>
```

## Samples

```
    #
    # obtain the access token from the authorization header
    #
    map $http_authorization $source_token {
        default "";
        "~*^Bearer\s+(?<token>[\S]+)$" $token;
    }

    server {
        listen       7070;
        server_name  nginx;

        #
        # introspection
        #

        location /oauth2/pingfed/introspect {
            OAuth2TokenVerify $source_token introspect 
                https://pingfed:9031/as/introspect.oauth2
                introspect.ssl_verify=false&introspect.auth=client_secret_basic&client_id=rs0&client_secret=2Federate;

            OAuth2Claim sub $pfc_introspect_sub;
            OAuth2Claim username $pfc_introspect_username;
            OAuth2Claim active $pfc_introspect_active;

            proxy_set_header OAUTH2_CLAIM_sub $pfc_introspect_sub;
            proxy_set_header OAUTH2_CLAIM_username $pfc_introspect_username;
            proxy_set_header OAUTH2_CLAIM_active $pfc_introspect_active;
            proxy_pass http://echo:8080/headers$is_args$args;
        }

        #
        # local validation from a  provided jwks_uri
        #
        
        location /oauth2/pingfed/jwks_uri {
            OAuth2TokenVerify $source_token jwks_uri
            	https://pingfed:9031/ext/one
            	jwks_uri.ssl_verify=false;

            OAuth2Claim sub $pfc_jwks_uri_sub;
            OAuth2Claim username $pfc_jwks_uri_username;
            OAuth2Claim active $pfc_jwks_uri_active;

            proxy_set_header OAUTH2_CLAIM_sub $pfc_jwks_uri_sub;
            proxy_set_header OAUTH2_CLAIM_username $pfc_jwks_uri_username;
            proxy_set_header OAUTH2_CLAIM_active $pfc_jwks_uri_active;
            proxy_pass http://echo:8080/headers$is_args$args;
        }

        #
        # local validation from a provided jwk
        #

        location /oauth2/pingfed/jwk {
			OAuth2TokenVerify $source_token jwk 
				"{	\"kty\":\"RSA\",
					\"kid\":\"one\",
					\"use\":\"sig\",
					\"n\":\"12SBWV_4xU8sBEC2IXcakiDe3IrrUcnIHexfyHG11Kw-EsrZvOy6PrrcqfTr1GcecyWFzQvUr61DWESrZWq96vd08_iTIWIny8pU5dlCoC7FsHU_onUQI1m4gQ3jNr00KhH878vrBVdr_T-zuOYQQOBRMEyFG-I4nb91zO1n2gcpQHeabJw3JIC9g65FCpu8DSw8uXQ1hVfGUDZAK6iwncNZ1uqN4HhRGNevFXT7KVG0cNS8S3oF4AhHafFurheVxh714R2EseTVD_FfLn2QTlCss_73YIJjzn047yKmAx5a9zuun6FKiISnMupGnHShwVoaS695rDmFvj7mvDppMQ\",
					\"e\":\"AQAB\"
				}";

            OAuth2Claim sub $pfc_jwk_sub;
            OAuth2Claim username $pfc_jwk_username;
            OAuth2Claim active $pfc_jwk_active;

            proxy_set_header OAUTH2_CLAIM_sub $pfc_jwk_sub;
            proxy_set_header OAUTH2_CLAIM_username $pfc_jwk_username;
            proxy_set_header OAUTH2_CLAIM_active $pfc_jwk_active;
            proxy_pass http://echo:8080/headers$is_args$args;
        }
    }      
```

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/ngx_oauth2_module/wiki](https://github.com/zmartzone/ngx_oauth2_module/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
