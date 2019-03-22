# ngx_oauth2_module
An module for the NGINX web server which makes NGINX operate as an
OAuth 2.0 Resource Server, validating OAuth 2.0 bearer access tokens and setting headers/environment
variables based on the validation results.

## Configuration 

### Source Token Retrieval and Exchange

Cookie:
```
	map $http_cookie $sts_source_token {
		default "";
		"~*MyCookieName=(?<token>[^;]+)" "$token";
	}
	sts_handler $sts_source_token $sts_target_token
```

Header:
```
	map $http_authorization $sts_source_token {
		default "";
		"~Bearer (?<token>.+)$" "$token";
	}
	sts_handler $sts_source_token $sts_target_token

```

Query:
```
	if ($args_token != "not found") {
		$sts_source_token = $args_token
	}
	sts_handler $sts_source_token $sts_target_token
```

Post:
```
	# use form-input-nginx-module
	set_form_input $sts_source_token access_token;
	sts_handler $sts_source_token $sts_target_token
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
