location ~* ^/(?<path>.*((wp-login|wp-admin|admin|administrator/index)\.php|administrator/?))$
{
	if (-e /usr/local/wpblocker/whitelist/$host) { return 402; }
	if (!-e $wpblocker_path)
	{
		rewrite ^ /__wpblocker/$path/form last;
	}
	error_page 402 = @fallback;
	return 402;
}

location ~* ^/__wpblocker/(?<path>.*)/form
{
	ssi on;
	ssi_types *;
	default_type "text/html; charset=utf-8";
	alias /usr/local/wpblocker/form.shtml;
}

location ~* ^/__wpblocker/(?<path>.*)/auth
{
	perl wpblocker::try_auth;
}

location ~* ^/__wpblocker/(?<path>.*)/ok
{
	internal;
	rewrite ^ /$path redirect;
}
