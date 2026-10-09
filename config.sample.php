<?php
/**
 * SiteBridge Hub configuration.
 *
 * COPY this file to `config.php` (same folder) and fill in your values.
 * config.php is blocked from the web by .htaccess and must never be committed.
 */

return array(

	/*
	 * Master token: the single secret that protects this hub.
	 * Any AI client must send it as  Authorization: Bearer <this value>.
	 * Generate a long random string, e.g. on the server:  openssl rand -hex 32
	 */
	'master_token' => 'CHANGE-ME-to-a-long-random-string',

	/*
	 * The WordPress sites this hub can manage.
	 * The key (e.g. "rickrak") is the short name you pass as the tool's "site" argument.
	 * "url" is the site root; "key" is the SiteBridge plugin API key generated on that site
	 * (Settings → SiteBridge → Generate new key).
	 */
	'sites' => array(
		'rickrak' => array(
			'url' => 'https://rickrak.com',
			'key' => 'sbk_PUT_THE_PLUGIN_KEY_FOR_THIS_SITE_HERE',
		),
		'wpsprints' => array(
			'url' => 'https://www.wpsprints.com',
			'key' => 'sbk_PUT_THE_PLUGIN_KEY_FOR_THIS_SITE_HERE',
		),
		// Add as many as you like…
	),

	/*
	 * Optional: request timeout (seconds) when the hub calls a site.
	 */
	'timeout' => 30,
);
