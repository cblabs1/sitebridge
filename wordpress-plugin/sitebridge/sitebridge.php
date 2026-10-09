<?php
/**
 * Plugin Name:       SiteBridge — AI Site Connector
 * Plugin URI:        https://example.com/sitebridge
 * Description:       Exposes safe, API-key-protected REST endpoints so an external MCP server / AI agent can manage this WordPress site (site info, content, WooCommerce, options, and guarded DB/code editing). A WPVibe-style connector you own.
 * Version:           0.2.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Your Agency
 * License:           GPL-2.0-or-later
 * Text Domain:       sitebridge
 *
 * SECURITY MODEL (read this):
 *  - Every endpoint requires a valid API key (Bearer token) that you generate in
 *    Settings → SiteBridge. Keys are shown once and stored only as SHA-256 hashes.
 *  - Every capability is individually toggleable and OFF by default except read-only
 *    site info. Write, DB-write and code-edit capabilities must be explicitly enabled.
 *  - DB-write and code-edit are inherently dangerous; they are heavily guarded, disabled
 *    by default, always backed up / logged, and should only be enabled on sites you control.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

define( 'SITEBRIDGE_VERSION', '0.2.0' );
define( 'SITEBRIDGE_FILE', __FILE__ );
define( 'SITEBRIDGE_DIR', plugin_dir_path( __FILE__ ) );
define( 'SITEBRIDGE_NS', 'sitebridge/v1' );
define( 'SITEBRIDGE_OPT_SETTINGS', 'sitebridge_settings' );
define( 'SITEBRIDGE_OPT_KEYS', 'sitebridge_keys' );

require_once SITEBRIDGE_DIR . 'includes/class-sitebridge-logger.php';
require_once SITEBRIDGE_DIR . 'includes/class-sitebridge-auth.php';
require_once SITEBRIDGE_DIR . 'includes/class-sitebridge-settings.php';
require_once SITEBRIDGE_DIR . 'includes/class-sitebridge-rest.php';
require_once SITEBRIDGE_DIR . 'includes/class-sitebridge-connect.php';

/**
 * Default capability flags. Only site_read is on by default.
 */
function sitebridge_default_settings() {
	return array(
		'enabled'       => true,
		'site_read'     => true,
		'content_write' => false,
		'woo_write'     => false,
		'options_read'  => false,
		'db_read'       => false,
		'db_write'      => false, // dangerous
		'code_edit'     => false, // dangerous
	);
}

function sitebridge_get_settings() {
	$saved = get_option( SITEBRIDGE_OPT_SETTINGS, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return wp_parse_args( $saved, sitebridge_default_settings() );
}

/**
 * Activation: create the activity-log table.
 */
function sitebridge_activate() {
	SiteBridge_Logger::install_table();
	if ( false === get_option( SITEBRIDGE_OPT_SETTINGS, false ) ) {
		add_option( SITEBRIDGE_OPT_SETTINGS, sitebridge_default_settings() );
	}
}
register_activation_hook( __FILE__, 'sitebridge_activate' );

/**
 * Boot.
 */
function sitebridge_boot() {
	new SiteBridge_Settings();
	new SiteBridge_Connect();
	add_action(
		'rest_api_init',
		function () {
			( new SiteBridge_REST() )->register_routes();
		}
	);
}
add_action( 'plugins_loaded', 'sitebridge_boot' );
