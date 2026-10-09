<?php
/**
 * Lightweight activity logger for SiteBridge API calls.
 *
 * @package SiteBridge
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SiteBridge_Logger {

	/**
	 * Table name (with prefix).
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'sitebridge_log';
	}

	/**
	 * Create the log table on activation.
	 */
	public static function install_table() {
		global $wpdb;
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			key_label VARCHAR(120) NULL,
			action VARCHAR(80) NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'ok',
			detail TEXT NULL,
			ip VARCHAR(64) NULL,
			PRIMARY KEY (id),
			KEY created_at (created_at)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Insert a log row. Never throws.
	 *
	 * @param string $action  Short action code.
	 * @param string $status  'ok' | 'denied' | 'error'.
	 * @param string $detail  Human detail (kept short).
	 * @param string $label   API key label, if known.
	 */
	public static function log( $action, $status = 'ok', $detail = '', $label = '' ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->insert(
			self::table(),
			array(
				'action'    => substr( (string) $action, 0, 80 ),
				'status'    => substr( (string) $status, 0, 20 ),
				'detail'    => substr( (string) $detail, 0, 2000 ),
				'key_label' => substr( (string) $label, 0, 120 ),
				'ip'        => isset( $_SERVER['REMOTE_ADDR'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ), 0, 64 ) : '',
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Fetch recent log rows for the admin screen.
	 */
	public static function recent( $limit = 30 ) {
		global $wpdb;
		$table = self::table();
		$limit = max( 1, min( 200, (int) $limit ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit ) );
	}
}
