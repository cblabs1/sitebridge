<?php
/**
 * API-key authentication and capability gating for SiteBridge.
 *
 * @package SiteBridge
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SiteBridge_Auth {

    protected static $application = null;
    protected static $application_user = null;

    public static function register_application_password_hooks() {
        add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'check_application' ), 10, 4 );
        add_action( 'application_password_did_authenticate', array( __CLASS__, 'capture_application' ), 10, 2 );
        add_filter( 'rest_pre_dispatch', array( __CLASS__, 'restrict_application_routes' ), 5, 3 );
    }
    public static function check_application( $error, $user, $item, $password ) {
        if ( ( $item['app_id'] ?? '' ) !== SITEBRIDGE_APP_ID ) { return; }
        $settings = sitebridge_get_settings();
        if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || ! user_can( $user, 'manage_options' ) || empty( $settings['enabled'] ) ) {
            $error->add( 'sitebridge_application_forbidden', 'This SiteBridge application password requires an administrator and an enabled SiteBridge REST API.', array( 'status' => 403 ) );
        }
    }
    public static function capture_application( $user, $item ) {
        self::$application = ( $item['app_id'] ?? '' ) === SITEBRIDGE_APP_ID ? $item : null;
        self::$application_user = self::$application ? $user : null;
    }
    public static function restrict_application_routes( $result, $server, $request ) {
        if ( self::$application && strpos( $request->get_route(), '/' . SITEBRIDGE_NS . '/' ) !== 0 ) {
            return new WP_Error( 'sitebridge_application_scope', 'This application password is restricted to SiteBridge endpoints.', array( 'status' => 403 ) );
        }
        return $result;
    }
    public static function current_application() {
        return self::$application && self::$application_user && get_current_user_id() === self::$application_user->ID && current_user_can( 'manage_options' ) ? self::$application : null;
    }

	/**
	 * The key record validated for the current request (or null).
	 *
	 * @var array|null
	 */
	protected static $current_key = null;

	/**
	 * Extract the Bearer token from the request.
	 */
	public static function bearer_token( $request ) {
		$header = $request->get_header( 'authorization' );
		if ( ! $header ) {
			// Some servers strip Authorization; allow a fallback header.
			$header = $request->get_header( 'x_sitebridge_key' );
			if ( $header ) {
				return trim( $header );
			}
			return '';
		}
		if ( 0 === stripos( $header, 'bearer ' ) ) {
			return trim( substr( $header, 7 ) );
		}
		return trim( $header );
	}

	/**
	 * Look up a stored key record by matching the raw token's SHA-256 hash.
	 * Constant-time comparison against every stored hash.
	 *
	 * @return array|null  Key record or null.
	 */
	public static function match_key( $raw ) {
		if ( '' === $raw ) {
			return null;
		}
		$hash  = hash( 'sha256', $raw );
		$keys  = get_option( SITEBRIDGE_OPT_KEYS, array() );
		$found = null;
		if ( is_array( $keys ) ) {
			foreach ( $keys as $id => $rec ) {
				if ( empty( $rec['hash'] ) ) {
					continue;
				}
				if ( hash_equals( (string) $rec['hash'], $hash ) ) {
					$rec['id'] = $id;
					$found     = $rec;
				}
			}
		}
		return $found;
	}

	/**
	 * Build a permission_callback bound to a required capability flag.
	 *
	 * Usage: 'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' )
	 *
	 * @param string $cap  Capability flag name from settings.
	 * @return callable
	 */
	public static function require_cap( $cap ) {
		return function ( $request ) use ( $cap ) {
			$settings = sitebridge_get_settings();

			if ( empty( $settings['enabled'] ) ) {
				return new WP_Error( 'sitebridge_disabled', 'SiteBridge API is disabled.', array( 'status' => 403 ) );
			}

			$raw = self::bearer_token( $request );
			$rec = self::match_key( $raw );
            $application = self::current_application();
            if ( ! $rec && $application ) {
                $rec = array( 'id' => $application['uuid'], 'label' => $application['name'], 'native' => true );
            }
			if ( ! $rec ) {
				SiteBridge_Logger::log( 'auth', 'denied', 'Invalid or missing API key' );
				return new WP_Error( 'sitebridge_unauthorized', 'Invalid or missing API key.', array( 'status' => 401 ) );
			}

			// Capability must be enabled globally.
			if ( empty( $settings[ $cap ] ) ) {
				SiteBridge_Logger::log( 'cap:' . $cap, 'denied', 'Capability disabled in settings', isset( $rec['label'] ) ? $rec['label'] : '' );
				return new WP_Error( 'sitebridge_forbidden', sprintf( 'Capability "%s" is disabled in SiteBridge settings.', $cap ), array( 'status' => 403 ) );
			}

			// Per-key capability restriction (optional): if a key lists caps, enforce them.
			if ( ! empty( $rec['caps'] ) && is_array( $rec['caps'] ) && ! in_array( $cap, $rec['caps'], true ) ) {
				SiteBridge_Logger::log( 'cap:' . $cap, 'denied', 'Key not permitted for capability', isset( $rec['label'] ) ? $rec['label'] : '' );
				return new WP_Error( 'sitebridge_forbidden', 'This API key is not permitted for that capability.', array( 'status' => 403 ) );
			}

			self::$current_key = $rec;
			if ( empty( $rec['native'] ) ) { self::touch_key( $rec['id'] ); }
			return true;
		};
	}

	/**
	 * Update last_used timestamp for a key.
	 */
	protected static function touch_key( $id ) {
		$keys = get_option( SITEBRIDGE_OPT_KEYS, array() );
		if ( isset( $keys[ $id ] ) ) {
			$keys[ $id ]['last_used'] = gmdate( 'Y-m-d H:i:s' );
			update_option( SITEBRIDGE_OPT_KEYS, $keys, false );
		}
	}

	/**
	 * Label of the current request's key (for logging).
	 */
	public static function current_label() {
		return self::$current_key && isset( self::$current_key['label'] ) ? self::$current_key['label'] : '';
	}

	/**
	 * Generate a new API key. Returns the RAW key (shown once); stores only its hash.
	 *
	 * @return array [ 'id' => string, 'raw' => string ]
	 */
	public static function generate_key( $label, $caps = array() ) {
		$raw  = 'sbk_' . bin2hex( random_bytes( 24 ) );
		$id   = 'k_' . bin2hex( random_bytes( 6 ) );
		$keys = get_option( SITEBRIDGE_OPT_KEYS, array() );
		if ( ! is_array( $keys ) ) {
			$keys = array();
		}
		$keys[ $id ] = array(
			'label'     => sanitize_text_field( $label ),
			'hash'      => hash( 'sha256', $raw ),
			'caps'      => array_values( array_filter( array_map( 'sanitize_key', (array) $caps ) ) ),
			'created'   => gmdate( 'Y-m-d H:i:s' ),
			'last_used' => null,
		);
		update_option( SITEBRIDGE_OPT_KEYS, $keys, false );
		return array(
			'id'  => $id,
			'raw' => $raw,
		);
	}

	/**
	 * Revoke a key by id.
	 */
	public static function revoke_key( $id ) {
		$keys = get_option( SITEBRIDGE_OPT_KEYS, array() );
		if ( isset( $keys[ $id ] ) ) {
			unset( $keys[ $id ] );
			update_option( SITEBRIDGE_OPT_KEYS, $keys, false );
			return true;
		}
		return false;
	}
}
