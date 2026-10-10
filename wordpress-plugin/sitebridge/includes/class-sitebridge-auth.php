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
        add_filter( 'rest_pre_dispatch', array( __CLASS__, 'authenticate_forwarded_application' ), 4, 3 );
        add_filter( 'rest_pre_dispatch', array( __CLASS__, 'restrict_application_routes' ), 5, 3 );
    }
    public static function check_application( $error, $user, $item, $password ) {
        if ( ( $item['app_id'] ?? '' ) !== SITEBRIDGE_APP_ID ) { return; }
        // WordPress has not initialized its current user here. Capability and
        // option filters can read that user and recursively restart authentication.
        // Defer those checks to REST dispatch, after user initialization finishes.
        if ( ! self::is_sitebridge_rest_request() ) {
            SiteBridge_Logger::log( 'auth', 'denied', 'SiteBridge application password used outside SiteBridge REST routes' );
            $error->add( 'sitebridge_application_forbidden', 'This SiteBridge application password is restricted to the REST API.', array( 'status' => 403 ) );
        }
    }
    /**
     * Plugins may initialize the current user before WordPress defines REST_REQUEST
     * (core treats that as an API request only through application_password_is_api_request).
     * Recognize SiteBridge REST URLs directly so that early authentication is not refused.
     */
    private static function is_sitebridge_rest_request() {
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) { return false; }
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) { return true; }
        // Avoid home_url()/options here: their filters can restart user initialization.
        if ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) ) {
            return 0 === strpos( wp_unslash( $_GET['rest_route'] ), '/' . SITEBRIDGE_NS . '/' );
        }
        $path = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';
        return false !== strpos( $path, '/' . trim( rest_get_url_prefix(), '/' ) . '/' . SITEBRIDGE_NS . '/' );
    }
    public static function capture_application( $user, $item ) {
        self::$application = ( $item['app_id'] ?? '' ) === SITEBRIDGE_APP_ID ? $item : null;
        self::$application_user = self::$application ? $user : null;
    }
    public static function restrict_application_routes( $result, $server, $request ) {
        if ( self::authenticated_application() ) {
            if ( strpos( $request->get_route(), '/' . SITEBRIDGE_NS . '/' ) !== 0 ) {
                SiteBridge_Logger::log( 'auth', 'denied', 'Application password used outside the SiteBridge namespace' );
                return new WP_Error( 'sitebridge_application_scope', 'This application password is restricted to SiteBridge endpoints.', array( 'status' => 403 ) );
            }
            $settings = sitebridge_get_settings();
            if ( ! current_user_can( 'manage_options' ) || empty( $settings['enabled'] ) ) {
                SiteBridge_Logger::log( 'auth', 'denied', sprintf( 'Application password refused: user %d, manage_options %s, SiteBridge %s', get_current_user_id(), current_user_can( 'manage_options' ) ? 'yes' : 'no (removed by role or another plugin)', empty( $settings['enabled'] ) ? 'disabled' : 'enabled' ) );
                return new WP_Error( 'sitebridge_application_forbidden', 'This SiteBridge application password requires an administrator and an enabled SiteBridge REST API.', array( 'status' => 403 ) );
            }
        }
        return $result;
    }
    private static function authenticated_application() {
        // Core may authenticate before this plugin's observation hook runs.
        $uuid = function_exists( 'rest_get_authenticated_app_password' ) ? rest_get_authenticated_app_password() : null;
        if ( $uuid ) {
            $item = WP_Application_Passwords::get_user_application_password( get_current_user_id(), $uuid );
            return $item && ( $item['app_id'] ?? '' ) === SITEBRIDGE_APP_ID ? $item : null;
        }
        return self::$application && self::$application_user && get_current_user_id() === self::$application_user->ID ? self::$application : null;
    }
    public static function current_application() {
        return current_user_can( 'manage_options' ) ? self::authenticated_application() : null;
    }
    public static function authenticate_forwarded_application( $result, $server, $request ) {
        if ( $result !== null || strpos( $request->get_route(), '/' . SITEBRIDGE_NS . '/' ) !== 0 || self::current_application() ) { return $result; }
        // Some CGI hosts remove Authorization before WordPress can populate PHP_AUTH_*.
        // This header transports a credential only; core still checks its stored hash,
        // availability and authentication hooks. REST dispatch checks permissions.
        $header = $request->get_header( 'x_sitebridge_authorization' );
        if ( ! $header ) { $header = $request->get_header( 'authorization' ); }
        if ( ! is_string( $header ) || strlen( $header ) > 2048 || ! preg_match( '/^Basic ([a-zA-Z0-9+\/=]+)$/', $header, $matches ) ) { return $result; }
        $decoded = base64_decode( $matches[1], true );
        if ( $decoded === false || strpos( $decoded, ':' ) === false ) { return new WP_Error( 'sitebridge_invalid_authorization', 'Invalid application authentication header.', array( 'status' => 401 ) ); }
        list( $username, $password ) = explode( ':', $decoded, 2 );
        $user = wp_authenticate_application_password( null, $username, $password );
        if ( is_wp_error( $user ) ) { SiteBridge_Logger::log( 'auth', 'denied', 'Forwarded application password failed: ' . $user->get_error_code() ); return new WP_Error( 'sitebridge_invalid_authorization', 'Application password authentication failed.', array( 'status' => 401 ) ); }
        if ( ! $user instanceof WP_User || ! self::$application || ! self::$application_user || self::$application_user->ID !== $user->ID ) { SiteBridge_Logger::log( 'auth', 'denied', 'Forwarded password is not a SiteBridge application password' ); return new WP_Error( 'sitebridge_native_required', 'A SiteBridge application password for an administrator is required.', array( 'status' => 401 ) ); }
        wp_set_current_user( $user->ID );
        return self::restrict_application_routes( $result, $server, $request );
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
