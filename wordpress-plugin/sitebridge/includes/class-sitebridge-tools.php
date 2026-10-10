<?php
/**
 * WPVibe-style tools: plugin REST routes, abilities, post meta, media, custom CSS,
 * option writes and cache purging. Each route is gated by a SiteBridge capability.
 *
 * @package SiteBridge
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SiteBridge_Tools {

	/** Option names that are never written through SiteBridge. */
	protected $protected_options = array( 'siteurl', 'home', 'admin_email', 'new_admin_email', 'users_can_register', 'default_role', 'active_plugins', 'active_sitewide_plugins', 'template', 'stylesheet', 'recently_activated', 'uninstall_plugins', 'auto_update_plugins', 'auto_update_themes', 'cron', 'rewrite_rules' );

	public function register_routes() {
		$ns = SITEBRIDGE_NS;
		register_rest_route( $ns, '/rest', array( 'methods' => 'POST', 'callback' => array( $this, 'rest_proxy' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'rest_proxy' ) ) );
		register_rest_route( $ns, '/abilities', array( 'methods' => 'GET', 'callback' => array( $this, 'list_abilities' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'rest_proxy' ) ) );
		register_rest_route( $ns, '/abilities/run', array( 'methods' => 'POST', 'callback' => array( $this, 'run_ability' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'rest_proxy' ) ) );
		register_rest_route(
			$ns,
			'/meta/(?P<id>\d+)',
			array(
				array( 'methods' => 'GET', 'callback' => array( $this, 'get_meta' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ) ),
				array( 'methods' => 'PUT', 'callback' => array( $this, 'update_meta' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ) ),
			)
		);
		register_rest_route( $ns, '/media', array( 'methods' => 'POST', 'callback' => array( $this, 'upload_media' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ) ) );
		register_rest_route(
			$ns,
			'/css',
			array(
				array( 'methods' => 'GET', 'callback' => array( $this, 'get_css' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ) ),
				array( 'methods' => 'PUT', 'callback' => array( $this, 'update_css' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ) ),
			)
		);
		register_rest_route( $ns, '/option-write/(?P<name>[A-Za-z0-9_\-]+)', array( 'methods' => 'PUT', 'callback' => array( $this, 'update_option_value' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'options_write' ) ) );
		register_rest_route( $ns, '/cache/purge', array( 'methods' => 'POST', 'callback' => array( $this, 'purge_cache' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* REST proxy: any registered route, as the connected administrator    */
	/* ------------------------------------------------------------------ */

	/**
	 * Routes reachable only when the matching SiteBridge capability is enabled,
	 * so the proxy never widens what the settings screen allows.
	 *
	 * @return WP_Error|null
	 */
	protected function guard_route( $method, $route ) {
		$settings = sitebridge_get_settings();
		$write    = 'GET' !== $method;
		$route    = '/' . ltrim( $route, '/' );
		if ( 0 === strpos( $route, '/' . SITEBRIDGE_NS ) ) {
			return new WP_Error( 'sitebridge_proxy_loop', 'Call SiteBridge tools directly, not through the REST proxy.', array( 'status' => 400 ) );
		}
		if ( false !== strpos( $route, '/application-passwords' ) ) {
			return new WP_Error( 'sitebridge_proxy_forbidden', 'Application passwords cannot be managed through SiteBridge.', array( 'status' => 403 ) );
		}
		if ( $write && preg_match( '#^/wp/v2/users(/|$)#', $route ) ) {
			return new WP_Error( 'sitebridge_proxy_forbidden', 'Users and roles cannot be changed through SiteBridge.', array( 'status' => 403 ) );
		}
		if ( $write && preg_match( '#^/wp/v2/(plugins|themes)(/|$)#', $route ) && empty( $settings['code_edit'] ) ) {
			return new WP_Error( 'sitebridge_forbidden', 'Installing or changing plugins and themes requires the code editing capability.', array( 'status' => 403 ) );
		}
		if ( $write && preg_match( '#^/wp/v2/settings(/|$)#', $route ) && empty( $settings['options_write'] ) ) {
			return new WP_Error( 'sitebridge_forbidden', 'Changing settings requires the option writing capability.', array( 'status' => 403 ) );
		}
		if ( $write && empty( $settings['content_write'] ) ) {
			return new WP_Error( 'sitebridge_forbidden', 'Write requests require the content management capability.', array( 'status' => 403 ) );
		}
		return null;
	}

	public function rest_proxy( $request ) {
		$body   = $request->get_json_params();
		$method = strtoupper( isset( $body['method'] ) ? (string) $body['method'] : 'GET' );
		$route  = isset( $body['route'] ) ? (string) $body['route'] : '';
		if ( ! in_array( $method, array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) || '' === $route || preg_match( '/[\x00-\x1f]/', $route ) ) {
			return new WP_Error( 'invalid', 'Provide a method (GET, POST, PUT, PATCH or DELETE) and a route such as /wp/v2/posts.', array( 'status' => 400 ) );
		}
		$path  = (string) wp_parse_url( $route, PHP_URL_PATH );
		$query = array();
		wp_parse_str( (string) wp_parse_url( $route, PHP_URL_QUERY ), $query );
		if ( isset( $body['query'] ) && is_array( $body['query'] ) ) {
			$query = array_merge( $query, $body['query'] );
		}
		$path  = '/' . ltrim( preg_replace( '#^/?wp-json#', '', $path ), '/' );
		$guard = $this->guard_route( $method, $path );
		if ( $guard ) {
			SiteBridge_Logger::log( 'rest.proxy', 'denied', $method . ' ' . $path, SiteBridge_Auth::current_label() );
			return $guard;
		}
		$inner = new WP_REST_Request( $method, $path );
		$inner->set_query_params( $query );
		if ( isset( $body['body'] ) && is_array( $body['body'] ) ) {
			$inner->set_header( 'Content-Type', 'application/json' );
			$inner->set_body( wp_json_encode( $body['body'] ) );
			$inner->set_body_params( $body['body'] );
		}
		$response = SiteBridge_Auth::internal_dispatch(
			function () use ( $inner ) {
				return rest_do_request( $inner );
			}
		);
		$server = rest_get_server();
		$data   = $server->response_to_data( $response, ! empty( $body['embed'] ) );
		SiteBridge_Logger::log( 'rest.proxy', $response->is_error() ? 'error' : 'ok', $method . ' ' . $path . ' → ' . $response->get_status(), SiteBridge_Auth::current_label() );
		$headers = array_intersect_key( $response->get_headers(), array_flip( array( 'X-WP-Total', 'X-WP-TotalPages' ) ) );
		return rest_ensure_response( array( 'status' => $response->get_status(), 'headers' => $headers, 'data' => $data ) );
	}

	/* ------------------------------------------------------------------ */
	/* Abilities API (WordPress 6.9+)                                      */
	/* ------------------------------------------------------------------ */

	public function list_abilities( $request ) {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return new WP_Error( 'no_abilities', 'This site does not support the WordPress Abilities API (WordPress 6.9+ or the Abilities API plugin).', array( 'status' => 400 ) );
		}
		$search = strtolower( (string) $request->get_param( 'search' ) );
		$out    = array();
		foreach ( wp_get_abilities() as $ability ) {
			$row = array( 'name' => $ability->get_name(), 'label' => $ability->get_label(), 'description' => $ability->get_description(), 'input_schema' => $ability->get_input_schema() );
			if ( '' === $search || false !== strpos( strtolower( $row['name'] . ' ' . $row['label'] . ' ' . $row['description'] ), $search ) ) {
				$out[] = $row;
			}
		}
		return rest_ensure_response( array( 'abilities' => $out ) );
	}

	public function run_ability( $request ) {
		if ( ! function_exists( 'wp_get_ability' ) ) {
			return new WP_Error( 'no_abilities', 'This site does not support the WordPress Abilities API.', array( 'status' => 400 ) );
		}
		$body    = $request->get_json_params();
		$ability = wp_get_ability( isset( $body['name'] ) ? (string) $body['name'] : '' );
		if ( ! $ability ) {
			return new WP_Error( 'not_found', 'Unknown ability. Use discover_abilities to list them.', array( 'status' => 404 ) );
		}
		$result = $ability->execute( $body['input'] ?? null );
		SiteBridge_Logger::log( 'ability.run', is_wp_error( $result ) ? 'error' : 'ok', $ability->get_name(), SiteBridge_Auth::current_label() );
		return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'result' => $result ) );
	}

	/* ------------------------------------------------------------------ */
	/* Post meta (SEO fields, page-builder data, custom fields)            */
	/* ------------------------------------------------------------------ */

	public function get_meta( $request ) {
		$id = (int) $request['id'];
		if ( ! get_post( $id ) ) {
			return new WP_Error( 'not_found', 'Post not found.', array( 'status' => 404 ) );
		}
		$key = (string) $request->get_param( 'key' );
		if ( '' !== $key ) {
			return rest_ensure_response( array( 'id' => $id, 'key' => $key, 'value' => get_post_meta( $id, $key, true ) ) );
		}
		$meta = array();
		foreach ( get_post_meta( $id ) as $name => $values ) {
			$value = maybe_unserialize( $values[0] );
			// Large blobs (page-builder JSON) are listed by size; fetch them with key.
			$meta[ $name ] = is_string( $value ) && strlen( $value ) > 2000 ? '[' . strlen( $value ) . ' bytes; request with key=' . $name . ']' : $value;
		}
		return rest_ensure_response( array( 'id' => $id, 'meta' => $meta ) );
	}

	public function update_meta( $request ) {
		$id = (int) $request['id'];
		if ( ! get_post( $id ) ) {
			return new WP_Error( 'not_found', 'Post not found.', array( 'status' => 404 ) );
		}
		$body = $request->get_json_params();
		if ( empty( $body['meta'] ) || ! is_array( $body['meta'] ) ) {
			return new WP_Error( 'invalid', 'Provide "meta" as an object of key → value. Use null to delete a key.', array( 'status' => 400 ) );
		}
		$done = array();
		foreach ( $body['meta'] as $key => $value ) {
			$key = (string) $key;
			if ( '' === $key || strlen( $key ) > 255 || in_array( $key, array( '_edit_lock', '_edit_last', '_wp_old_slug' ), true ) ) {
				continue;
			}
			if ( null === $value ) {
				delete_post_meta( $id, $key );
			} else {
				// wp_slash: update_post_meta unslashes its input.
				update_post_meta( $id, $key, wp_slash( $value ) );
			}
			$done[] = $key;
		}
		clean_post_cache( $id );
		$this->purge_post( $id );
		SiteBridge_Logger::log( 'meta.update', 'ok', 'id=' . $id . ' keys=' . implode( ',', $done ), SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'id' => $id, 'updated' => $done ) );
	}

	/* ------------------------------------------------------------------ */
	/* Media upload: from a public URL or base64 data                      */
	/* ------------------------------------------------------------------ */

	public function upload_media( $request ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';
		$body     = $request->get_json_params();
		$filename = sanitize_file_name( isset( $body['filename'] ) ? (string) $body['filename'] : '' );
		if ( ! empty( $body['url'] ) ) {
			$url = esc_url_raw( (string) $body['url'] );
			// download_url uses wp_safe_remote_get, which refuses private network destinations.
			$tmp = download_url( $url, 60 );
			if ( is_wp_error( $tmp ) ) {
				return new WP_Error( 'download_failed', 'Could not download that URL: ' . $tmp->get_error_message(), array( 'status' => 400 ) );
			}
			if ( '' === $filename ) {
				$filename = sanitize_file_name( wp_basename( (string) wp_parse_url( $url, PHP_URL_PATH ) ) );
			}
		} elseif ( ! empty( $body['data'] ) ) {
			$bytes = base64_decode( (string) $body['data'], true );
			if ( false === $bytes || '' === $filename ) {
				return new WP_Error( 'invalid', 'Provide valid base64 "data" and a "filename" with an extension.', array( 'status' => 400 ) );
			}
			$tmp = wp_tempnam( $filename );
			file_put_contents( $tmp, $bytes ); // phpcs:ignore
		} else {
			return new WP_Error( 'invalid', 'Provide "url" or base64 "data".', array( 'status' => 400 ) );
		}
		$file = array( 'name' => $filename ? $filename : 'upload', 'tmp_name' => $tmp );
		// media_handle_sideload checks the file type against the site's allowed MIME types.
		$id = media_handle_sideload( $file, isset( $body['post_id'] ) ? (int) $body['post_id'] : 0, isset( $body['title'] ) ? sanitize_text_field( $body['title'] ) : null );
		if ( file_exists( $tmp ) ) {
			wp_delete_file( $tmp );
		}
		if ( is_wp_error( $id ) ) {
			SiteBridge_Logger::log( 'media.upload', 'error', $id->get_error_message(), SiteBridge_Auth::current_label() );
			return $id;
		}
		if ( isset( $body['alt'] ) ) {
			update_post_meta( $id, '_wp_attachment_image_alt', sanitize_text_field( $body['alt'] ) );
		}
		if ( isset( $body['caption'] ) ) {
			wp_update_post( array( 'ID' => $id, 'post_excerpt' => wp_kses_post( $body['caption'] ) ) );
		}
		SiteBridge_Logger::log( 'media.upload', 'ok', 'id=' . $id, SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'id' => $id, 'url' => wp_get_attachment_url( $id ), 'mime_type' => get_post_mime_type( $id ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* Customizer "Additional CSS" for the active theme                    */
	/* ------------------------------------------------------------------ */

	public function get_css() {
		return rest_ensure_response( array( 'theme' => get_stylesheet(), 'css' => wp_get_custom_css() ) );
	}

	public function update_css( $request ) {
		$body = $request->get_json_params();
		if ( ! isset( $body['css'] ) || ! is_string( $body['css'] ) ) {
			return new WP_Error( 'invalid', 'Provide "css" with the complete stylesheet.', array( 'status' => 400 ) );
		}
		if ( preg_match( '#</?\w+#', $body['css'] ) ) {
			return new WP_Error( 'invalid', 'CSS must not contain HTML tags.', array( 'status' => 400 ) );
		}
		$post = wp_update_custom_css_post( $body['css'] );
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		$this->purge_all();
		SiteBridge_Logger::log( 'css.update', 'ok', strlen( $body['css'] ) . ' bytes', SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'theme' => get_stylesheet(), 'bytes' => strlen( $body['css'] ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* Option write (guarded)                                              */
	/* ------------------------------------------------------------------ */

	public function update_option_value( $request ) {
		global $wpdb;
		$name = sanitize_key( $request['name'] );
		$deny = array_merge( $this->protected_options, array( $wpdb->prefix . 'user_roles' ) );
		if ( in_array( $name, $deny, true ) || 0 === strpos( $name, 'sitebridge' ) || preg_match( '/auth_key|salt|secret|password|token|api_key|license/', $name ) ) {
			SiteBridge_Logger::log( 'option.write', 'denied', $name, SiteBridge_Auth::current_label() );
			return new WP_Error( 'forbidden_option', 'That option cannot be changed through SiteBridge.', array( 'status' => 403 ) );
		}
		$body = $request->get_json_params();
		if ( ! array_key_exists( 'value', (array) $body ) ) {
			return new WP_Error( 'invalid', 'Provide "value".', array( 'status' => 400 ) );
		}
		$previous = get_option( $name, null );
		update_option( $name, $body['value'] );
		SiteBridge_Logger::log( 'option.write', 'ok', $name, SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'name' => $name, 'previous' => $previous, 'value' => get_option( $name, null ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* Cache purge                                                         */
	/* ------------------------------------------------------------------ */

	public function purge_cache( $request ) {
		$body = $request->get_json_params();
		$id   = isset( $body['post_id'] ) ? (int) $body['post_id'] : 0;
		$done = $id ? $this->purge_post( $id ) : $this->purge_all();
		SiteBridge_Logger::log( 'cache.purge', 'ok', ( $id ? 'id=' . $id . ' ' : '' ) . implode( ',', $done ), SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'purged' => $done ) );
	}

	/** Purge every detected page cache. Returns the cache names that were purged. */
	public function purge_all() {
		$done = array();
		if ( function_exists( 'rocket_clean_domain' ) ) { rocket_clean_domain(); $done[] = 'wp-rocket'; }
		if ( defined( 'LSCWP_V' ) ) { do_action( 'litespeed_purge_all' ); $done[] = 'litespeed'; }
		if ( function_exists( 'w3tc_flush_all' ) ) { w3tc_flush_all(); $done[] = 'w3-total-cache'; }
		if ( function_exists( 'wp_cache_clear_cache' ) ) { wp_cache_clear_cache(); $done[] = 'wp-super-cache'; }
		if ( function_exists( 'sg_cachepress_purge_cache' ) ) { sg_cachepress_purge_cache(); $done[] = 'siteground'; }
		if ( class_exists( 'autoptimizeCache' ) ) { autoptimizeCache::clearall(); $done[] = 'autoptimize'; }
		if ( isset( $GLOBALS['wp_fastest_cache'] ) && method_exists( $GLOBALS['wp_fastest_cache'], 'deleteCache' ) ) { $GLOBALS['wp_fastest_cache']->deleteCache( true ); $done[] = 'wp-fastest-cache'; }
		if ( class_exists( '\\Elementor\\Plugin' ) && \Elementor\Plugin::$instance && isset( \Elementor\Plugin::$instance->files_manager ) ) { \Elementor\Plugin::$instance->files_manager->clear_cache(); $done[] = 'elementor-css'; }
		do_action( 'sitebridge_purge_all' );
		wp_cache_flush();
		$done[] = 'object-cache';
		return $done;
	}

	/** Purge caches for one post. Falls back to a full purge where only that is supported. */
	public function purge_post( $id ) {
		$done = array();
		clean_post_cache( $id );
		if ( function_exists( 'rocket_clean_post' ) ) { rocket_clean_post( $id ); $done[] = 'wp-rocket'; }
		if ( defined( 'LSCWP_V' ) ) { do_action( 'litespeed_purge_post', $id ); $done[] = 'litespeed'; }
		if ( function_exists( 'w3tc_flush_post' ) ) { w3tc_flush_post( $id ); $done[] = 'w3-total-cache'; }
		if ( function_exists( 'wpsc_delete_post_cache' ) ) { wpsc_delete_post_cache( $id ); $done[] = 'wp-super-cache'; }
		if ( function_exists( 'sg_cachepress_purge_cache' ) ) { sg_cachepress_purge_cache( get_permalink( $id ) ); $done[] = 'siteground'; }
		do_action( 'sitebridge_purge_post', $id );
		$done[] = 'post-cache';
		return $done;
	}
}
