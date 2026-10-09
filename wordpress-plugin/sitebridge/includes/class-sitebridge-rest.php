<?php
/**
 * REST endpoints for SiteBridge.
 *
 * Namespace: sitebridge/v1
 *
 * @package SiteBridge
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SiteBridge_REST {

	public function register_routes() {
		$ns = SITEBRIDGE_NS;

		// --- Site info & health (read-only) ---
		register_rest_route(
			$ns,
			'/site',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_site' ),
				'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ),
			)
		);

		// --- Content: list / get / create / update ---
		register_rest_route(
			$ns,
			'/content',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'list_content' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'create_content' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ),
				),
			)
		);
		register_rest_route(
			$ns,
			'/content/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_content' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ),
				),
				array(
					'methods'             => 'PUT',
					'callback'            => array( $this, 'update_content' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'content_write' ),
				),
			)
		);

		// --- WooCommerce products ---
		register_rest_route(
			$ns,
			'/products',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'list_products' ),
				'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ),
			)
		);
		register_rest_route(
			$ns,
			'/products/(?P<id>\d+)',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'get_product' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ),
				),
				array(
					'methods'             => 'PUT',
					'callback'            => array( $this, 'update_product' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'woo_write' ),
				),
			)
		);

		// --- Options (read) ---
		register_rest_route(
			$ns,
			'/option/(?P<name>[A-Za-z0-9_\-]+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_option_value' ),
				'permission_callback' => SiteBridge_Auth::require_cap( 'options_read' ),
			)
		);

		// --- DB read (SELECT only) ---
		register_rest_route(
			$ns,
			'/db/query',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'db_query' ),
				'permission_callback' => SiteBridge_Auth::require_cap( 'db_read' ),
			)
		);

		// --- DB write (guarded, dangerous) ---
		register_rest_route(
			$ns,
			'/db/execute',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'db_execute' ),
				'permission_callback' => SiteBridge_Auth::require_cap( 'db_write' ),
			)
		);

		// --- Code / file edit (guarded, dangerous) ---
		register_rest_route(
			$ns,
			'/file',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'read_file' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'code_edit' ),
				),
				array(
					'methods'             => 'PUT',
					'callback'            => array( $this, 'write_file' ),
					'permission_callback' => SiteBridge_Auth::require_cap( 'code_edit' ),
				),
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Site info                                                          */
	/* ------------------------------------------------------------------ */

	public function get_site() {
		global $wp_version;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) {
			$plugins[] = array(
				'file'    => $file,
				'name'    => $data['Name'],
				'version' => $data['Version'],
				'active'  => is_plugin_active( $file ),
			);
		}
		$theme = wp_get_theme();

		SiteBridge_Logger::log( 'site.read', 'ok', '', SiteBridge_Auth::current_label() );

		return rest_ensure_response(
			array(
				'name'             => get_bloginfo( 'name' ),
				'url'              => home_url(),
				'wp_version'       => $wp_version,
				'php_version'      => PHP_VERSION,
				'is_multisite'     => is_multisite(),
				'active_theme'     => array(
					'name'    => $theme->get( 'Name' ),
					'version' => $theme->get( 'Version' ),
					'slug'    => $theme->get_stylesheet(),
				),
				'woocommerce'      => class_exists( 'WooCommerce' ) ? ( defined( 'WC_VERSION' ) ? WC_VERSION : true ) : false,
				'plugins'          => $plugins,
				'sitebridge'       => SITEBRIDGE_VERSION,
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* Content (posts / pages / any public post type)                      */
	/* ------------------------------------------------------------------ */

	protected function post_to_array( $post ) {
		return array(
			'id'        => $post->ID,
			'type'      => $post->post_type,
			'status'    => $post->post_status,
			'title'     => $post->post_title,
			'slug'      => $post->post_name,
			'excerpt'   => $post->post_excerpt,
			'content'   => $post->post_content,
			'link'      => get_permalink( $post ),
			'modified'  => $post->post_modified_gmt,
		);
	}

	public function list_content( $request ) {
		$type   = $request->get_param( 'type' ) ? sanitize_key( $request->get_param( 'type' ) ) : 'post';
		$search = $request->get_param( 'search' );
		$limit  = min( 100, max( 1, (int) ( $request->get_param( 'per_page' ) ?: 20 ) ) );

		$query = new WP_Query(
			array(
				'post_type'      => $type,
				'post_status'    => 'any',
				's'              => $search ? sanitize_text_field( $search ) : '',
				'posts_per_page' => $limit,
				'no_found_rows'  => true,
			)
		);
		$out = array();
		foreach ( $query->posts as $p ) {
			$row = $this->post_to_array( $p );
			unset( $row['content'] ); // keep list light
			$out[] = $row;
		}
		SiteBridge_Logger::log( 'content.list', 'ok', $type, SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'items' => $out ) );
	}

	public function get_content( $request ) {
		$post = get_post( (int) $request['id'] );
		if ( ! $post ) {
			return new WP_Error( 'not_found', 'Post not found.', array( 'status' => 404 ) );
		}
		return rest_ensure_response( $this->post_to_array( $post ) );
	}

	public function create_content( $request ) {
		$body = $request->get_json_params();
		if ( empty( $body['title'] ) && empty( $body['content'] ) ) {
			return new WP_Error( 'invalid', 'Provide at least a title or content.', array( 'status' => 400 ) );
		}
		$postarr = array(
			'post_type'    => isset( $body['type'] ) ? sanitize_key( $body['type'] ) : 'post',
			'post_title'   => isset( $body['title'] ) ? sanitize_text_field( $body['title'] ) : '',
			'post_content' => isset( $body['content'] ) ? wp_kses_post( $body['content'] ) : '',
			'post_excerpt' => isset( $body['excerpt'] ) ? wp_kses_post( $body['excerpt'] ) : '',
			'post_status'  => isset( $body['status'] ) ? sanitize_key( $body['status'] ) : 'draft',
		);
		$id = wp_insert_post( $postarr, true );
		if ( is_wp_error( $id ) ) {
			SiteBridge_Logger::log( 'content.create', 'error', $id->get_error_message(), SiteBridge_Auth::current_label() );
			return $id;
		}
		SiteBridge_Logger::log( 'content.create', 'ok', 'id=' . $id, SiteBridge_Auth::current_label() );
		return rest_ensure_response( $this->post_to_array( get_post( $id ) ) );
	}

	public function update_content( $request ) {
		$id = (int) $request['id'];
		if ( ! get_post( $id ) ) {
			return new WP_Error( 'not_found', 'Post not found.', array( 'status' => 404 ) );
		}
		$body    = $request->get_json_params();
		$postarr = array( 'ID' => $id );
		if ( isset( $body['title'] ) ) {
			$postarr['post_title'] = sanitize_text_field( $body['title'] );
		}
		if ( isset( $body['content'] ) ) {
			$postarr['post_content'] = wp_kses_post( $body['content'] );
		}
		if ( isset( $body['excerpt'] ) ) {
			$postarr['post_excerpt'] = wp_kses_post( $body['excerpt'] );
		}
		if ( isset( $body['status'] ) ) {
			$postarr['post_status'] = sanitize_key( $body['status'] );
		}
		$res = wp_update_post( $postarr, true );
		if ( is_wp_error( $res ) ) {
			SiteBridge_Logger::log( 'content.update', 'error', $res->get_error_message(), SiteBridge_Auth::current_label() );
			return $res;
		}
		SiteBridge_Logger::log( 'content.update', 'ok', 'id=' . $id, SiteBridge_Auth::current_label() );
		return rest_ensure_response( $this->post_to_array( get_post( $id ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* WooCommerce products                                                */
	/* ------------------------------------------------------------------ */

	protected function require_woo() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return new WP_Error( 'no_woo', 'WooCommerce is not active on this site.', array( 'status' => 400 ) );
		}
		return true;
	}

	public function list_products( $request ) {
		$check = $this->require_woo();
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$limit    = min( 100, max( 1, (int) ( $request->get_param( 'per_page' ) ?: 20 ) ) );
		$search   = $request->get_param( 'search' );
		$products = wc_get_products(
			array(
				'limit'  => $limit,
				's'      => $search ? sanitize_text_field( $search ) : '',
				'status' => 'any',
			)
		);
		$out = array();
		foreach ( $products as $p ) {
			$out[] = array(
				'id'     => $p->get_id(),
				'name'   => $p->get_name(),
				'type'   => $p->get_type(),
				'sku'    => $p->get_sku(),
				'price'  => $p->get_price(),
				'stock'  => $p->get_stock_quantity(),
				'status' => $p->get_status(),
			);
		}
		SiteBridge_Logger::log( 'products.list', 'ok', '', SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'items' => $out ) );
	}

	public function get_product( $request ) {
		$check = $this->require_woo();
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$p = wc_get_product( (int) $request['id'] );
		if ( ! $p ) {
			return new WP_Error( 'not_found', 'Product not found.', array( 'status' => 404 ) );
		}
		return rest_ensure_response(
			array(
				'id'                => $p->get_id(),
				'name'              => $p->get_name(),
				'type'              => $p->get_type(),
				'sku'               => $p->get_sku(),
				'regular_price'     => $p->get_regular_price(),
				'sale_price'        => $p->get_sale_price(),
				'price'             => $p->get_price(),
				'stock_quantity'    => $p->get_stock_quantity(),
				'stock_status'      => $p->get_stock_status(),
				'status'            => $p->get_status(),
				'short_description' => $p->get_short_description(),
				'description'       => $p->get_description(),
			)
		);
	}

	public function update_product( $request ) {
		$check = $this->require_woo();
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$p = wc_get_product( (int) $request['id'] );
		if ( ! $p ) {
			return new WP_Error( 'not_found', 'Product not found.', array( 'status' => 404 ) );
		}
		$body = $request->get_json_params();
		// Use WooCommerce CRUD setters so its own validation & hooks run.
		if ( isset( $body['regular_price'] ) ) {
			$p->set_regular_price( wc_format_decimal( $body['regular_price'] ) );
		}
		if ( isset( $body['sale_price'] ) ) {
			$p->set_sale_price( wc_format_decimal( $body['sale_price'] ) );
		}
		if ( isset( $body['stock_quantity'] ) ) {
			$p->set_manage_stock( true );
			$p->set_stock_quantity( (int) $body['stock_quantity'] );
		}
		if ( isset( $body['stock_status'] ) ) {
			$p->set_stock_status( sanitize_text_field( $body['stock_status'] ) );
		}
		if ( isset( $body['status'] ) ) {
			$p->set_status( sanitize_key( $body['status'] ) );
		}
		if ( isset( $body['name'] ) ) {
			$p->set_name( sanitize_text_field( $body['name'] ) );
		}
		if ( isset( $body['short_description'] ) ) {
			$p->set_short_description( wp_kses_post( $body['short_description'] ) );
		}
		if ( isset( $body['description'] ) ) {
			$p->set_description( wp_kses_post( $body['description'] ) );
		}
		$id = $p->save();
		SiteBridge_Logger::log( 'products.update', 'ok', 'id=' . $id, SiteBridge_Auth::current_label() );
		return $this->get_product( $request );
	}

	/* ------------------------------------------------------------------ */
	/* Options                                                             */
	/* ------------------------------------------------------------------ */

	public function get_option_value( $request ) {
		$name = sanitize_key( $request['name'] );
		// Never expose secrets / credentials.
		$blocklist = array( 'auth_key', 'auth_salt', 'secret', 'sitebridge_keys' );
		foreach ( $blocklist as $bad ) {
			if ( false !== stripos( $name, $bad ) ) {
				return new WP_Error( 'forbidden_option', 'That option cannot be read via SiteBridge.', array( 'status' => 403 ) );
			}
		}
		$value = get_option( $name, null );
		SiteBridge_Logger::log( 'option.read', 'ok', $name, SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'name' => $name, 'value' => $value ) );
	}

	/* ------------------------------------------------------------------ */
	/* DB read (SELECT / SHOW / DESCRIBE / EXPLAIN only)                    */
	/* ------------------------------------------------------------------ */

	public function db_query( $request ) {
		global $wpdb;
		$sql = trim( (string) $request->get_param( 'sql' ) );
		if ( '' === $sql ) {
			return new WP_Error( 'invalid', 'Provide a "sql" parameter.', array( 'status' => 400 ) );
		}
		$guard = $this->guard_readonly_sql( $sql );
		if ( is_wp_error( $guard ) ) {
			SiteBridge_Logger::log( 'db.query', 'denied', $guard->get_error_message(), SiteBridge_Auth::current_label() );
			return $guard;
		}
		$sql = $guard; // possibly appended LIMIT

		// phpcs:ignore WordPress.DB.PreparedSQL
		$rows = $wpdb->get_results( $sql, ARRAY_A );
		if ( $wpdb->last_error ) {
			SiteBridge_Logger::log( 'db.query', 'error', $wpdb->last_error, SiteBridge_Auth::current_label() );
			return new WP_Error( 'sql_error', $wpdb->last_error, array( 'status' => 400 ) );
		}
		SiteBridge_Logger::log( 'db.query', 'ok', substr( $sql, 0, 200 ), SiteBridge_Auth::current_label() );
		return rest_ensure_response(
			array(
				'row_count' => is_array( $rows ) ? count( $rows ) : 0,
				'rows'      => $rows,
			)
		);
	}

	/**
	 * Validate a statement is a safe, single, read-only query.
	 *
	 * @return string|WP_Error  The (possibly LIMIT-appended) SQL, or an error.
	 */
	protected function guard_readonly_sql( $sql ) {
		$trimmed = rtrim( $sql, "; \t\n\r" );
		// Reject multiple statements.
		if ( false !== strpos( $trimmed, ';' ) ) {
			return new WP_Error( 'multi_statement', 'Only a single statement is allowed.', array( 'status' => 400 ) );
		}
		// Reject comment markers that can hide payloads.
		if ( preg_match( '#(--|/\*|\#)#', $trimmed ) ) {
			return new WP_Error( 'comment_blocked', 'SQL comments are not allowed.', array( 'status' => 400 ) );
		}
		// Must start with a read-only verb.
		if ( ! preg_match( '/^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN)\b/i', $trimmed ) ) {
			return new WP_Error( 'not_readonly', 'Only SELECT / SHOW / DESCRIBE / EXPLAIN are allowed here.', array( 'status' => 400 ) );
		}
		// Belt & suspenders: block write verbs anywhere.
		if ( preg_match( '/\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE|GRANT|RENAME|INTO\s+OUTFILE|LOAD_FILE)\b/i', $trimmed ) ) {
			return new WP_Error( 'write_blocked', 'This looks like a write/DDL statement, which is not allowed here.', array( 'status' => 400 ) );
		}
		// Append a LIMIT if the query is a SELECT without one.
		if ( preg_match( '/^\s*SELECT\b/i', $trimmed ) && ! preg_match( '/\bLIMIT\b/i', $trimmed ) ) {
			$trimmed .= ' LIMIT 500';
		}
		return $trimmed;
	}

	/* ------------------------------------------------------------------ */
	/* DB write (guarded, dangerous)                                       */
	/* ------------------------------------------------------------------ */

	public function db_execute( $request ) {
		global $wpdb;
		$sql     = trim( (string) $request->get_param( 'sql' ) );
		$confirm = (bool) $request->get_param( 'confirm' );
		if ( '' === $sql ) {
			return new WP_Error( 'invalid', 'Provide a "sql" parameter.', array( 'status' => 400 ) );
		}
		if ( ! $confirm ) {
			return new WP_Error( 'confirm_required', 'Pass "confirm": true to run a write statement.', array( 'status' => 400 ) );
		}
		$trimmed = rtrim( $sql, "; \t\n\r" );
		if ( false !== strpos( $trimmed, ';' ) ) {
			return new WP_Error( 'multi_statement', 'Only a single statement is allowed.', array( 'status' => 400 ) );
		}
		if ( preg_match( '#(--|/\*|\#)#', $trimmed ) ) {
			return new WP_Error( 'comment_blocked', 'SQL comments are not allowed.', array( 'status' => 400 ) );
		}
		// Allow only UPDATE / INSERT / DELETE. Block schema-destructive DDL outright.
		if ( ! preg_match( '/^\s*(UPDATE|INSERT|DELETE)\b/i', $trimmed ) ) {
			return new WP_Error( 'not_dml', 'Only UPDATE / INSERT / DELETE are allowed (no DROP/ALTER/TRUNCATE/CREATE).', array( 'status' => 400 ) );
		}
		if ( preg_match( '/\b(DROP|ALTER|TRUNCATE|CREATE|GRANT|RENAME|INTO\s+OUTFILE)\b/i', $trimmed ) ) {
			return new WP_Error( 'ddl_blocked', 'Schema-changing statements are not allowed.', array( 'status' => 400 ) );
		}
		// Require a WHERE on UPDATE/DELETE to avoid mass writes.
		if ( preg_match( '/^\s*(UPDATE|DELETE)\b/i', $trimmed ) && ! preg_match( '/\bWHERE\b/i', $trimmed ) ) {
			return new WP_Error( 'where_required', 'UPDATE/DELETE must include a WHERE clause.', array( 'status' => 400 ) );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL
		$result = $wpdb->query( $trimmed );
		if ( false === $result ) {
			SiteBridge_Logger::log( 'db.execute', 'error', $wpdb->last_error ? $wpdb->last_error : 'query failed', SiteBridge_Auth::current_label() );
			return new WP_Error( 'sql_error', $wpdb->last_error ? $wpdb->last_error : 'Query failed.', array( 'status' => 400 ) );
		}
		SiteBridge_Logger::log( 'db.execute', 'ok', 'rows=' . (int) $result . ' :: ' . substr( $trimmed, 0, 160 ), SiteBridge_Auth::current_label() );
		return rest_ensure_response( array( 'rows_affected' => (int) $result ) );
	}

	/* ------------------------------------------------------------------ */
	/* File / code edit (guarded, dangerous)                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Resolve a caller-supplied path safely inside wp-content.
	 *
	 * @return string|WP_Error absolute path.
	 */
	protected function safe_path( $rel ) {
		$rel  = ltrim( (string) $rel, '/' );
		$base = wp_normalize_path( WP_CONTENT_DIR );
		$full = wp_normalize_path( $base . '/' . $rel );

		// Reject traversal.
		if ( false !== strpos( $rel, '..' ) ) {
			return new WP_Error( 'bad_path', 'Path traversal is not allowed.', array( 'status' => 400 ) );
		}
		// Must remain inside wp-content.
		if ( 0 !== strpos( $full, trailingslashit( $base ) ) ) {
			return new WP_Error( 'outside_root', 'Path must be inside wp-content.', array( 'status' => 400 ) );
		}
		return $full;
	}

	protected $allowed_ext = array( 'php', 'js', 'css', 'txt', 'json', 'html', 'md' );

	public function read_file( $request ) {
		$path = $this->safe_path( $request->get_param( 'path' ) );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return new WP_Error( 'not_found', 'File not found or not readable.', array( 'status' => 404 ) );
		}
		if ( filesize( $path ) > 512 * 1024 ) {
			return new WP_Error( 'too_large', 'File is larger than 512KB.', array( 'status' => 413 ) );
		}
		SiteBridge_Logger::log( 'file.read', 'ok', $request->get_param( 'path' ), SiteBridge_Auth::current_label() );
		return rest_ensure_response(
			array(
				'path'    => $request->get_param( 'path' ),
				'content' => file_get_contents( $path ), // phpcs:ignore
			)
		);
	}

	public function write_file( $request ) {
		$rel  = $request->get_param( 'path' );
		$path = $this->safe_path( $rel );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, $this->allowed_ext, true ) ) {
			return new WP_Error( 'ext_blocked', 'That file type cannot be edited via SiteBridge.', array( 'status' => 400 ) );
		}
		$body    = $request->get_json_params();
		$content = isset( $body['content'] ) ? (string) $body['content'] : null;
		if ( null === $content ) {
			return new WP_Error( 'invalid', 'Provide "content".', array( 'status' => 400 ) );
		}

		// Always back up an existing file first.
		if ( file_exists( $path ) ) {
			$backup = $path . '.sitebridge-bak-' . gmdate( 'YmdHis' );
			@copy( $path, $backup ); // phpcs:ignore
		}

		$written = file_put_contents( $path, $content ); // phpcs:ignore
		if ( false === $written ) {
			SiteBridge_Logger::log( 'file.write', 'error', $rel, SiteBridge_Auth::current_label() );
			return new WP_Error( 'write_failed', 'Could not write the file (permissions?).', array( 'status' => 500 ) );
		}
		SiteBridge_Logger::log( 'file.write', 'ok', $rel . ' (' . $written . ' bytes)', SiteBridge_Auth::current_label() );
		return rest_ensure_response(
			array(
				'path'          => $rel,
				'bytes_written' => $written,
				'backup'        => isset( $backup ) ? basename( $backup ) : null,
			)
		);
	}
}
