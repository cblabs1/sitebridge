<?php
/**
 * Admin settings screen: capability toggles, API keys, activity log.
 *
 * @package SiteBridge
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SiteBridge_Settings {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_post_sitebridge_save', array( $this, 'handle_save' ) );
		add_action( 'admin_post_sitebridge_genkey', array( $this, 'handle_genkey' ) );
		add_action( 'admin_post_sitebridge_revoke', array( $this, 'handle_revoke' ) );
	}

	public function menu() {
		add_options_page(
			'SiteBridge',
			'SiteBridge',
			'manage_options',
			'sitebridge',
			array( $this, 'render' )
		);
	}

	protected function cap_labels() {
		return array(
			'site_read'     => 'Site info &amp; health (read-only)',
			'content_write' => 'Content management — create/update posts &amp; pages',
			'woo_write'     => 'WooCommerce — read/update products',
			'options_read'  => 'Settings &amp; safe DB reads (options + SELECT queries)',
			'db_read'       => 'Run read-only SQL (SELECT/SHOW)',
			'db_write'      => 'DB write (UPDATE/INSERT/DELETE) — DANGEROUS',
			'code_edit'     => 'Code/file editing inside wp-content — DANGEROUS',
		);
	}

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings  = sitebridge_get_settings();
		$keys      = get_option( SITEBRIDGE_OPT_KEYS, array() );
		$new_key   = get_transient( 'sitebridge_new_key' );
		delete_transient( 'sitebridge_new_key' );
		$rest_base = esc_url( rest_url( SITEBRIDGE_NS ) );
		?>
		<div class="wrap">
			<h1>SiteBridge — AI Site Connector</h1>
			<p>Expose this site to your MCP server / AI agent through secure, key-protected endpoints. API base: <code><?php echo $rest_base; ?></code></p>

			<?php if ( $new_key ) : ?>
				<div class="notice notice-success"><p>
					<strong>New API key (copy it now — it is shown only once):</strong><br>
					<code style="font-size:14px;user-select:all;"><?php echo esc_html( $new_key ); ?></code>
				</p></div>
			<?php endif; ?>

			<h2>Capabilities</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="sitebridge_save">
				<?php wp_nonce_field( 'sitebridge_save' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Master switch</th>
						<td><label><input type="checkbox" name="s[enabled]" value="1" <?php checked( ! empty( $settings['enabled'] ) ); ?>> Enable the SiteBridge API</label></td>
					</tr>
					<?php foreach ( $this->cap_labels() as $key => $label ) : ?>
						<tr>
							<th scope="row"><?php echo wp_kses_post( $label ); ?></th>
							<td><label><input type="checkbox" name="s[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $settings[ $key ] ) ); ?>> Enabled</label>
							<?php if ( in_array( $key, array( 'db_write', 'code_edit' ), true ) ) : ?>
								<span style="color:#b32d2e;"> — leave OFF unless you fully trust the connecting agent.</span>
							<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
				<?php submit_button( 'Save capabilities' ); ?>
			</form>

			<hr>
			<h2>Connected AI clients and API keys</h2>
			<p>To connect through your AI app, ask it to connect this website and open its approval link. No manual key copying is needed. Browser-approved connections appear below; revoke their key to stop access.</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:16px;">
				<input type="hidden" name="action" value="sitebridge_genkey">
				<?php wp_nonce_field( 'sitebridge_genkey' ); ?>
				<input type="text" name="label" placeholder="Key label (e.g. My MCP server)" class="regular-text" required>
				<?php submit_button( 'Generate new key', 'secondary', 'submit', false ); ?>
			</form>
			<table class="widefat striped">
				<thead><tr><th>Label</th><th>Created</th><th>Last used</th><th></th></tr></thead>
				<tbody>
				<?php if ( empty( $keys ) ) : ?>
					<tr><td colspan="4">No keys yet.</td></tr>
				<?php else : ?>
					<?php foreach ( $keys as $id => $rec ) : ?>
						<tr>
							<td><?php echo esc_html( $rec['label'] ); ?></td>
							<td><?php echo esc_html( $rec['created'] ); ?></td>
							<td><?php echo esc_html( $rec['last_used'] ? $rec['last_used'] : '—' ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('Revoke this key?');">
									<input type="hidden" name="action" value="sitebridge_revoke">
									<input type="hidden" name="id" value="<?php echo esc_attr( $id ); ?>">
									<?php wp_nonce_field( 'sitebridge_revoke' ); ?>
									<button class="button-link-delete button-link">Revoke</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

			<hr>
			<h2>Recent activity</h2>
			<table class="widefat striped">
				<thead><tr><th>Time (UTC)</th><th>Action</th><th>Status</th><th>Detail</th><th>Key</th></tr></thead>
				<tbody>
				<?php
				$rows = SiteBridge_Logger::recent( 30 );
				if ( empty( $rows ) ) :
					?>
					<tr><td colspan="5">No activity yet.</td></tr>
				<?php else : ?>
					<?php foreach ( $rows as $r ) : ?>
						<tr>
							<td><?php echo esc_html( $r->created_at ); ?></td>
							<td><code><?php echo esc_html( $r->action ); ?></code></td>
							<td><?php echo esc_html( $r->status ); ?></td>
							<td><?php echo esc_html( $r->detail ); ?></td>
							<td><?php echo esc_html( $r->key_label ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	public function handle_save() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'sitebridge_save' ) ) {
			wp_die( 'Not allowed' );
		}
		$in       = isset( $_POST['s'] ) && is_array( $_POST['s'] ) ? wp_unslash( $_POST['s'] ) : array();
		$defaults = sitebridge_default_settings();
		$out      = array();
		foreach ( array_keys( $defaults ) as $k ) {
			$out[ $k ] = ! empty( $in[ $k ] );
		}
		update_option( SITEBRIDGE_OPT_SETTINGS, $out );
		wp_safe_redirect( admin_url( 'options-general.php?page=sitebridge&saved=1' ) );
		exit;
	}

	public function handle_genkey() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'sitebridge_genkey' ) ) {
			wp_die( 'Not allowed' );
		}
		$label = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : 'Key';
		$key   = SiteBridge_Auth::generate_key( $label );
		set_transient( 'sitebridge_new_key', $key['raw'], 120 );
		wp_safe_redirect( admin_url( 'options-general.php?page=sitebridge' ) );
		exit;
	}

	public function handle_revoke() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'sitebridge_revoke' ) ) {
			wp_die( 'Not allowed' );
		}
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		SiteBridge_Auth::revoke_key( $id );
		wp_safe_redirect( admin_url( 'options-general.php?page=sitebridge&revoked=1' ) );
		exit;
	}
}
