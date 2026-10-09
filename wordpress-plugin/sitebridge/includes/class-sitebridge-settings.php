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
        <style>
        .sitebridge-admin{max-width:1100px;color:#19223b}.sitebridge-admin .sb-admin-hero{background:linear-gradient(120deg,#f3efff,#fff);border:1px solid #e5e6ef;border-radius:16px;padding:28px 30px;margin:20px 0 24px}.sitebridge-admin .sb-admin-brand{font-size:13px;font-weight:700;color:#6554dc;margin-bottom:10px}.sitebridge-admin .sb-admin-hero h1{padding:0;margin:0 0 10px;font-size:29px;font-weight:650;letter-spacing:-.8px}.sitebridge-admin .sb-admin-hero p{color:#69718a;font-size:14px;margin:0 0 15px}.sitebridge-admin .sb-admin-status{display:inline-block;border-radius:99px;background:#fff;border:1px solid #e5e6ef;padding:5px 12px;font-size:12px}.sitebridge-admin .sb-admin-steps{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:28px}.sitebridge-admin .sb-admin-step{background:white;border:1px solid #e5e6ef;border-radius:12px;padding:20px}.sitebridge-admin .sb-admin-step span{display:block;color:#6554dc;font-size:11px;font-weight:700;margin-bottom:7px}.sitebridge-admin .sb-admin-step strong{font-size:14px}.sitebridge-admin .sb-admin-step p{margin:7px 0 0;color:#69718a;font-size:13px}.sitebridge-admin h2{font-size:19px;margin-top:28px}.sitebridge-admin hr{border-top-color:#e5e6ef;margin-top:30px}.sitebridge-admin .widefat{border:1px solid #e5e6ef;border-radius:10px;overflow:hidden}.sitebridge-admin .widefat th,.sitebridge-admin .widefat td{padding:12px}.sitebridge-admin .button-primary{background:#6554dc;border-color:#6554dc;border-radius:6px}.sitebridge-admin .sb-admin-manual{background:white;border:1px solid #e5e6ef;border-radius:10px;padding:14px 18px;margin:20px 0}.sitebridge-admin summary{cursor:pointer;font-weight:600}.sitebridge-admin code{overflow-wrap:anywhere}@media(max-width:760px){.sitebridge-admin .sb-admin-steps{grid-template-columns:1fr}.sitebridge-admin .sb-admin-hero{padding:22px}}
        </style>
        <div class="wrap sitebridge-admin">
            <div class="sb-admin-hero"><div class="sb-admin-brand">SiteBridge · WordPress + AI</div><h1>Your website. Your AI.</h1><p>Connect your AI assistant and work on your website through conversation.</p><span class="sb-admin-status"><?php echo ! empty( $settings['enabled'] ) ? '● Ready to connect' : '○ Connections disabled'; ?> · <?php echo esc_html( count( $keys ) ); ?> active connections &amp; keys</span></div>
            <div class="sb-admin-steps"><div class="sb-admin-step"><span>01 · ADD YOUR CONNECTOR</span><strong>Open your AI app</strong><p>Add your SiteBridge hub URL as a remote MCP connector and choose OAuth sign-in.</p></div><div class="sb-admin-step"><span>02 · CONNECT THIS WEBSITE</span><strong>Ask your AI to connect</strong><p>Give your AI this website’s address. Open the connection link it provides.</p></div><div class="sb-admin-step"><span>03 · APPROVE &amp; START</span><strong>One approval. You’re ready.</strong><p>Approve in WordPress, then return to your AI app. Manage or revoke access below.</p></div></div>

			<?php if ( $new_key ) : ?>
				<div class="notice notice-success"><p>
					<strong>New API key (copy it now — it is shown only once):</strong><br>
					<code style="font-size:14px;user-select:all;"><?php echo esc_html( $new_key ); ?></code>
				</p></div>
			<?php endif; ?>

			<h2>Access settings</h2>
            <p>Set access here once. New connections automatically use the enabled permissions when you approve. Existing keys keep their approved scopes; reconnect to grant additional access.</p>
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
            <details class="sb-admin-manual"><summary>Advanced: create a manual API key</summary><p>Browser approval handles keys automatically. Use manual keys only for a custom integration.</p><p>API endpoint: <code><?php echo $rest_base; ?></code></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:16px;">
				<input type="hidden" name="action" value="sitebridge_genkey">
				<?php wp_nonce_field( 'sitebridge_genkey' ); ?>
				<input type="text" name="label" placeholder="Key label (e.g. My MCP server)" class="regular-text" required>
				<?php submit_button( 'Generate new key', 'secondary', 'submit', false ); ?>
			</form>
            </details>
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
