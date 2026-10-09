<?php
/** Administrator-approved, one-time connections to a SiteBridge hub. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class SiteBridge_Connect {
    public function __construct() {
        add_action( 'admin_post_sitebridge_connect', array( $this, 'screen' ) );
        add_action( 'admin_post_nopriv_sitebridge_connect', array( $this, 'login' ) );
        add_action( 'admin_post_sitebridge_connect_decide', array( $this, 'decide' ) );
        add_action( 'rest_api_init', function () {
            register_rest_route( SITEBRIDGE_NS, '/connect/exchange', array(
                'methods' => 'POST', 'callback' => array( $this, 'exchange' ),
                // The expiring, one-time code is the credential, not a WP cookie.
                'permission_callback' => '__return_true',
            ) );
        } );
    }
    private function input() {
        $hub = isset( $_GET['hub'] ) ? esc_url_raw( wp_unslash( $_GET['hub'] ) ) : '';
        $id = isset( $_GET['request'] ) ? sanitize_text_field( wp_unslash( $_GET['request'] ) ) : '';
        $secret = isset( $_GET['secret'] ) ? sanitize_text_field( wp_unslash( $_GET['secret'] ) ) : '';
        $p = wp_parse_url( $hub );
        if ( ! $p || ( $p['scheme'] ?? '' ) !== 'https' || empty( $p['host'] ) || isset( $p['user'] ) || isset( $p['pass'] ) || isset( $p['query'] ) || isset( $p['fragment'] ) || ! empty( $p['path'] ) || ( isset( $p['port'] ) && $p['port'] !== 443 ) || ! preg_match( '/^[a-f0-9]{64}$/', $id ) || ! preg_match( '/^[a-f0-9]{64}$/', $secret ) ) {
            wp_die( 'Invalid connection link.', 'SiteBridge', array( 'response' => 400 ) );
        }
        return array( 'hub' => rtrim( $hub, '/' ), 'request' => $id, 'secret' => $secret );
    }
    public function login() {
        $input = $this->input();
        $return = add_query_arg( array_merge( array( 'action' => 'sitebridge_connect' ), $input ), admin_url( 'admin-post.php' ) );
        wp_safe_redirect( wp_login_url( $return ) ); exit;
    }
    private function details( $input ) {
        $url = $input['hub'] . '/?' . http_build_query( array( 'route' => 'request', 'request' => $input['request'], 'secret' => $input['secret'] ) );
        $res = wp_safe_remote_get( $url, array( 'timeout' => 20, 'redirection' => 0, 'limit_response_size' => 32768 ) );
        if ( is_wp_error( $res ) || wp_remote_retrieve_response_code( $res ) !== 200 ) { wp_die( 'The connection link expired or the hub could not be reached. Ask your agent for a new link.' ); }
        $data = json_decode( wp_remote_retrieve_body( $res ), true );
        if ( ! is_array( $data ) || ( $data['request'] ?? '' ) !== $input['request'] || ( $data['hub_url'] ?? '' ) !== $input['hub'] || rtrim( $data['site_url'] ?? '', '/' ) !== rtrim( home_url(), '/' ) || ( $data['expires'] ?? 0 ) < time() ) {
            wp_die( 'This connection request does not match this WordPress website.' );
        }
        return $data;
    }
    private function labels() {
        return array(
            'site_read' => 'Read site information, posts, pages, and products',
            'content_write' => 'Create and edit posts and pages',
            'woo_write' => 'Edit WooCommerce products',
            'options_read' => 'Read allowed WordPress settings',
            'db_read' => 'Run read-only database queries',
            'db_write' => 'Modify the database (advanced)',
            'code_edit' => 'Read and edit files in wp-content (advanced)',
        );
    }
    private function headers() {
        nocache_headers();
        header( 'Referrer-Policy: no-referrer' );
        header( 'X-Frame-Options: DENY' );
        header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" );
        header( 'Content-Type: text/html; charset=UTF-8' );
    }
    public function screen() {
        if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Only a WordPress administrator can approve this connection.', '', array( 'response' => 403 ) ); }
        $input = $this->input();
        $data = $this->details( $input );
        $settings = sitebridge_get_settings();
        if ( empty( $settings['enabled'] ) ) { wp_die( 'Enable SiteBridge in Settings before connecting.' ); }
        $local = bin2hex( random_bytes( 24 ) );
        set_transient( 'sb_connect_' . get_current_user_id() . '_' . $local, $input, 600 );
        $this->headers();
        ?>
        <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Approve SiteBridge connection</title>
        <style>body{font:17px system-ui;max-width:680px;margin:6vh auto;padding:24px;color:#172033}label{display:block;margin:16px 0}button{padding:12px 20px;margin:10px 10px 0 0;border:1px solid #bbc6d8;border-radius:6px}button[value=approve]{background:#2255cc;color:white}small{display:block;color:#536174}code{overflow-wrap:anywhere}</style>
        <h1>Connect your WordPress website</h1>
        <p><strong><?php echo esc_html( $data['client_name'] ); ?></strong> requests access to <strong><?php echo esc_html( get_bloginfo( 'name' ) ); ?></strong>.</p>
        <p>Connection service: <code><?php echo esc_html( $input['hub'] ); ?></code></p>
        <p>Only approve a service you trust. Its operator and this AI client will be able to use the permissions you select. The client name is supplied by the connecting app.</p>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <input type="hidden" name="action" value="sitebridge_connect_decide">
        <input type="hidden" name="local" value="<?php echo esc_attr( $local ); ?>">
        <?php wp_nonce_field( 'sitebridge_connect_' . $local ); ?>
        <h2>Permissions</h2>
        <?php foreach ( $this->labels() as $cap => $label ) : ?>
            <label><input type="checkbox" name="caps[]" value="<?php echo esc_attr( $cap ); ?>" <?php checked( $cap === 'site_read' && ! empty( $settings[ $cap ] ) ); ?> <?php disabled( empty( $settings[ $cap ] ) ); ?>> <?php echo esc_html( $label ); ?>
            <?php if ( empty( $settings[ $cap ] ) ) : ?><small>Disabled in Settings → SiteBridge. Enable it there first if needed.</small><?php endif; ?></label>
        <?php endforeach; ?>
        <p>You can revoke access anytime in Settings → SiteBridge → API keys. New permissions require a new approval.</p>
        <button name="decision" value="approve">Approve connection</button><button name="decision" value="deny">Deny</button>
        </form></html>
        <?php
        exit;
    }
    public function decide() {
        if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Not allowed.', '', array( 'response' => 403 ) ); }
        $local = isset( $_POST['local'] ) ? sanitize_text_field( wp_unslash( $_POST['local'] ) ) : '';
        if ( ! preg_match( '/^[a-f0-9]{48}$/', $local ) ) { wp_die( 'Invalid approval form.' ); }
        check_admin_referer( 'sitebridge_connect_' . $local );
        $slot = 'sb_connect_' . get_current_user_id() . '_' . $local;
        $input = get_transient( $slot );
        if ( ! $input ) { wp_die( 'Approval expired or was already submitted.' ); }
        $details = $this->details( $input );
        // A unique option makes duplicate browser submissions fail closed.
        $lock = 'sb_connect_lock_' . $local;
        if ( ! add_option( $lock, time(), '', false ) ) { wp_die( 'This approval was already submitted.' ); }
        wp_schedule_single_event( time() + 600, 'sitebridge_cleanup_lock', array( $lock ) );
        delete_transient( $slot );
        $decision = isset( $_POST['decision'] ) && $_POST['decision'] === 'approve' ? 'approve' : 'deny';
        $payload = array( 'request' => $input['request'], 'secret' => $input['secret'], 'decision' => $decision );
        $key = null; $exchange_slot = null;
        if ( $decision === 'approve' ) {
            $settings = sitebridge_get_settings();
            if ( empty( $settings['enabled'] ) ) { wp_die( 'SiteBridge is disabled.' ); }
            $selected = isset( $_POST['caps'] ) && is_array( $_POST['caps'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['caps'] ) ) : array();
            $caps = array_values( array_filter( array_intersect( $selected, array_keys( $this->labels() ) ), function ( $cap ) use ( $settings ) { return ! empty( $settings[ $cap ] ); } ) );
            // An empty caps array means unrestricted for legacy keys; never generate one here.
            if ( ! in_array( 'site_read', $caps, true ) ) { wp_die( 'Select read access to connect. Request a new approval link and try again.' ); }
            $key = SiteBridge_Auth::generate_key( substr( $details['client_name'], 0, 60 ) . ' | ' . $input['hub'] . ' | ' . substr( $input['request'], 0, 8 ), $caps );
            $code = bin2hex( random_bytes( 32 ) );
            $exchange_slot = 'sb_exchange_' . hash( 'sha256', $code );
            set_transient( $exchange_slot, array( 'request' => $input['request'], 'key' => $key['raw'], 'site_url' => rtrim( home_url(), '/' ), 'capabilities' => $caps ), 120 );
            $payload['code'] = $code;
        }
        $res = wp_safe_remote_post( $input['hub'] . '/?route=callback', array( 'timeout' => 30, 'redirection' => 0, 'headers' => array( 'Content-Type' => 'application/json' ), 'body' => wp_json_encode( $payload ), 'limit_response_size' => 32768 ) );
        $data = is_wp_error( $res ) ? null : json_decode( wp_remote_retrieve_body( $res ), true );
        if ( ! is_array( $data ) || wp_remote_retrieve_response_code( $res ) !== 200 || ! in_array( $data['status'] ?? '', array( 'connected', 'denied' ), true ) ) {
            if ( $key ) { SiteBridge_Auth::revoke_key( $key['id'] ); }
            if ( $exchange_slot ) { delete_transient( $exchange_slot ); }
            wp_die( 'The hub could not complete this connection. No new access remains active. Ask your agent for a fresh approval link.' );
        }
        SiteBridge_Logger::log( 'connect', $data['status'], 'Hub: ' . $input['hub'] );
        $this->headers();
        echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>SiteBridge connection</title><body><h1>' . ( $data['status'] === 'connected' ? 'Website connected' : 'Connection denied' ) . '</h1><p>Return to your AI app to continue.</p>';
        // Deliberately a clicked link: never blindly redirect to a URL returned by another server.
        if ( isset( $data['return_url'] ) ) {
            $p = wp_parse_url( $data['return_url'] );
            $valid = $p && ! isset( $p['user'] ) && ! isset( $p['pass'] ) && ( ( $p['scheme'] ?? '' ) === 'https' || ( ( $p['scheme'] ?? '' ) === 'http' && in_array( $p['host'] ?? '', array( 'localhost', '127.0.0.1', '[::1]' ), true ) ) );
            if ( $valid ) { echo '<p><a rel="noreferrer" href="' . esc_url( $data['return_url'] ) . '">Finish connecting to your AI app</a></p>'; }
        }
        echo '</body></html>'; exit;
    }
    public function exchange( $request ) {
        $code = $request->get_param( 'code' );
        $id = $request->get_param( 'request' );
        if ( ! is_string( $code ) || ! preg_match( '/^[a-f0-9]{64}$/', $code ) || ! is_string( $id ) ) { return new WP_Error( 'invalid_exchange', 'Invalid exchange code.', array( 'status' => 403 ) ); }
        $slot = 'sb_exchange_' . hash( 'sha256', $code );
        $data = get_transient( $slot );
        if ( ! $data || ! hash_equals( $data['request'], $id ) ) { return new WP_Error( 'invalid_exchange', 'Code expired or already used.', array( 'status' => 403 ) ); }
        $lock = 'sb_exchange_lock_' . hash( 'sha256', $code );
        if ( ! add_option( $lock, time(), '', false ) ) { return new WP_Error( 'invalid_exchange', 'Code already used.', array( 'status' => 403 ) ); }
        wp_schedule_single_event( time() + 600, 'sitebridge_cleanup_lock', array( $lock ) );
        delete_transient( $slot );
        unset( $data['request'] );
        $response = new WP_REST_Response( $data );
        $response->header( 'Cache-Control', 'no-store' );
        return $response;
    }
}
add_action( 'sitebridge_cleanup_lock', function ( $lock ) {
    if ( strpos( $lock, 'sb_connect_lock_' ) === 0 || strpos( $lock, 'sb_exchange_lock_' ) === 0 ) { delete_option( $lock ); }
} );
