<?php
/** Administrator-approved, one-time connections to a SiteBridge hub. */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class SiteBridge_Connect {
    public function __construct() {
        add_action( 'admin_post_sitebridge_connect', array( $this, 'screen' ) );
        add_action( 'admin_post_nopriv_sitebridge_connect', array( $this, 'login' ) );
        add_action( 'admin_post_sitebridge_connect_decide', array( $this, 'decide' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'login_style' ) );
        add_action( 'login_form', array( $this, 'login_context' ) );
        add_filter( 'login_headertext', array( $this, 'login_title' ) );
        add_filter( 'login_headerurl', array( $this, 'login_url' ) );
        add_action( 'rest_api_init', function () {
            register_rest_route( SITEBRIDGE_NS, '/connect/info', array( 'methods' => 'GET', 'callback' => array( $this, 'native_info' ), 'permission_callback' => '__return_true' ) );
            register_rest_route( SITEBRIDGE_NS, '/connect/verify', array( 'methods' => 'GET', 'callback' => array( $this, 'native_verify' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ) ) );
            register_rest_route( SITEBRIDGE_NS, '/connect/revoke', array( 'methods' => 'POST', 'callback' => array( $this, 'native_revoke' ), 'permission_callback' => SiteBridge_Auth::require_cap( 'site_read' ) ) );
            register_rest_route( SITEBRIDGE_NS, '/connect/exchange', array(
                'methods' => 'POST', 'callback' => array( $this, 'exchange' ),
                // The expiring, one-time code is the credential, not a WP cookie.
                'permission_callback' => '__return_true',
            ) );
        } );
    }
    public function native_info() {
        $settings = sitebridge_get_settings();
        $response = new WP_REST_Response( array( 'version' => SITEBRIDGE_VERSION, 'app_id' => SITEBRIDGE_APP_ID, 'available' => wp_is_application_passwords_available() && ! empty( $settings['enabled'] ) && ! empty( $settings['site_read'] ), 'authorization_url' => admin_url( 'authorize-application.php' ), 'site_url' => rtrim( home_url(), '/' ) ) );
        $response->header( 'Cache-Control', 'no-store' );
        return $response;
    }
    public function native_verify() {
        $application = SiteBridge_Auth::current_application();
        if ( ! $application ) {
            SiteBridge_Logger::log( 'connect', 'denied', sprintf( 'Verify refused: user %d, manage_options %s, app password uuid %s', get_current_user_id(), current_user_can( 'manage_options' ) ? 'yes' : 'no', function_exists( 'rest_get_authenticated_app_password' ) && rest_get_authenticated_app_password() ? 'present' : 'missing' ) );
            return new WP_Error( 'sitebridge_native_required', 'Authorize a SiteBridge application password with an administrator account.', array( 'status' => 403 ) );
        }
        $response = new WP_REST_Response( array( 'site_url' => rtrim( home_url(), '/' ), 'app_id' => $application['app_id'], 'uuid' => $application['uuid'], 'capabilities' => $this->enabled_caps( sitebridge_get_settings() ) ) );
        $response->header( 'Cache-Control', 'no-store' );
        return $response;
    }
    public function native_revoke() {
        $application = SiteBridge_Auth::current_application();
        if ( ! $application ) { return new WP_Error( 'sitebridge_native_required', 'No SiteBridge application password was authenticated.', array( 'status' => 403 ) ); }
        $deleted = WP_Application_Passwords::delete_application_password( get_current_user_id(), $application['uuid'] );
        return is_wp_error( $deleted ) ? $deleted : new WP_REST_Response( array( 'revoked' => true ) );
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
        wp_safe_redirect( add_query_arg( 'sitebridge_login', '1', wp_login_url( $return ) ) ); exit;
    }
    private function is_login() {
        return isset( $_REQUEST['sitebridge_login'] ) && $_REQUEST['sitebridge_login'] === '1';
    }
    public function login_style() {
        if ( ! $this->is_login() ) { return; }
        echo '<style>body.login{background:radial-gradient(ellipse at 50% 0,#35245566,transparent 60%),#070b16;color:#f1f3ff;font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.login #login{padding-top:7vh;width:min(360px,calc(100% - 40px))}.login h1 a{background:none;text-indent:0;width:auto;height:auto;font-size:25px;letter-spacing:-1px;font-weight:750;color:#f1f3ff}.login form{background:#111728;border:1px solid #ffffff20;border-radius:18px;padding:28px;box-shadow:0 18px 65px #0005;color:#f1f3ff}.login .message,.login #login_error{border-radius:10px}.login .button-primary{background:#a998ff;border-color:#a998ff;color:#101027;border-radius:7px;min-height:38px}.login .button-primary:hover{background:#c0b2ff;border-color:#c0b2ff}.login input[type=text],.login input[type=password]{border-radius:8px;border-color:#ffffff30;background:#080d1a;color:#f1f3ff}.login #nav a,.login #backtoblog a{color:#9ca6c5}</style>';
        add_filter( 'login_message', function ( $message ) { return '<p class="message">Sign in to WordPress to finish connecting your website to SiteBridge.</p>' . $message; } );
    }
    public function login_context() { if ( $this->is_login() ) { echo '<input type="hidden" name="sitebridge_login" value="1">'; } }
    public function login_title( $title ) { return $this->is_login() ? 'SiteBridge' : $title; }
    public function login_url( $url ) { return $this->is_login() ? home_url() : $url; }
    private function page( $title, $body, $step = 2 ) {
        $this->headers();
        $css = file_get_contents( dirname( __DIR__ ) . '/assets/connection-ui.css' );
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . esc_html( $title ) . ' · SiteBridge</title><style>' . $css . '</style></head><body class="sb-journey"><main class="sb-shell"><div class="sb-brand"><span class="sb-mark" aria-hidden="true">sb</span>SiteBridge</div><ol class="sb-steps" aria-label="Connection progress">';
        foreach ( array( 1 => 'Connect', 2 => 'Approve', 3 => 'Ready' ) as $number => $label ) {
            echo '<li class="' . ( $number === $step ? 'is-current' : ( $number < $step ? 'is-complete' : '' ) ) . '"' . ( $number === $step ? ' aria-current="step"' : '' ) . '><span class="sb-step-number">' . $number . '</span>' . $label . '</li>';
        }
        echo '</ol><section class="sb-card" aria-labelledby="sb-title">' . $body . '</section><footer class="sb-footer">Your website. Your AI. Connected with SiteBridge.</footer></main></body></html>';
    }
    private function error( $message, $status = 400 ) {
        status_header( $status );
        $this->page( 'Connection needs attention', '<div class="sb-outcome"><div class="sb-outcome-icon is-error" aria-hidden="true">!</div><p class="sb-eyebrow">Let’s try that again</p><h1 id="sb-title">Connection needs attention</h1><p class="sb-lead">' . esc_html( $message ) . '</p><p class="sb-note">Return to your AI app and ask for a fresh connection link.</p></div>' );
        exit;
    }
    /** Snapshot the enabled settings shown at approval, never scopes supplied by a browser. */
    private function enabled_caps( $settings ) {
        return array_values( array_filter( array_keys( $this->labels() ), function ( $cap ) use ( $settings ) { return ! empty( $settings[ $cap ] ); } ) );
    }
    private function details( $input ) {
        $url = $input['hub'] . '/?' . http_build_query( array( 'route' => 'request', 'request' => $input['request'], 'secret' => $input['secret'] ) );
        $res = wp_safe_remote_get( $url, array( 'timeout' => 20, 'redirection' => 0, 'limit_response_size' => 32768 ) );
        if ( is_wp_error( $res ) || wp_remote_retrieve_response_code( $res ) !== 200 ) { $this->error( 'This link expired or the connection service could not be reached. Ask your AI app for a new link.' ); }
        $data = json_decode( wp_remote_retrieve_body( $res ), true );
        if ( ! is_array( $data ) || ( $data['request'] ?? '' ) !== $input['request'] || ( $data['hub_url'] ?? '' ) !== $input['hub'] || rtrim( $data['site_url'] ?? '', '/' ) !== rtrim( home_url(), '/' ) || ( $data['expires'] ?? 0 ) < time() ) {
            $this->error( 'This link belongs to a different WordPress website. Check the website address in your AI app.' );
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
        $caps = $this->enabled_caps( $settings );
        if ( ! in_array( 'site_read', $caps, true ) ) { $this->error( 'Enable Site info in Settings → SiteBridge before connecting.' ); }
        $local = bin2hex( random_bytes( 24 ) );
        $input['approved_caps'] = $caps;
        set_transient( 'sb_connect_' . get_current_user_id() . '_' . $local, $input, 600 );
        ob_start();
        ?>
        <p class="sb-eyebrow">One last step</p>
        <h1 id="sb-title">Connect your website</h1>
        <p class="sb-lead">Allow <span class="sb-client"><?php echo esc_html( $data['client_name'] ); ?></span> to work with your WordPress website through SiteBridge.</p>
        <div class="sb-site"><span class="sb-site-icon" aria-hidden="true">W</span><div><strong><?php echo esc_html( get_bloginfo( 'name' ) ); ?></strong><span class="sb-url"><?php echo esc_html( home_url() ); ?></span></div></div>
        <div class="sb-summary"><span class="sb-label">Connection service</span><span class="sb-url"><?php echo esc_html( $input['hub'] ); ?></span></div>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <input type="hidden" name="action" value="sitebridge_connect_decide">
        <input type="hidden" name="local" value="<?php echo esc_attr( $local ); ?>">
        <?php wp_nonce_field( 'sitebridge_connect_' . $local ); ?>
        <button class="sb-button" name="decision" value="approve">Approve connection <span aria-hidden="true">→</span></button>
        <button class="sb-secondary" name="decision" value="deny">Cancel</button>
        </form>
        <p class="sb-note">Manage access and revoke this connection anytime in the SiteBridge plugin settings.</p>
        <?php
        $this->page( 'Approve connection', ob_get_clean() );
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
            // Only grant the server-side snapshot shown on the approval screen, intersected
            // with current settings. Settings changes cannot silently broaden this approval.
            $approved = isset( $input['approved_caps'] ) && is_array( $input['approved_caps'] ) ? $input['approved_caps'] : array();
            $caps = array_values( array_intersect( $approved, $this->enabled_caps( $settings ) ) );
            if ( ! in_array( 'site_read', $caps, true ) ) { wp_die( 'Read access is disabled or this approval is out of date. Request a new connection link.' ); }
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
            $this->error( 'We couldn’t finish connecting. The new key was revoked. Ask your AI app for a fresh link.', 502 );
        }
        SiteBridge_Logger::log( 'connect', $data['status'], 'Hub: ' . $input['hub'] );
        $connected = $data['status'] === 'connected';
        $return_url = null;
        // Keep the user's explicit final click; do not redirect to a URL supplied by another server.
        if ( isset( $data['return_url'] ) ) {
            $p = wp_parse_url( $data['return_url'] );
            $valid = $p && ! isset( $p['user'] ) && ! isset( $p['pass'] ) && ( ( $p['scheme'] ?? '' ) === 'https' || ( ( $p['scheme'] ?? '' ) === 'http' && in_array( $p['host'] ?? '', array( 'localhost', '127.0.0.1', '[::1]' ), true ) ) );
            if ( $valid ) { $return_url = $data['return_url']; }
        }
        $title = $connected ? 'You’re connected' : 'Connection canceled';
        $body = '<div class="sb-outcome"><div class="sb-outcome-icon' . ( $connected ? '' : ' is-neutral' ) . '" aria-hidden="true">' . ( $connected ? '✓' : '−' ) . '</div><p class="sb-eyebrow">' . ( $connected ? 'Ready when you are' : 'No access granted' ) . '</p><h1 id="sb-title">' . $title . '</h1><p class="sb-lead">' . ( $connected ? 'Your website is connected to SiteBridge. Finish below, then return to your AI app to start working.' : 'Your website has not been connected. You can start again from your AI app whenever you’re ready.' ) . '</p>';
        if ( $connected ) { $body .= '<div class="sb-site"><span class="sb-site-icon" aria-hidden="true">W</span><div><strong>' . esc_html( get_bloginfo( 'name' ) ) . '</strong><span class="sb-url">' . esc_html( home_url() ) . '</span></div><span class="sb-pill">Connected</span></div>'; }
        if ( $return_url ) { $body .= '<a class="sb-button" rel="noreferrer" href="' . esc_url( $return_url ) . '">' . ( $connected ? 'Finish connecting to your AI app' : 'Return to your AI app' ) . ' <span aria-hidden="true">→</span></a>'; }
        else { $body .= '<p class="sb-summary">Return to the conversation where you requested this connection and ask your AI to check the connection.</p>'; }
        $body .= '<p class="sb-note">Manage your connection anytime in Settings → SiteBridge.</p></div>';
        $this->page( $title, $body, 3 );
        exit;
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
