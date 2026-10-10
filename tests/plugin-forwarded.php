<?php
/** FastCGI/header-forwarding regressions, extending the native auth boundary fixture. */
define( 'SITEBRIDGE_NATIVE_FIXTURE_ONLY', true );
require __DIR__ . '/plugin-native.php';
class WP_User { public $ID; public $admin; public function __construct( $id, $admin ) { $this->ID=$id; $this->admin=$admin; } }
class WP_Application_Passwords {
    public static function get_user_application_password( $user_id, $uuid ) {
        return $user_id === 7 && $uuid === 'native-uuid' ? array( 'uuid'=>'native-uuid', 'name'=>'SiteBridge Test', 'app_id'=>SITEBRIDGE_APP_ID ) : null;
    }
}
function rest_get_authenticated_app_password() { return $GLOBALS['core_uuid'] ?? null; }
function wp_set_current_user( $id ) { $GLOBALS['user_id']=$id; $GLOBALS['is_admin']=$id===7; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function wp_authenticate_application_password( $unused, $username, $password ) {
    $GLOBALS['core_auth_calls']=($GLOBALS['core_auth_calls'] ?? 0)+1;
    if ( $username !== 'admin' || $password !== str_repeat('A',24) ) { return new WP_Error('incorrect_password'); }
    $user = new WP_User(7,true);
    $item = array('uuid'=>'native-uuid','name'=>'SiteBridge Test','app_id'=>$GLOBALS['test_app_id'] ?? SITEBRIDGE_APP_ID);
    $error = new WP_Error();
    SiteBridge_Auth::check_application($error,$user,$item,$password);
    if ($error->has_errors()) { return $error; }
    SiteBridge_Auth::capture_application($user,$item);
    return $user;
}
class ForwardedRequest extends Request {
    private $headers;
    public function __construct($route,$headers=array()) { parent::__construct($route); $this->headers=$headers; }
    public function get_header($name=null) { return $this->headers[$name] ?? ''; }
}
function clear_auth_fixture() {
    SiteBridge_Auth::capture_application((object)array('ID'=>7),array('app_id'=>'unrelated'));
    $GLOBALS['core_uuid']=null; $GLOBALS['user_id']=0; $GLOBALS['is_admin']=false;
    $GLOBALS['test_app_id']=SITEBRIDGE_APP_ID;
}
$GLOBALS['settings']['content_write']=false;
$header='Basic '.base64_encode('admin:'.str_repeat('A',24));
clear_auth_fixture();
$request=new ForwardedRequest('/sitebridge/v1/connect/verify',array('x_sitebridge_authorization'=>$header));
$result=SiteBridge_Auth::authenticate_forwarded_application(null,null,$request);
check($result===null && get_current_user_id()===7 && $GLOBALS['core_auth_calls']===1,'stripped standard header authenticates through WordPress using the fallback header');
check(SiteBridge_Auth::require_cap('site_read')($request)===true,'forwarded credential can complete native verification');
check(SiteBridge_Auth::require_cap('content_write')($request) instanceof WP_Error,'forwarded credential retains disabled capability checks');
clear_auth_fixture();
$request=new ForwardedRequest('/sitebridge/v1/connect/verify',array('authorization'=>$header));
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request)===null && get_current_user_id()===7,'visible Basic header works when CGI auth variables were not populated');
clear_auth_fixture();
$before=$GLOBALS['core_auth_calls'];
$request=new ForwardedRequest('/wp/v2/users',array('x_sitebridge_authorization'=>$header));
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request)===null && $GLOBALS['core_auth_calls']===$before && get_current_user_id()===0,'fallback header never authenticates other WordPress namespaces');
$request=new ForwardedRequest('/sitebridge/v1/site',array('x_sitebridge_authorization'=>$header));
$existing_error=new WP_Error('blocked_by_security_plugin');
check(SiteBridge_Auth::authenticate_forwarded_application($existing_error,null,$request)===$existing_error && $GLOBALS['core_auth_calls']===$before,'fallback preserves earlier security errors');
$request=new ForwardedRequest('/sitebridge/v1/site',array('x_sitebridge_authorization'=>'Basic '.base64_encode('admin:invalid')));
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request) instanceof WP_Error && get_current_user_id()===0,'invalid forwarded Application Password is rejected');
$request=new ForwardedRequest('/sitebridge/v1/site',array('x_sitebridge_authorization'=>'Basic bm9jb2xvbg=='));
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request) instanceof WP_Error,'malformed forwarded credential is rejected');
$GLOBALS['test_app_id']='another-application';
$request=new ForwardedRequest('/sitebridge/v1/site',array('x_sitebridge_authorization'=>$header));
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request) instanceof WP_Error && get_current_user_id()===0,'unrelated Application Password cannot use forwarded SiteBridge authentication');
clear_auth_fixture();
$GLOBALS['settings']['enabled']=false;
check(SiteBridge_Auth::authenticate_forwarded_application(null,null,$request) instanceof WP_Error && get_current_user_id()===0,'disabled SiteBridge rejects the forwarded password through core hooks');
$GLOBALS['settings']['enabled']=true;
clear_auth_fixture();
$GLOBALS['core_uuid']='native-uuid'; $GLOBALS['user_id']=7; $GLOBALS['is_admin']=true;
check(SiteBridge_Auth::current_application()['uuid']==='native-uuid','core-authenticated password is recognized even if the observation hook was missed');
check(SiteBridge_Auth::restrict_application_routes(null,null,new Request('/wp/v2/posts')) instanceof WP_Error,'core UUID recovery also retains namespace restrictions');
