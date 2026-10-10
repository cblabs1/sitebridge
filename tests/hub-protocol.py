"""Exercise actual PHP HTTP routes without contacting any real WordPress site."""
import re, base64, hashlib, http.cookiejar, json, os, pathlib, shutil, socket, subprocess, tempfile, time, urllib.request, urllib.error
ROOT = pathlib.Path(__file__).resolve().parents[1]

def check(condition, name):
    if not condition:
        raise AssertionError(name)
    print('PASS', name)

with tempfile.TemporaryDirectory(prefix='sbh-http-') as work:
    work = pathlib.Path(work)
    web = work/'web'; private = work/'private'; private.mkdir()
    hub = ROOT/'sitebridge-hub' if (ROOT/'sitebridge-hub').is_dir() else ROOT
    web.mkdir()
    for name in ['index.php', 'connections.php', 'connection-ui.css', '.htaccess']:
        shutil.copy2(hub/name, web/name)
    production_connections = (web/'connections.php').read_text()
    (web/'connections.php').write_text(production_connections.replace('function sbh_http(', 'function sbh_real_http(', 1) + r"""
function sbh_http($url, $method='GET', $body=null, $headers=array(), $timeout=20) {
    if (strpos($url, 'https://alice.example.com/') === 0) {
        if (strpos($url, '/connect/info') !== false) { return array('app_id'=>'6c78a910-07e3-4a44-a3fa-299b20b471c5','available'=>true,'site_url'=>'https://alice.example.com','authorization_url'=>'https://alice.example.com/wp-admin/authorize-application.php'); }
        if (strpos($url, '/connect/verify') !== false) {
            if (!in_array('Authorization: Basic '.base64_encode('admin:'.str_repeat('A',24)),$headers,true)) { sbh_fail('Invalid fixture credential.',403); }
            return array('app_id'=>'6c78a910-07e3-4a44-a3fa-299b20b471c5','site_url'=>'https://alice.example.com','uuid'=>'fixture-uuid','capabilities'=>array('site_read'));
        }
        if (strpos($url, '/connect/revoke') !== false) { return array('revoked'=>true); }
        if (strpos($url, '/site') !== false) {
            if (!in_array('Authorization: Basic '.base64_encode('admin:'.str_repeat('A',24)),$headers,true)) { sbh_fail('Wrong proxy authentication.',403); }
            return array('name'=>'Native fixture site');
        }
    }
    return sbh_real_http($url,$method,$body,$headers,$timeout);
}
""")
    config = {'public_url':'https://hub.example.com', 'encryption_key':os.urandom(32).hex(), 'storage_path':str(private/'connections.sqlite'), 'master_token':'test-admin', 'sites':{'manual':{'url':'https://manual.example.com','key':'sbk_test'}}}
    (web/'config.php').write_text('<?php return json_decode('+json.dumps(json.dumps(config))+', true);')
    # Fixture setup runs outside the webroot and only seeds authorization grants.
    fixture = work/'fixture.php'
    fixture.write_text('''<?php
require $argv[1] . '/connections.php';
$config = require $argv[1] . '/config.php';
$_SERVER['DOCUMENT_ROOT'] = $argv[1];
$db = sbh_db($config);
$input = json_decode(file_get_contents('php://stdin'), true);
if ($input['action'] === 'code') {
    sbh_put($db, 'code', sbh_hash($input['code']), $input['data'], time()+120);
} elseif ($input['action'] === 'token') {
    echo json_encode(sbh_access_token($db,$input['owner'],$input['client_id'],'https://hub.example.com/'));
} elseif ($input['action'] === 'connection') {
    sbh_put($db,'connection',$input['id'],array('owner'=>$input['owner'],'url'=>$input['url'],'key'=>sbh_encrypt($config,'sbk_'.str_repeat('a',48))));
}
''')
    def seed(data):
        output = subprocess.check_output(['php', str(fixture),str(web)],input=json.dumps(data).encode())
        return json.loads(output) if output else None
    sock = socket.socket(); sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]; sock.close()
    server = subprocess.Popen(['php','-S',f'127.0.0.1:{port}',str(web/'index.php')], cwd=web, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path='/',data=None,token=None,form=False,method=None,extra_headers=None):
        headers=dict(extra_headers or {})
        if token: headers['Authorization']='Bearer '+token
        if data is not None:
            if form:
                from urllib.parse import urlencode
                data=urlencode(data).encode(); headers['Content-Type']='application/x-www-form-urlencoded'
            else:
                data=json.dumps(data).encode(); headers['Content-Type']='application/json'
        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers=headers,method=method)
        try: response=opener.open(req,timeout=5)
        except urllib.error.HTTPError as e: response=e
        raw=response.read().decode()
        try: body=json.loads(raw)
        except ValueError: body=raw
        return response.status,response.headers,body
    def rpc(name,args,token):
        status,headers,body=request(data={'jsonrpc':'2.0','id':8,'method':'tools/call','params':{'name':name,'arguments':args}},token=token)
        result=body.get('result',{})
        return status,headers,json.loads(result['content'][0]['text']) if result.get('content') else body
    try:
        for _ in range(50):
            try: request(); break
            except urllib.error.URLError: time.sleep(.05)
        status,_,body=request()
        check(status==200 and body['ok'], 'health endpoint')
        req=urllib.request.Request(f'http://127.0.0.1:{port}/',headers={'Accept':'text/html'})
        with opener.open(req,timeout=5) as r:
            landing=r.read().decode()
        check('Your MCP server URL' in landing and 'sb-journey' in landing, 'browser landing uses branded UI while health stays JSON')
        status,headers,_=request(data={'jsonrpc':'2.0','id':1,'method':'tools/list'})
        check(status==401 and 'oauth-protected-resource' in headers['WWW-Authenticate'], 'unauthenticated MCP challenge includes discovery')
        status,_,body=request('/.well-known/oauth-protected-resource')
        check(status==200 and body['resource']=='https://hub.example.com/', 'resource discovery')
        status,_,body=request('/.well-known/oauth-authorization-server')
        check(body['code_challenge_methods_supported']==['S256'] and body['client_id_metadata_document_supported'], 'authorization discovery with PKCE and CIMD')
        client={'client_name':'Test AI','redirect_uris':['https://client.example.com/callback'],'token_endpoint_auth_method':'none'}
        status,_,registered=request('/?route=register',client)
        check(status==201 and 'client_id' in registered,'dynamic client registration')
        client_id=registered['client_id']
        status,_,_=request('/?route=register',{'client_name':'Bad','redirect_uris':['http://evil.example.com']})
        check(status==400, 'unsafe registration rejected')
        from urllib.parse import urlencode
        verifier='x'*64
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        auth={'client_id':client_id,'redirect_uri':client['redirect_uris'][0],'response_type':'code','code_challenge_method':'S256','code_challenge':challenge,'state':'original-state','resource':'https://hub.example.com/'}
        status,auth_headers,body=request('/?route=authorize&'+urlencode(auth))
        auth_html=body
        check(status==200 and 'Continue to WordPress' in body, 'OAuth sign-in form')
        flow=re.search(r'name="flow" value="([a-f0-9]+)"',auth_html).group(1)
        restart=re.search(r'name="restart" value="([a-f0-9]+)"',auth_html).group(1)
        post={'flow':flow,'restart':restart,'site_url':'https://alice.example.com'}
        status,_,body=request('/?route=authorize',post,form=True,extra_headers={'Accept':'text/html'})
        check(status==403 and 'Restart connection' in body and 'browser session' in body,'missing browser cookie gives a safe restart action')
        status,fresh_headers,fresh_html=request('/?route=authorize&restart='+restart)
        check(status==200 and 'Continue to WordPress' in fresh_html,'restart reopens validated OAuth context')
        fresh_flow=re.search(r'name="flow" value="([a-f0-9]+)"',fresh_html).group(1)
        fresh_restart=re.search(r'name="restart" value="([a-f0-9]+)"',fresh_html).group(1)
        fresh_post={'flow':fresh_flow,'restart':fresh_restart,'site_url':'https://alice.example.com'}
        # Test server is HTTP; send its production Secure cookie explicitly rather than weakening it.
        cookie=fresh_headers['Set-Cookie'].split(';',1)[0]
        status,headers,body=request('/?route=authorize',fresh_post,form=True,extra_headers={'Cookie':cookie})
        check(status==200 and 'http-equiv="refresh"' in body and 'route=connect' in body and 'Location' not in headers,'browser handoff avoids CSP-blocked form redirects and includes a fallback link')
        approval=re.search(r'<a class="sb-button" href="([^"]+)"',body).group(1)
        status,_,body=request('/?route=authorize',fresh_post,form=True,extra_headers={'Cookie':cookie,'Accept':'text/html'})
        check(status==200 and approval in body,'repeated submission resumes the same approval request')
        status,_,_=request('/?route=authorize',fresh_post,form=True)
        check(status==403,'retry still requires the browser cookie')
        status,_,_=request('/?route=authorize',dict(fresh_post,site_url='https://other.example.com'),form=True,extra_headers={'Cookie':cookie})
        check(status==409,'retry cannot substitute a different website')
        status,_,_=request('/?route=authorize&restart='+('0'*64))
        check(status==403,'forged restart context rejected')
        invalid=dict(auth,redirect_uri='https://evil.example.com/callback')
        status,headers,_=request('/?route=authorize&'+urlencode(invalid))
        check(status==400 and 'Location' not in headers, 'redirect substitution rejected without redirecting')
        status,_,_=request('/?route=authorize',{'flow':'missing','site_url':'https://example.com'},form=True)
        check(status==403, 'OAuth form CSRF rejected')
        code=os.urandom(32).hex()
        row={'owner':'alice','client_id':client_id,'redirect_uri':client['redirect_uris'][0],'challenge':challenge,'resource':'https://hub.example.com/'}
        seed({'action':'code','code':code,'data':row})
        grant={'grant_type':'authorization_code','code':code,'client_id':client_id,'redirect_uri':client['redirect_uris'][0],'code_verifier':'wrong'*10}
        status,_,body=request('/?route=token',grant,form=True)
        check(status==400 and body['error']=='invalid_grant','wrong PKCE verifier rejected')
        grant['code_verifier']=verifier
        status,_,body=request('/?route=token',dict(grant,resource='https://evil.example.com'),form=True)
        check(status==400 and body['error']=='invalid_grant','wrong token audience rejected')
        status,_,tokens=request('/?route=token',grant,form=True)
        check(status==200 and tokens['token_type']=='Bearer','authorization code exchanged')
        status,_,body=request('/?route=token',grant,form=True)
        check(status==400 and body['error']=='invalid_grant','authorization code replay rejected')
        seed({'action':'connection','id':'site_alice','owner':'alice','url':'https://alice.example.com'})
        seed({'action':'connection','id':'site_bob','owner':'bob','url':'https://bob.example.com'})
        bob=seed({'action':'token','owner':'bob','client_id':client_id})
        call={'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'list_sites','arguments':{}}}
        status,_,body=request(data=call,token=tokens['access_token'])
        sites=json.loads(body['result']['content'][0]['text'])['sites']
        check([s['site'] for s in sites]==['site_alice'],'MCP Alice sees only Alice sites')
        status,_,body=request(data=call,token=bob['access_token'])
        sites=json.loads(body['result']['content'][0]['text'])['sites']
        check([s['site'] for s in sites]==['site_bob'],'MCP Bob sees only Bob sites')
        status,_,body=request(data=call,token='test-admin')
        sites=json.loads(body['result']['content'][0]['text'])['sites']
        check([s['site'] for s in sites]==['manual'],'legacy master sees only manual sites')
        connect={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'connect_site','arguments':{'site_url':'https://alice.example.com'}}}
        status,_,body=request(data=connect,token=tokens['access_token'])
        pending=json.loads(body['result']['content'][0]['text'])
        check('approval_url' in pending,'agent receives approval URL')
        poll={'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'connection_status','arguments':{'request_id':pending['request_id']}}}
        status,_,body=request(data=poll,token=bob['access_token'])
        check(json.loads(body['result']['content'][0]['text'])['status']=='expired','other principal cannot inspect pending request')
        from urllib.parse import parse_qs,urlparse
        alice=tokens['access_token']
        native_link=urlparse(pending['approval_url'])
        status,start_headers,_=request('/?'+native_link.query)
        native_url=urlparse(start_headers.get('Location',''))
        native_args=parse_qs(native_url.query)
        check(status==303 and native_url.path=='/wp-admin/authorize-application.php' and native_args['app_id']==['6c78a910-07e3-4a44-a3fa-299b20b471c5'],'native approval uses the WordPress authorization screen')
        native_cookie=start_headers['Set-Cookie'].split(';',1)[0]
        callback=urlparse(native_args['success_url'][0])
        callback_args=parse_qs(callback.query)
        callback_args={k:v[0] for k,v in callback_args.items()}
        callback_args.update(site_url='https://alice.example.com',user_login='admin',password='A'*24)
        status,bad_headers,_=request('/?'+urlencode(callback_args))
        check(status==303 and 'password' not in bad_headers['Location'],'unbound callback leaves the credential URL without exposing credentials')
        status,finish_headers,_=request('/?'+urlencode(callback_args),extra_headers={'Cookie':native_cookie})
        check(status==303 and 'route=connected' in finish_headers['Location'] and 'password' not in finish_headers['Location'],'valid native approval verifies credentials then redirects to a clean result URL')
        result_path='/?'+urlparse(finish_headers['Location']).query
        status,_,finished=request(result_path,extra_headers={'Cookie':native_cookie})
        check(status==200 and 'You’re connected' in finished and 'A'*24 not in finished,'connected screen contains no WordPress password')
        status,_,_=request(result_path)
        check(status==403,'connection result is bound to the approving browser')
        status,replay_headers,_=request('/?'+urlencode(callback_args),extra_headers={'Cookie':native_cookie})
        status,_,replayed=request('/?'+urlparse(replay_headers['Location']).query)
        check('You’re connected' not in replayed,'native callback replay cannot reconnect')
        status,_,native_status=rpc('connection_status',{'request_id':pending['request_id']},alice)
        check(native_status['status']=='connected','native approval updates the agent connection status')
        native_site=native_status['site']
        status,_,native_info=rpc('site_info',{'site':native_site},alice)
        check(native_info.get('name')=='Native fixture site','native WordPress requests use HTTP Basic authentication')
        status,_,native_disconnect=rpc('disconnect_site',{'site':native_site},alice)
        check(native_disconnect.get('disconnected') is True and native_disconnect.get('wordpress_revoked') is True,'disconnect revokes the native application password and removes the connection')
        from html import unescape
        oauth_link=urlparse(unescape(approval))
        status,oauth_start,_=request('/?'+oauth_link.query)
        oauth_args=parse_qs(urlparse(oauth_start['Location']).query)
        oauth_callback={k:v[0] for k,v in parse_qs(urlparse(oauth_args['success_url'][0]).query).items()}
        oauth_callback.update(site_url='https://alice.example.com',user_login='admin',password='A'*24)
        oauth_cookie=oauth_start['Set-Cookie'].split(';',1)[0]
        status,oauth_finish,_=request('/?'+urlencode(oauth_callback),extra_headers={'Cookie':oauth_cookie})
        status,_,oauth_result=request('/?'+urlparse(oauth_finish['Location']).query,extra_headers={'Cookie':oauth_cookie})
        oauth_return=unescape(re.search(r'<a class="sb-button" href="([^"]+)"',oauth_result).group(1))
        oauth_return_args=parse_qs(urlparse(oauth_return).query)
        check('http-equiv="refresh"' in oauth_result and oauth_return_args['state']==['original-state'],'native OAuth completion automatically returns to the registered AI client with its original state')
        status,_,native_tokens=request('/?route=token',{'grant_type':'authorization_code','client_id':client_id,'code':oauth_return_args['code'][0],'redirect_uri':client['redirect_uris'][0],'code_verifier':verifier},form=True)
        check(status==200 and 'access_token' in native_tokens,'native approval completes the AI OAuth PKCE exchange')
        check(b'A'*24 not in (private/'connections.sqlite').read_bytes(),'native password is encrypted at rest')
        def native_attempt(extra):
            _,_,p=rpc('connect_site',{'site_url':'https://alice.example.com'},alice)
            _,h,_=request('/?'+urlparse(p['approval_url']).query)
            cb={k:v[0] for k,v in parse_qs(urlparse(parse_qs(urlparse(h['Location']).query)['success_url'][0]).query).items()}
            cb.update(extra)
            cookie=h['Set-Cookie'].split(';',1)[0]
            _,done,_=request('/?'+urlencode(cb),extra_headers={'Cookie':cookie})
            _,_,result=request('/?'+urlparse(done['Location']).query,extra_headers={'Cookie':cookie})
            _,_,state=rpc('connection_status',{'request_id':p['request_id']},alice)
            return result,state
        denied,denied_status=native_attempt({'denied':'1'})
        check('Connection canceled' in denied and denied_status['status']=='denied','native cancellation grants no connection')
        invalid,invalid_status=native_attempt({'site_url':'https://other.example.com','user_login':'admin','password':'A'*24})
        check('You’re connected' not in invalid and invalid_status['status']=='failed','native callback refuses a different WordPress site')
        invalid,invalid_status=native_attempt({'site_url':'https://alice.example.com','user_login':'admin','password':'B'*24})
        check('You’re connected' not in invalid and invalid_status['status']=='failed','unverified native credentials cannot create a connection')
        status,_,second_pending=rpc('connect_site',{'site_url':'https://alice.example.com'},alice)
        pending=second_pending
        query=parse_qs(urlparse(pending['approval_url']).query)
        status,_,body=request('/?route=callback',{'request':pending['request_id'],'secret':'wrong','decision':'deny'})
        check(status==403,'forged callback rejected')
        decision={'request':pending['request_id'],'secret':query['secret'][0],'decision':'deny'}
        status,_,body=request('/?route=callback',decision)
        check(status==200 and body['status']=='denied','denial stored')
        status,_,_=request('/?route=callback',decision)
        check(status==403,'callback replay rejected')
        refresh={'grant_type':'refresh_token','refresh_token':tokens['refresh_token'],'client_id':client_id}
        status,_,new=request('/?route=token',refresh,form=True)
        check(status==200 and new['refresh_token']!=tokens['refresh_token'],'refresh token rotates')
        status,_,body=request('/?route=token',refresh,form=True)
        check(status==400 and body['error']=='invalid_grant','refresh token replay rejected')
        status,_,_=request(data=call,token=new['access_token'])
        check(status==401,'refresh replay revokes entire token family')
        status,_,_=request('/?route=revoke',{'token':bob['refresh_token'],'client_id':client_id},form=True)
        check(status==200,'revocation endpoint')
        status,_,_=request(data=call,token=bob['access_token'])
        check(status==401,'revoked client cannot use MCP')
    finally:
        server.terminate();server.wait(timeout=5)
