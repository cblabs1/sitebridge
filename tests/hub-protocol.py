"""Exercise actual PHP HTTP routes without contacting any real WordPress site."""
import base64, hashlib, http.cookiejar, json, os, pathlib, shutil, socket, subprocess, tempfile, time, urllib.request, urllib.error
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
    for name in ['index.php', 'connections.php', '.htaccess']:
        shutil.copy2(hub/name, web/name)
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
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path='/',data=None,token=None,form=False,method=None):
        headers={}
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
    try:
        for _ in range(50):
            try: request(); break
            except urllib.error.URLError: time.sleep(.05)
        status,_,body=request()
        check(status==200 and body['ok'], 'health endpoint')
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
        status,_,body=request('/?route=authorize&'+urlencode(auth))
        check(status==200 and 'Continue to WordPress' in body, 'OAuth sign-in form')
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
