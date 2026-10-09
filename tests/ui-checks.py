"""Check rendered HTML and escaping for all connection outcome states."""
import pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
def render(mode):return subprocess.check_output(['php',str(root/'tests/render-ui.php'),mode],text=True)
def check(value,name):
 if not value:raise AssertionError(name)
 print('PASS',name)
approval=render('approve')
check('type="checkbox"' not in approval and 'name="caps' not in approval,'approval has no permission controls')
check('Approve connection' in approval and 'value="deny"' in approval,'approval and cancel remain explicit')
check('Create and edit posts' in approval and 'Modify the database' not in approval,'connection details summarize only enabled access')
check('name="_wpnonce"' in approval and 'name="local"' in approval,'rendered approval retains CSRF fields')
check('aria-current="step"' in approval and 'aria-labelledby="sb-title"' in approval,'progress and card have accessible labels')
escaped=render('escape')
check('<script>' not in escaped and '&lt;script&gt;' in escaped,'untrusted app name is escaped')
for mode,title in [('success','You’re connected'),('denied','Connection canceled'),('error','Connection needs attention'),('landing','Your MCP server URL')]:
 html=render(mode)
 check(title in html and 'sb-journey' in html and '<meta name="viewport"' in html,f'{mode} uses responsive journey layout')
check('Finish connecting to your AI app' in render('success'),'success retains explicit OAuth completion link')
css=(root/'sitebridge/assets/connection-ui.css' if (root/'sitebridge').is_dir() else root/'wordpress-plugin/sitebridge/assets/connection-ui.css').read_text()
check('@media(max-width:540px)' in css and ':focus-visible' in css and 'prefers-reduced-motion' in css,'responsive, keyboard focus and reduced-motion styles present')
