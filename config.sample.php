<?php
/** Copy to config.php. Never commit that file or either secret. */
return array(
    'public_url' => 'https://lemonchiffon-pigeon-682675.hostingersite.com',

    // Generate a NEW, separate value with: openssl rand -hex 32
    // Keep this stable: it encrypts stored WordPress credentials.
    'encryption_key' => 'REPLACE_WITH_A_NEW_64_CHARACTER_HEX_SECRET',

    // Existing, writable private directory OUTSIDE your website document root.
    // Replace this with your actual Hostinger home path. Do not use public_html.
    'storage_path' => '/home/YOUR_HOSTINGER_USER/sitebridge-private/connections.sqlite',

    // Optional legacy/private administrator token. Empty disables manual bearer access.
    // OAuth users do not need this token and cannot see these manually configured sites.
    'master_token' => '',
    'sites' => array(),
    'timeout' => 30,
);
