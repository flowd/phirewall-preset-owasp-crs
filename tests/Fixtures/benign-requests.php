<?php

declare(strict_types=1);

/**
 * Curated corpus of real-world benign requests that must NOT be blocked by the
 * shipped CRS rules - the counterpart to the per-rule attack coverage in
 * {@see Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules\EveryRulePayloadTest}.
 *
 * Each entry carries `maxCleanParanoiaLevel`: the highest paranoia level at which
 * the request must still pass (stay below the anomaly threshold). Legitimate
 * traffic must stay clean at every level (4). A few realistic inputs are known
 * upstream CRS false positives at higher paranoia (English prose that contains SQL
 * keywords; a literal `&`/`or`/`and` in free text) - CRS trades false positives for
 * coverage above PL1 - so they are only required to pass at PL1 (1). That both
 * documents the accepted higher-PL FP and still guards PL1-cleanliness for them.
 *
 * @return list<array{
 *     label: string,
 *     maxCleanParanoiaLevel: int,
 *     method: string,
 *     uri: string,
 *     headers: array<string, string>,
 *     cookies: array<string, string>,
 *     body: array<string, string>|null,
 * }>
 */

$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
$firefox = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0';
$safariIos = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1';
$googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
$jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSmFuZSJ9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

$entry = static fn(string $label, string $method, string $uri, array $headers = [], array $cookies = [], ?array $body = null, int $maxCleanParanoiaLevel = 4): array => [
    'label' => $label,
    'maxCleanParanoiaLevel' => $maxCleanParanoiaLevel,
    'method' => $method,
    'uri' => $uri,
    'headers' => $headers,
    'cookies' => $cookies,
    'body' => $body,
];

return [
    $entry('homepage', 'GET', 'https://shop.test/', ['User-Agent' => $chrome]),
    $entry('product listing with sort/filter/pagination', 'GET', 'https://shop.test/products?category=electronics&sort=price&order=asc&page=2&per_page=50', ['User-Agent' => $chrome]),
    $entry('blog path containing "select"', 'GET', 'https://shop.test/blog/2024/how-to-select-a-database-index', ['User-Agent' => $chrome]),
    $entry('marketing/tracking params', 'GET', 'https://shop.test/?utm_source=newsletter&utm_medium=email&utm_campaign=spring_sale&gclid=EAIaIQob&fbclid=IwAR123&msclkid=abc', ['User-Agent' => $chrome]),
    $entry('search with an apostrophe (name)', 'GET', "https://shop.test/search?q=O'Reilly+books", ['User-Agent' => $firefox]),
    $entry('search with a percent-encoded percent sign', 'GET', 'https://shop.test/search?q=save+50%25+today+and+more', ['User-Agent' => $chrome]),
    $entry('search with German umlauts', 'GET', 'https://shop.test/suche?q=Gr%C3%BC%C3%9Fe+%C3%BCber+K%C3%B6ln', ['User-Agent' => $firefox]),
    $entry('email address in a query parameter', 'GET', 'https://shop.test/unsubscribe?email=jane.doe%2Btag@example.co.uk', ['User-Agent' => $chrome]),
    $entry('internal redirect parameter', 'GET', 'https://shop.test/login?redirect=/account/settings', ['User-Agent' => $chrome]),
    $entry('version number in the path', 'GET', 'https://shop.test/api/v1.2.3/status', ['User-Agent' => $chrome]),
    $entry('filename in a download parameter', 'GET', 'https://shop.test/download?file=report_2024_Q1.pdf', ['User-Agent' => $chrome]),
    $entry('googlebot fetching the sitemap', 'GET', 'https://shop.test/sitemap.xml', ['User-Agent' => $googlebot]),
    $entry('mobile safari homepage', 'GET', 'https://shop.test/', ['User-Agent' => $safariIos]),
    $entry('numeric ids in the path', 'GET', 'https://shop.test/api/users/123456/orders', ['User-Agent' => $chrome]),
    $entry('session + csrf + locale cookies (JWT session)', 'GET', 'https://shop.test/account', ['User-Agent' => $chrome], ['session' => $jwt, 'csrf_token' => 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1x', 'locale' => 'en_US']),
    $entry('authorization bearer token', 'GET', 'https://api.test/v1/me', ['User-Agent' => $chrome, 'Authorization' => 'Bearer ' . $jwt]),
    $entry('referer from a google search', 'GET', 'https://shop.test/product/42', ['User-Agent' => $chrome, 'Referer' => 'https://www.google.com/search?q=best+running+shoes']),
    $entry('login form body', 'POST', 'https://shop.test/login', ['User-Agent' => $chrome, 'Content-Type' => 'application/x-www-form-urlencoded'], [], ['email' => 'user@example.com', 'password' => 'Correct-Horse-Battery-Staple-9!']),
    $entry('json api body with an apostrophe name', 'POST', 'https://api.test/v1/comments', ['User-Agent' => $chrome, 'Content-Type' => 'application/json'], [], ['name' => "O'Brien", 'title' => 'My 2 cents on the new model']),
    // Known upstream CRS false positives above PL1 (documented; required clean only at PL1):
    $entry('search: english prose with SQL keywords', 'GET', 'https://shop.test/search?q=how+to+select+the+best+wine+from+france', ['User-Agent' => $firefox], [], null, 1),
    $entry('free text containing an ampersand', 'GET', 'https://shop.test/menu?dish=Fish+%26+Chips', ['User-Agent' => $chrome], [], null, 1),
    $entry('search sentence with "and"/"or"', 'GET', 'https://shop.test/search?q=red+or+blue+shirts+and+shoes', ['User-Agent' => $firefox], [], null, 1),
];
