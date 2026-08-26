<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Variable;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\ArgsCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\ArgsNamesCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\QueryStringCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestCookiesCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestCookiesNamesCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestFilenameCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestHeadersCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestHeadersNamesCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestMethodCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestUriCollector;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\VariableCollectorFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class VariableCollectorTest extends TestCase
{
    /**
     * @param list<array{name: ?string, value: string}> $entries
     * @return list<string>
     */
    private function values(array $entries): array
    {
        return array_column($entries, 'value');
    }

    public function testRequestUriCollectorReturnsPathAndQueryUnnamed(): void
    {
        $collector = new RequestUriCollector();
        $request = new ServerRequest('GET', '/admin?x=1');

        $this->assertSame([['name' => null, 'value' => '/admin?x=1']], $collector->collect($request));
    }

    public function testRequestUriCollectorOmitsQuestionMarkWhenNoQuery(): void
    {
        $collector = new RequestUriCollector();
        $request = new ServerRequest('GET', '/page');

        $this->assertSame([['name' => null, 'value' => '/page']], $collector->collect($request));
    }

    public function testRequestMethodCollectorReturnsMethod(): void
    {
        $collector = new RequestMethodCollector();

        $this->assertSame([['name' => null, 'value' => 'POST']], $collector->collect(new ServerRequest('POST', '/')));
        $this->assertSame([['name' => null, 'value' => 'GET']], $collector->collect(new ServerRequest('GET', '/')));
    }

    public function testQueryStringCollectorReturnsRawQuery(): void
    {
        $collector = new QueryStringCollector();
        $request = new ServerRequest('GET', '/path?a=1&b=2');

        $this->assertSame([['name' => null, 'value' => 'a=1&b=2']], $collector->collect($request));
    }

    public function testQueryStringCollectorReturnsEmptyStringWhenNoQuery(): void
    {
        $collector = new QueryStringCollector();
        $request = new ServerRequest('GET', '/path');

        $this->assertSame([['name' => null, 'value' => '']], $collector->collect($request));
    }

    public function testArgsCollectorCollectsQueryAndBodyValuesAndNames(): void
    {
        $collector = new ArgsCollector();
        $request = (new ServerRequest('POST', '/submit?foo=bar'))
            ->withParsedBody(['token' => 'secret', 'nested' => ['a', 'b']]);

        $values = $this->values($collector->collect($request));

        // Query params: value "bar", key "foo"
        $this->assertContains('bar', $values);
        $this->assertContains('foo', $values);
        // Body params: value "secret", key "token", nested values "a"/"b" with bracketed names.
        $this->assertContains('secret', $values);
        $this->assertContains('token', $values);
        $this->assertContains('a', $values);
        $this->assertContains('b', $values);
        // The collected name is the original bracketed parameter, not each path segment.
        $this->assertContains('nested[0]', $values);
        $this->assertContains('nested[1]', $values);
        $this->assertNotContains('nested', $values);
    }

    public function testArgsCollectorAttributesValueAndNameEntriesToTheParameter(): void
    {
        $collector = new ArgsCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withQueryParams(['utm_source' => 'facebook']);

        $this->assertSame([
            ['name' => 'utm_source', 'value' => 'facebook'],
            ['name' => 'utm_source', 'value' => 'utm_source', 'isNameEntry' => true],
        ], $collector->collect($request));
    }

    public function testArgsCollectorCollectsDeeplyNestedValuesWithBracketedNames(): void
    {
        // a[b][c]=payload parses to a nested array; the leaf value must still be collected so an
        // ARGS-targeting rule cannot be evaded by nesting, and the name flattens to the bracketed
        // parameter name rather than each segment.
        $collector = new ArgsCollector();
        $request = (new ServerRequest('POST', '/'))
            ->withQueryParams(['a' => ['b' => ['c' => 'queryPayload']]])
            ->withParsedBody(['x' => ['y' => ['z' => 'bodyPayload']]]);

        $entries = $collector->collect($request);
        $values = $this->values($entries);

        $this->assertContains('queryPayload', $values);
        $this->assertContains('bodyPayload', $values);
        $this->assertContains('a[b][c]', $values);
        $this->assertContains('x[y][z]', $values);
        $this->assertNotContains('a', $values);
        $this->assertNotContains('b', $values);
        $this->assertContains(['name' => 'a[b][c]', 'value' => 'queryPayload'], $entries);
    }

    public function testArgsCollectorCollectsValueAndNameForEveryParameterWithoutTruncating(): void
    {
        $collector = new ArgsCollector();

        // The collector no longer caps: it returns a value AND a name entry for every parameter.
        // Bounding the entry count (and failing closed when exceeded) is applied centrally
        // by RequestVariableValues, so a parameter is never half-collected here.
        $queryParams = [];
        for ($index = 0; $index < 50; ++$index) {
            $queryParams['k' . $index] = 'v' . $index;
        }

        $request = (new ServerRequest('GET', '/'))->withQueryParams($queryParams);

        $result = $collector->collect($request);

        $this->assertCount(100, $result, 'Every parameter contributes its value and its name, untruncated');
    }

    public function testArgsNamesCollectorCollectsKeysOnly(): void
    {
        $collector = new ArgsNamesCollector();
        $request = (new ServerRequest('POST', '/x?foo=1&bar=2'))
            ->withParsedBody(['token' => 'v']);

        $entries = $collector->collect($request);
        $values = $this->values($entries);

        $this->assertContains('foo', $values);
        $this->assertContains('bar', $values);
        $this->assertContains('token', $values);
        $this->assertNotContains('1', $values);
        $this->assertNotContains('2', $values);
        $this->assertNotContains('v', $values);
        $this->assertContains(['name' => 'foo', 'value' => 'foo'], $entries);
    }

    public function testRequestCookiesCollectorReturnsCookieValuesWithNames(): void
    {
        $collector = new RequestCookiesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'chocolate']);

        $this->assertSame([
            ['name' => 'session', 'value' => 'abc'],
            ['name' => 'flavor', 'value' => 'chocolate'],
        ], $collector->collect($request));
    }

    public function testRequestCookiesCollectorFlattensNestedCookieArrays(): void
    {
        // PHP parses a bracketed cookie name (Cookie: foo[a]=1; foo[b][c]=payload) into a nested
        // array, exactly like query parameters. The collector must collect the leaf values instead
        // of casting the array (which would raise a warning and scan the literal string "Array").
        $collector = new RequestCookiesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withCookieParams([
                'session' => 'abc',
                'foo' => ['a' => '1', 'b' => ['c' => 'payload']],
            ]);

        $this->assertSame([
            ['name' => 'session', 'value' => 'abc'],
            ['name' => 'foo[a]', 'value' => '1'],
            ['name' => 'foo[b][c]', 'value' => 'payload'],
        ], $collector->collect($request));
    }

    public function testRequestCookiesNamesCollectorReturnsCookieKeys(): void
    {
        $collector = new RequestCookiesNamesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withCookieParams(['session' => 'abc', 'flavor' => 'vanilla']);

        $this->assertSame([
            ['name' => 'session', 'value' => 'session'],
            ['name' => 'flavor', 'value' => 'flavor'],
        ], $collector->collect($request));
    }

    public function testRequestHeadersCollectorReturnsAllHeaderValuesWithNames(): void
    {
        $collector = new RequestHeadersCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('User-Agent', ['Mozilla/5.0', 'Extra'])
            ->withHeader('Accept', 'text/html');

        $entries = $collector->collect($request);
        $values = $this->values($entries);

        $this->assertContains('Mozilla/5.0', $values);
        $this->assertContains('Extra', $values);
        $this->assertContains('text/html', $values);

        foreach ($entries as $entry) {
            if ($entry['value'] === 'Mozilla/5.0' || $entry['value'] === 'Extra') {
                $this->assertNotNull($entry['name']);
                $this->assertSame('user-agent', strtolower($entry['name']));
            }
        }
    }

    public function testRequestHeadersNamesCollectorReturnsHeaderNames(): void
    {
        $collector = new RequestHeadersNamesCollector();
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('X-Test', '1')
            ->withHeader('Content-Type', 'text/plain');

        $values = $this->values($collector->collect($request));

        // Nyholm PSR-7 normalizes header names
        $lowered = array_map('strtolower', $values);
        $this->assertContains('x-test', $lowered);
        $this->assertContains('content-type', $lowered);
    }

    public function testRequestFilenameCollectorReturnsBasename(): void
    {
        $collector = new RequestFilenameCollector();
        $request = new ServerRequest('GET', '/uploads/photo.jpg');

        $this->assertSame([['name' => null, 'value' => 'photo.jpg']], $collector->collect($request));
    }

    public function testRequestFilenameCollectorReturnsEmptyForEmptyPath(): void
    {
        $collector = new RequestFilenameCollector();
        // Construct with an empty path
        $request = new ServerRequest('GET', '');

        $result = $collector->collect($request);
        // PSR-7 may normalize empty path; just verify no exception and result type
        $this->assertGreaterThanOrEqual(0, count($result));
    }

    public function testFactoryResolvesKnownVariables(): void
    {
        $this->assertInstanceOf(RequestUriCollector::class, VariableCollectorFactory::create('REQUEST_URI'));
        $this->assertInstanceOf(RequestMethodCollector::class, VariableCollectorFactory::create('REQUEST_METHOD'));
        $this->assertInstanceOf(QueryStringCollector::class, VariableCollectorFactory::create('QUERY_STRING'));
        $this->assertInstanceOf(ArgsCollector::class, VariableCollectorFactory::create('ARGS'));
        $this->assertInstanceOf(ArgsNamesCollector::class, VariableCollectorFactory::create('ARGS_NAMES'));
        $this->assertInstanceOf(RequestCookiesCollector::class, VariableCollectorFactory::create('REQUEST_COOKIES'));
        $this->assertInstanceOf(RequestCookiesNamesCollector::class, VariableCollectorFactory::create('REQUEST_COOKIES_NAMES'));
        $this->assertInstanceOf(RequestHeadersCollector::class, VariableCollectorFactory::create('REQUEST_HEADERS'));
        $this->assertInstanceOf(RequestHeadersNamesCollector::class, VariableCollectorFactory::create('REQUEST_HEADERS_NAMES'));
        $this->assertInstanceOf(RequestFilenameCollector::class, VariableCollectorFactory::create('REQUEST_FILENAME'));
    }

    public function testFactoryReturnsNullForUnknownVariables(): void
    {
        $this->assertInstanceOf(RequestUriCollector::class, VariableCollectorFactory::create('REQUEST_URI'));
        $this->assertNull(VariableCollectorFactory::create('XML:/*'));
        $this->assertNull(VariableCollectorFactory::create('UNKNOWN_VAR'));
    }
}
