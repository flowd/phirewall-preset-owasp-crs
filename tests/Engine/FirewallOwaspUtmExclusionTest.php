<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\AbstractLogger;

/**
 * End-to-end scenario for the utm-parameter false-positive workflow against
 * the real shipped PL1 rules: an XSS payload in a utm parameter blocks, the
 * documented exclusions silence exactly that parameter family, and the same
 * payload in any other parameter keeps blocking.
 */
final class FirewallOwaspUtmExclusionTest extends TestCase
{
    /**
     * The verified fixture payload for shipped rule 941110 (XSS), delivered via ARGS.
     */
    private function xssPayload(): string
    {
        /** @var array{payloads: array<int, array{vector: string, payload_base64: string}>} $fixtures */
        $fixtures = require __DIR__ . '/../Fixtures/rule-payloads.php';
        $payload = base64_decode($fixtures['payloads'][941110]['payload_base64'], true);
        $this->assertIsString($payload);

        return $payload;
    }

    private function requestWithParam(string $name, string $value): ServerRequestInterface
    {
        return (new ServerRequest('GET', 'https://example.test/landing'))
            ->withQueryParams([$name => $value]);
    }

    public function testUtmParameterPayloadBlocksWithoutExclusions(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(ParanoiaLevel::Level1)));

        $this->assertTrue(
            $firewall->decide($this->requestWithParam('utm_content', $this->xssPayload()))->isBlocked(),
        );
    }

    public function testUtmExclusionSilencesTheParameterFamilyButNothingElse(): void
    {
        $logger = new class () extends AbstractLogger {
            /** @var list<array<string, mixed>> */
            public array $contexts = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->contexts[] = $context;
            }
        };

        $firewall = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(
            ParanoiaLevel::Level1,
            configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher): void {
                $coreRuleSetMatcher->excludeTarget('ARGS:/^utm_/');
                $coreRuleSetMatcher->excludeTarget('ARGS_NAMES:/^utm_/');
            },
            logger: $logger,
        )));

        $payload = $this->xssPayload();

        $this->assertFalse(
            $firewall->decide($this->requestWithParam('utm_content', $payload))->isBlocked(),
            'The excluded utm parameter family is not inspected',
        );
        $this->assertSame([], $logger->contexts, 'No rule matches once the parameter is excluded');

        $this->assertTrue(
            $firewall->decide($this->requestWithParam('q', $payload))->isBlocked(),
            'The same payload in a regular parameter keeps blocking',
        );
        $this->assertNotSame([], $logger->contexts);
        $this->assertContains('ARGS:q', array_column($logger->contexts, 'matched_variable'));
    }

    public function testManipulatorSilencesASingleKnownValueEndToEnd(): void
    {
        $payload = $this->xssPayload();

        $firewall = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(
            ParanoiaLevel::Level1,
            configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher): void {
                $coreRuleSetMatcher->addManipulator(
                    static fn(string $variable, ?string $name, string $value): string => $name === 'fbclid' ? '' : $value,
                );
            },
        )));

        $this->assertFalse(
            $firewall->decide($this->requestWithParam('fbclid', $payload))->isBlocked(),
            'The manipulator removes the fbclid value from inspection',
        );

        $this->assertTrue(
            $firewall->decide($this->requestWithParam('q', $payload))->isBlocked(),
            'Other parameters stay inspected',
        );
    }
}
