<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\ConfigLayer;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Psr\Log\LoggerInterface;

/**
 * OWASP CRS presets as Config layers.
 *
 * Each factory returns a {@see ConfigLayer} for {@see Config::with()}:
 *
 *     $config = $config->with(Presets::blocklist(ParanoiaLevel::Level1));
 *
 * Requests are blocked when their accumulated anomaly score reaches
 * $anomalyThreshold (CRS default 5); $configure receives the matcher for
 * tuning (exclusions, manipulators, enable/disable) before the first request:
 *
 *     $config = $config->with(Presets::blocklist(configure: function (CoreRuleSetMatcher $matcher): void {
 *         $matcher->excludeTarget('ARGS:/^utm_/');
 *     }));
 */
final class Presets
{
    public const BLOCKLIST_RULE_NAME = 'preset.owasp-crs.blocklist';

    public const FAIL2BAN_RULE_NAME = 'preset.owasp-crs.fail2ban';

    private function __construct()
    {
    }

    /**
     * Block every request whose accumulated CRS anomaly score reaches the threshold.
     *
     * @param \Closure(CoreRuleSetMatcher): void|null $configure
     */
    public static function blocklist(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        ?string $rulesDirectory = null,
        int $anomalyThreshold = CoreRuleSetMatcher::DEFAULT_ANOMALY_THRESHOLD,
        ?\Closure $configure = null,
        ?LoggerInterface $logger = null,
    ): ConfigLayer {
        return self::layer(static function (Config $config) use ($paranoiaLevel, $rulesDirectory, $anomalyThreshold, $configure, $logger): void {
            $matcher = CoreRuleSetMatcher::fromRuleFiles($paranoiaLevel, $rulesDirectory, null, $anomalyThreshold, $logger);
            if ($configure instanceof \Closure) {
                $configure($matcher);
            }

            $config->blocklists->addRule(new BlocklistRule(self::BLOCKLIST_RULE_NAME, $matcher));
        });
    }

    /**
     * Block scoring requests and ban repeat offenders.
     *
     * A request whose accumulated anomaly score reaches $anomalyThreshold is
     * blocked (403) and counts toward the ban (Fail2BanMatched); the
     * $threshold-th such request within $period seconds additionally bans
     * the client key (IP by default) for $ban seconds, so any further request
     * from that key is blocked until the ban expires. Anomaly scores never
     * accumulate across requests.
     *
     * @param \Closure(CoreRuleSetMatcher): void|null $configure
     */
    public static function fail2ban(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        int $threshold = 5,
        int $period = 600,
        int $ban = 3600,
        ?string $rulesDirectory = null,
        int $anomalyThreshold = CoreRuleSetMatcher::DEFAULT_ANOMALY_THRESHOLD,
        ?\Closure $configure = null,
        ?LoggerInterface $logger = null,
    ): ConfigLayer {
        return self::layer(static function (Config $config) use ($paranoiaLevel, $threshold, $period, $ban, $rulesDirectory, $anomalyThreshold, $configure, $logger): void {
            $matcher = CoreRuleSetMatcher::fromRuleFiles($paranoiaLevel, $rulesDirectory, null, $anomalyThreshold, $logger);
            if ($configure instanceof \Closure) {
                $configure($matcher);
            }

            $config->fail2ban->addRule(new Fail2BanRule(
                self::FAIL2BAN_RULE_NAME,
                $threshold,
                $period,
                $ban,
                $matcher,
                null,
            ));
        });
    }

    /**
     * The imported CRS rules for a paranoia level, for manual wiring via a
     * BlocklistRule with a CoreRuleSetMatcher (or to enable/disable rule ids).
     */
    public static function coreRuleSet(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        ?string $rulesDirectory = null,
        ?int $maxValuesPerCrsVariable = null,
    ): CoreRuleSet {
        return RuleSetLoader::load($paranoiaLevel, $rulesDirectory, $maxValuesPerCrsVariable);
    }

    /**
     * The upstream CRS release tag the bundled rules were imported from.
     */
    public static function crsVersion(?string $rulesDirectory = null): string
    {
        return Manifest::read($rulesDirectory)->crsVersion;
    }

    /**
     * Wrap a rule-registration callback as a layer that populates a fresh Config
     * bound to the base infrastructure, then folds it onto the base.
     *
     * @param \Closure(Config): void $register
     */
    private static function layer(\Closure $register): ConfigLayer
    {
        return new class ($register) implements ConfigLayer {
            /** @param \Closure(Config): void $register */
            public function __construct(private readonly \Closure $register)
            {
            }

            public function applyTo(Config $config): Config
            {
                $layer = (new Config($config->cache, $config->eventDispatcher, $config->clock))
                    ->setEnabled($config->isEnabled());
                ($this->register)($layer);

                return $config->with($layer);
            }
        };
    }
}
