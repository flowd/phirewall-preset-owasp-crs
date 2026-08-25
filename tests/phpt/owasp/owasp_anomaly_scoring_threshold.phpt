--TEST--
Phirewall: OWASP anomaly scoring blocks only when accumulated severity scores reach the threshold
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\Phirewall\Store\InMemoryCache;

$rules = SecRuleLoader::fromString(
    'SecRule ARGS "@contains first-pattern" "id:942430,phase:2,block,severity:\'WARNING\'"' . "\n" .
    'SecRule ARGS "@contains second-pattern" "id:942431,phase:2,block,severity:\'WARNING\'"'
);

$config = new Config(new InMemoryCache());
$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($rules)));

$middleware = phpt_middleware($config);
$handler = phpt_handler();

// One WARNING match scores 3 < 5: the request passes.
$response = $middleware->process(phpt_request('GET', '/search?q=first-pattern'), $handler);
echo 'single=' . $response->getStatusCode() . "\n";

// Two WARNING matches score 6 >= 5: the request is blocked.
$response = $middleware->process(phpt_request('GET', '/search?a=first-pattern&b=second-pattern'), $handler);
echo 'accumulated=' . $response->getStatusCode() . "\n";
?>
--EXPECT--
single=200
accumulated=403
