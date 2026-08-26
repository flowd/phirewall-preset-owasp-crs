<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetManipulatorTest extends TestCase
{
    private function argsRule(int $id, string $needle = 'suspicious'): CoreRule
    {
        return new CoreRule($id, ['ARGS'], '@contains', $needle, ['deny' => true], null, 5, 'CRITICAL', 1);
    }

    public function testGlobalManipulatorTransformsValuesBeforeMatching(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300001)]);
        $coreRuleSet->addManipulator(
            static fn(string $variable, ?string $name, string $value): string => str_replace('{{known-token}}', '', $value),
        );

        $harmless = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'susp{{known-token}}icious']);
        $this->assertTrue(
            $coreRuleSet->evaluate($harmless)->isBlocked(),
            'After stripping the known token the payload is visible to the rule',
        );
    }

    public function testManipulatorReturningEmptyStringRemovesValueFromInspection(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300002)]);
        $coreRuleSet->addManipulator(
            static fn(string $variable, ?string $name, string $value): string => $name === 'trusted' ? '' : $value,
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['trusted' => 'suspicious']);

        $this->assertFalse($coreRuleSet->evaluate($request)->isBlocked());
    }

    public function testManipulatorByIdOnlyAffectsThatRule(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300003), $this->argsRule(300004)]);
        $coreRuleSet->addManipulatorById(
            300003,
            static fn(string $variable, ?string $name, string $value): string => str_replace('suspicious', 'harmless', $value),
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([300004], $evaluation->matchedRuleIds(), 'The manipulated rule no longer sees the payload');
    }

    public function testGlobalManipulatorRunsOncePerVariablePerRequest(): void
    {
        $invocations = 0;
        $manipulator = new class ($invocations) implements RequestValueManipulatorInterface {
            public function __construct(private int &$invocations)
            {
            }

            public function manipulate(string $variable, ?string $name, string $value): string
            {
                ++$this->invocations;

                return $value;
            }
        };

        $coreRuleSet = new CoreRuleSet([
            $this->argsRule(300005, 'no-match-one'),
            $this->argsRule(300006, 'no-match-two'),
            $this->argsRule(300007, 'no-match-three'),
        ]);
        $coreRuleSet->addManipulator($manipulator);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'clean']);
        $coreRuleSet->evaluate($request);

        // One parameter yields two ARGS entries (value + name); the shared
        // global result is reused by all three rules instead of 3 x 2 calls.
        $this->assertSame(2, $invocations);
    }

    public function testManipulatorExceptionsPropagate(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300008)]);
        $coreRuleSet->addManipulator(
            static fn(string $variable, ?string $name, string $value): string => throw new \RuntimeException('manipulator bug'),
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'anything']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('manipulator bug');

        $coreRuleSet->evaluate($request);
    }

    public function testExclusionsRunBeforeManipulators(): void
    {
        $seenNames = [];
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300009)]);
        $coreRuleSet->excludeTarget('ARGS:/^utm_/');
        $coreRuleSet->addManipulator(
            static function (string $variable, ?string $name, string $value) use (&$seenNames): string {
                $seenNames[] = $name;

                return $value;
            },
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['utm_source' => 'x', 'q' => 'clean']);
        $coreRuleSet->evaluate($request);

        $this->assertNotContains('utm_source', $seenNames, 'Excluded entries never reach a manipulator');
        $this->assertContains('q', $seenNames);
    }
}
