<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * A registered target exclusion: the selector picks entries by name, the
 * optional condition then approves each selected entry's value. Without a
 * condition every selected entry is excluded.
 */
final readonly class TargetExclusion
{
    public function __construct(
        public TargetSelector $selector,
        public ?TargetExclusionConditionInterface $condition = null,
    ) {
    }

    /**
     * Whether the entry is excluded from inspection.
     */
    public function excludes(?string $name, string $value, ServerRequestInterface $serverRequest): bool
    {
        if (!$this->selector->matchesName($name)) {
            return false;
        }

        if (!$this->condition instanceof TargetExclusionConditionInterface) {
            return true;
        }

        return $this->condition->shouldExclude($this->selector->variable, $name, $value, $serverRequest);
    }
}
