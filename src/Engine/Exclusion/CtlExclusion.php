<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;

/**
 * One parsed CRS exclusion: remove whole rules or one inspection target,
 * scoped by rule id range or rule tag (exact match).
 */
final readonly class CtlExclusion
{
    private function __construct(
        public CtlExclusionType $type,
        public ?int $idFrom,
        public ?int $idTo,
        public ?string $tag,
        public ?TargetSelector $selector,
    ) {
    }

    public static function removeById(int $idFrom, int $idTo): self
    {
        self::assertIdRange($idFrom, $idTo);

        return new self(CtlExclusionType::RemoveById, $idFrom, $idTo, null, null);
    }

    public static function removeByTag(string $tag): self
    {
        self::assertTag($tag);

        return new self(CtlExclusionType::RemoveByTag, null, null, $tag, null);
    }

    public static function removeTargetById(int $idFrom, int $idTo, TargetSelector $targetSelector): self
    {
        self::assertIdRange($idFrom, $idTo);

        return new self(CtlExclusionType::RemoveTargetById, $idFrom, $idTo, null, $targetSelector);
    }

    public static function removeTargetByTag(string $tag, TargetSelector $targetSelector): self
    {
        self::assertTag($tag);

        return new self(CtlExclusionType::RemoveTargetByTag, null, null, $tag, $targetSelector);
    }

    /**
     * Whether this exclusion removes whole rules (vs. one inspection target).
     */
    public function removesRules(): bool
    {
        return $this->type === CtlExclusionType::RemoveById || $this->type === CtlExclusionType::RemoveByTag;
    }

    /**
     * Whether this exclusion's id range or tag covers the rule.
     */
    public function appliesTo(CoreRule $coreRule): bool
    {
        if ($this->idFrom !== null && $this->idTo !== null) {
            return $coreRule->id >= $this->idFrom && $coreRule->id <= $this->idTo;
        }

        return $this->tag !== null && in_array($this->tag, $coreRule->tags, true);
    }

    private static function assertIdRange(int $idFrom, int $idTo): void
    {
        if ($idFrom < 1 || $idTo < $idFrom) {
            throw new \InvalidArgumentException(
                sprintf('Rule id range %d-%d is not a valid ascending range of positive ids.', $idFrom, $idTo),
            );
        }
    }

    private static function assertTag(string $tag): void
    {
        if (trim($tag) === '') {
            throw new \InvalidArgumentException('A tag-scoped exclusion requires a non-empty tag.');
        }
    }
}
