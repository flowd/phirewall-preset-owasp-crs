<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values against a list of phrases using case-insensitive substring matching (@pm operator).
 */
final readonly class PhraseMatchEvaluator implements DetailedOperatorEvaluatorInterface
{
    /** @var list<string> Cached parsed phrase list. */
    private array $phrases;

    public function __construct(string $phraseList)
    {
        $this->phrases = PhraseListParser::parse($phraseList);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        return self::firstMatch($values, $this->phrases);
    }

    /**
     * Check if any value contains any phrase (case-insensitive).
     *
     * Shared by PhraseMatchEvaluator and PhraseMatchFromFileEvaluator.
     *
     * @param list<string> $values
     * @param list<string> $phrases
     */
    public static function matchAny(array $values, array $phrases): bool
    {
        return self::firstMatch($values, $phrases) !== OperatorResult::noMatch();
    }

    /**
     * Locate the first value containing any phrase (case-insensitive); the
     * matched phrase is exposed as the TX.0 capture.
     *
     * @param list<string> $values
     * @param list<string> $phrases
     */
    public static function firstMatch(array $values, array $phrases): OperatorResult
    {
        if ($phrases === []) {
            return OperatorResult::noMatch();
        }

        foreach ($values as $index => $value) {
            foreach ($phrases as $phrase) {
                if ($phrase !== '' && stripos($value, $phrase) !== false) {
                    return OperatorResult::matched($index, [$phrase]);
                }
            }
        }

        return OperatorResult::noMatch();
    }
}
