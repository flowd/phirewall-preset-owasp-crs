<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Parses the inline phrase list of the @pm operator (a whitespace/comma-separated
 * argument). Supports quotes (single/double) and backslash escapes.
 *
 * @pmFromFile does NOT use this: a data file is one phrase per line (ModSecurity
 * semantics), so {@see PhraseMatchFromFileEvaluator} reads each line whole.
 */
final class PhraseListParser
{
    public const MAX_PHRASES = 5000;

    /**
     * Parse a phrase list string into an array of unique, non-empty tokens.
     *
     * @return list<string>
     */
    public static function parse(string $list): array
    {
        $tokens = [];
        $buffer = '';
        $inQuote = false;
        $quote = '';
        $length = strlen($list);

        for ($i = 0; $i < $length; ++$i) {
            $character = $list[$i];

            if ($inQuote) {
                if ($character === '\\' && $i + 1 < $length) {
                    $buffer .= $list[$i + 1];
                    ++$i;
                    continue;
                }

                if ($character === $quote) {
                    $inQuote = false;
                    continue;
                }

                $buffer .= $character;
                continue;
            }

            if ($character === "'" || $character === '"') {
                $inQuote = true;
                $quote = $character;
                continue;
            }

            if ($character === ',' || ctype_space($character)) {
                if ($buffer !== '') {
                    $tokens[] = $buffer;
                    $buffer = '';
                }

                continue;
            }

            $buffer .= $character;
        }

        if ($buffer !== '') {
            $tokens[] = $buffer;
        }

        // Remove empties and duplicates while preserving order
        $result = [];
        $seen = [];
        foreach ($tokens as $token) {
            $token = trim($token);
            if ($token === '') {
                continue;
            }

            if (!isset($seen[$token])) {
                $seen[$token] = true;
                $result[] = $token;
                if (count($result) >= self::MAX_PHRASES) {
                    break;
                }
            }
        }

        return $result;
    }
}
