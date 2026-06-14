<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

/**
 * Splits ModSecurity configuration text into logical lines.
 *
 * Joins backslash line continuations outside of quoted segments, keeps
 * escape sequences inside quotes untouched and skips blank and comment lines.
 * A single space is inserted at each join so the segments of a continued
 * directive stay separated in the generated single-line output.
 */
final class LogicalLineSplitter
{
    /**
     * @return list<string>
     */
    public function split(string $text): array
    {
        $length = strlen($text);
        $logicalLines = [];
        $buffer = '';
        $inQuote = false;
        $quoteCharacter = '';

        for ($position = 0; $position < $length; ++$position) {
            $character = $text[$position];

            if ($inQuote) {
                if ($character === '\\' && $position + 1 < $length) {
                    $buffer .= $character . $text[$position + 1];
                    ++$position;
                    continue;
                }

                if ($character === $quoteCharacter) {
                    $inQuote = false;
                    $quoteCharacter = '';
                }

                $buffer .= $character;
                continue;
            }

            if ($character === '#' && trim($buffer) === '') {
                while ($position + 1 < $length && $text[$position + 1] !== "\n") {
                    ++$position;
                }

                $buffer = '';
                continue;
            }

            if ($character === '"' || $character === "'") {
                $inQuote = true;
                $quoteCharacter = $character;
                $buffer .= $character;
                continue;
            }

            if ($character === "\r") {
                continue;
            }

            if ($character === "\n") {
                $lastIndex = strlen($buffer) - 1;
                while ($lastIndex >= 0 && ($buffer[$lastIndex] === ' ' || $buffer[$lastIndex] === "\t")) {
                    --$lastIndex;
                }

                if ($lastIndex >= 0 && $buffer[$lastIndex] === '\\') {
                    $buffer = rtrim(substr($buffer, 0, $lastIndex), " \t") . ' ';
                    $nextPosition = $position + 1;
                    while ($nextPosition < $length && ($text[$nextPosition] === ' ' || $text[$nextPosition] === "\t")) {
                        ++$nextPosition;
                    }

                    $position = $nextPosition - 1;
                    continue;
                }

                $trimmed = trim($buffer);
                if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
                    $logicalLines[] = $trimmed;
                }

                $buffer = '';
                continue;
            }

            $buffer .= $character;
        }

        $trimmed = trim($buffer);
        if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
            $logicalLines[] = $trimmed;
        }

        return $logicalLines;
    }
}
