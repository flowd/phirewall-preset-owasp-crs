<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * Tri-state result of evaluating a rule or operator against a request.
 *
 * FailClosed marks a decision forced by an uninspectable input (a variable
 * truncated at the collection cap, or a PCRE engine error on the subject)
 * rather than by an actual pattern match; callers block regardless of the
 * anomaly threshold when they see it.
 */
enum RuleOutcome
{
    case NoMatch;
    case Matched;
    case FailClosed;
}
