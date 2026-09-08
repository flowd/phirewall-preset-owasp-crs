<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

/**
 * The four supported CRS exclusion forms, shared by the configure-time
 * directives (`SecRuleRemove*`, `SecRuleUpdateTarget*`) and the runtime
 * `ctl:ruleRemove*` actions.
 */
enum CtlExclusionType
{
    case RemoveById;
    case RemoveByTag;
    case RemoveTargetById;
    case RemoveTargetByTag;
}
