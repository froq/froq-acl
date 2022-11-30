<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-acl
 */
declare(strict_types=1);

namespace froq\acl;

/**
 * Enum class as ACL rules.
 *
 * @package froq\acl
 * @object  froq\acl\Rule
 * @author  Kerem Güneş
 * @since   6.0
 */
class Rule
{
    /** Rules. */
    public const ALL = 'all', READ = 'read', WRITE = 'write';
}
