<?php
/**
 * Copyright (c) 2016 Kerem Güneş
 *     <k-gun@mail.com>
 *
 * GNU General Public License v3.0
 *     <http://www.gnu.org/licenses/gpl-3.0.txt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
declare(strict_types=1);

namespace Froq\Acl;

use Froq\Service\Service;

/**
 * @package    Froq
 * @subpackage Froq\Acl
 * @object     Froq\Acl\Acl
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final class Acl
{
    /**
     * Rules.
     * @const string
     */
    const RULE_ALL   = 'all',
          RULE_READ  = 'read',
          RULE_WRITE = 'write';

    /**
     * Service.
     * @var Froq\Service\Service
     */
    private $service;

    /**
     * User.
     * @var Froq\Acl\User
     */
    private $user;

    /**
     * Rules (comes from <FooService>/config['acl.config'] if provided).
     * @var array
     */
    private $rules = [];

    /**
     * Constructor.
     * @param Froq\Service\Service $service
     */
    final public function __construct(Service $service)
    {
        $this->service = $service;
    }

    /**
     * Get service.
     * @return Froq\Service\Service
     */
    public function getService(): Service
    {
        return $this->service;
    }

    /**
     * Set user.
     * @param  Froq\Acl\User $user
     * @return self
     */
    final public function setUser(User $user): self
    {
        $this->user = $user;
        $this->user->setAcl($this);

        $userRole = $this->user->getRole();
        if ($userRole && !empty($this->rules)) {
            foreach ($this->rules as $role => $rules) {
                if ($role == $userRole) {
                    foreach ($rules as $uri => $rules) {
                        $this->user->setPermissionsOf($uri,
                            explode(',', $rules) /* 'read,write' etc. */ );
                    }
                    break;
                }
            }
        }

        return $this;
    }

    /**
     * Get user.
     * @return Froq\Acl\User|null
     */
    final public function getUser()
    {
        return $this->user;
    }

    /**
     * Set rules.
     * @param  array $rules
     * @return self
     */
    final public function setRules(array $rules): self
    {
        $this->rules = $rules;

        return $this;
    }

    /**
     * Get rules.
     * @return array
     */
    final public function getRules(): array
    {
        return $this->rules;
    }
}
