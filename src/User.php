<?php
declare(strict_types=1);

namespace Froq\Acl;

final class User
{
    private $id;
    private $name;
    private $role;
    private $permissions = [];

    final public function __construct()
    {}

    // final public function setId($id) {}
    // final public function getId() {}

    // final public function setName($name) {}
    // final public function getName() {}

    // final public function setRole(Role $role) {}
    // final public function getRole() {}

    // final public function setPermissions(array $permissions) {}
    // final public function getPermissions(): array {}

    final public function isLoggedIn(): bool
    {
        return (null !== $this->id);
    }

    final public function hasAccessTo(Resource $resource): bool
    {
        return $this->role->hasAccessTo($resource);
    }

    // Alice: read,write; Bob: read
    final public function canRead(Resource $resource): bool
    {
        return $this->role->canRead($resource);
    }
    final public function canWrite(Resource $resource): bool
    {
        return $this->role->canWrite($resource);
    }

    final public function info(bool $full = false)
    {
        if (null === $this->id && null === $this->name) {
            return null;
        }

        $return = sprintf('id=%s(%s)', $this->id, $this->name);
        if ($full) {
            foreach ($this->role->getResources() as $resource) {
                $return .= sprintf(' resource(%s:%s)',
                    $resource->getName(), join(',', $resource->getPermissions()));
            }
        }

        return $return;
    }
}
