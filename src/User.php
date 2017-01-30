<?php
declare(strict_types=1);

namespace Froq\Acl;

final class User
{
    private $id;
    private $name;
    private $role;
    private $permissions = [];

    final public function __construct(array $info = null)
    {
        if ($info) {
            isset($info['id'])   && $this->setId($info['id']);
            isset($info['name']) && $this->setName($info['name']);
            isset($info['role']) && $this->setRole($info['role']);
        }
    }

    final public function setId($id)
    {
        $this->id = $id;
    }
    final public function getId()
    {
        return $this->id;
    }

    final public function setName(string $name)
    {
        $this->name = $name;
    }
    final public function getName()
    {
        return $this->name;
    }

    final public function setRole(string $role)
    {
        $this->role = $role;
    }
    final public function getRole()
    {
        return $this->role;
    }

    final public function setPermission($uri, array $permission)
    {
        $this->permissions[$uri] = $permission;
    }
    final public function getPermission($uri)
    {
        return $this->permissions[$uri] ?? null;
    }

    final public function setPermissions(array $permissions)
    {
        $this->permissions = $permissions;
    }
    final public function getPermissions(): array
    {
        return $this->permissions;
    }

    final public function isLoggedIn(): bool
    {
        return ($this->id !== null);
    }

    final public function hasAccessTo(string $uri): bool
    {
        return !!$this->getPermission($uri);
    }

    // // Alice: read,write; Bob: read
    // final public function canRead(Resource $resource): bool
    // {
    //     return $this->role->canRead($resource);
    //
    //     $permissions = $this->getPermission($uri);
        // if ($permissions) {
        //     foreach ($permissions as $permission) {
        //         if ($permission == Acl::RULE_ALL || $permission == Acl::RULE_READ) {
        //             return true;
        //         }
        //     }
        // }
        // return false;
    // }
    // final public function canWrite(Resource $resource): bool
    // {
    //     return $this->role->canWrite($resource);
    // }

    // final public function info(bool $full = false)
    // {
    //     if ($this->id === null && $this->name === null) {
    //         return null;
    //     }

    //     $return = sprintf('id=%s(%s)', $this->id, $this->name);
    //     if ($full) {
    //         foreach ($this->role->getResources() as $resource) {
    //             $return .= sprintf("\nresource(%s:%s)",
    //                 $resource->getName(), join(',', $resource->getPermissions()));
    //         }
    //     }

    //     return $return;
    // }
}
