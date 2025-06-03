/*
-- Insertion conditionnelle des permissions
INSERT INTO permissions (name, description)
SELECT * FROM (
    SELECT 'basic_access', 'Accès basique à l''application' UNION ALL
    SELECT 'user:read', 'Lire les informations utilisateur' UNION ALL
    SELECT 'user:create', 'Créer un nouvel utilisateur' UNION ALL
    -- ... autres permissions ...
    SELECT 'system:read', 'Lire les informations système') AS tmp
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE name = tmp.name);

-- Insertion conditionnelle du rôle ADMIN
INSERT INTO roles (name, description)
SELECT 'ROLE_ADMIN', 'Administrateur avec tous les droits'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'ROLE_ADMIN');

-- Assignation des permissions au rôle ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN'
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Insertion conditionnelle du rôle USER
INSERT INTO roles (name, description)
SELECT 'ROLE_USER', 'Utilisateur standard avec accès basique'
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'ROLE_USER');

-- Assignation de la permission basic_access au rôle USER
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_USER' AND p.name = 'basic_access'
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);*/


--TRUNCATE TABLE role_permissions, roles, permissions CASCADE;
