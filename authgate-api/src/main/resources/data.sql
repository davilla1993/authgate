
/*

-- 🔄 Nettoyage préalable si nécessaire
TRUNCATE TABLE role_permissions, roles, permissions RESTART IDENTITY CASCADE;

-- 🔐 Insertion des permissions statiques
INSERT INTO permissions (name, description, created_by)
VALUES
  ('USER_SELF_READ', 'Lire son propre profil', 'carlogbossou93@gmail.com'),
  ('USER_SELF_UPDATE', 'Modifier son propre profil', 'carlogbossou93@gmail.com'),
  ('USER_SELF_DELETE', 'Supprimer son propre profil', 'carlogbossou93@gmail.com'),
  ('BASIC_ACCESS', 'Accès basique à l\'application', 'carlogbossou93@gmail.com');

-- 🔐 Insertion des permissions dynamiques pour User.class
INSERT INTO permissions (name, description, created_by)
VALUES
  ('ADMIN_USER_CREATE', 'Gestion des utilisateurs (admin) - create', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_READ', 'Gestion des utilisateurs (admin) - read', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_UPDATE', 'Gestion des utilisateurs (admin) - update', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_DELETE', 'Gestion des utilisateurs (admin) - delete', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_LOCK', 'Gestion des utilisateurs (admin) - lock', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_UNLOCK', 'Gestion des utilisateurs (admin) - unlock', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_ASSIGN', 'Gestion des utilisateurs (admin) - assign', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_EXPORT', 'Gestion des utilisateurs (admin) - export', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_UPLOAD_PHOTO', 'Gestion des utilisateurs (admin) - upload_photo', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_DELETE_PHOTO', 'Gestion des utilisateurs (admin) - delete_photo', 'carlogbossou93@gmail.com'),
  ('ADMIN_USER_VIEW_PHOTO', 'Gestion des utilisateurs (admin) - view_photo', 'carlogbossou93@gmail.com');

-- 🔐 Insertion du rôle ROLE_USER
INSERT INTO roles (name, description, created_by)
VALUES ('ROLE_USER', 'Rôle utilisateur de base', 'carlogbossou93@gmail.com');

-- 🔐 Insertion du rôle ROLE_ADMIN
INSERT INTO roles (name, description, created_by)
VALUES ('ROLE_ADMIN', 'Rôle administrateur avec tous les droits', 'carlogbossou93@gmail.com');

-- 🧩 Association des permissions au rôle ROLE_USER
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_USER' AND p.name IN (
  'USER_SELF_READ',
  'USER_SELF_UPDATE',
  'USER_SELF_DELETE',
  'BASIC_ACCESS'
);

-- 🧩 Association des permissions au rôle ROLE_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN';


-- 🔐 Création de ADMIN
INSERT INTO users (
    email,
    password,
    first_name,
    last_name,
    enabled,
    created_by
) VALUES (
    'javaprogrammer1993@gmail.com',
    '$2a$12$xCvpxA4ZjxjMQlwO2rj96.W3BiYJmcDOR9WWZHuwSsODJNugx12li', -- Password@1234
    'Admin',
    'AuthGate',
    true,
    'carlogbossou93@gmail.com'
);

-- 🧩 Association de ROLE_ADMIN à ADMIN
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.email = 'javaprogrammer1993@gmail.com' AND r.name = 'ROLE_ADMIN';

*/

