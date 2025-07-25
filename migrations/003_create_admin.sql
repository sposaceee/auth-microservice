INSERT INTO auth_users (user_id, name, email, password_hash, role)
VALUES (
    '9218b941-d619-467d-a1be-aa04db9c3e93',  -- or use a static UUID if you prefer
    'Admin',
    'admin@example.com',
    '$2b$10$UHQhhTrRs/a9pIpkuBA9BeTldYmBOPWC48L4edHC.tP2j2.ndJi0a',
    'admin'
) ON CONFLICT (user_id) DO NOTHING;
