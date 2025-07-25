CREATE TABLE IF NOT EXISTS auth_users (
                                          user_id         UUID PRIMARY KEY,
                                          name            TEXT NOT NULL,
                                          email           TEXT UNIQUE NOT NULL,
                                          password_hash   TEXT NOT NULL,
                                          role TEXT  NOT NULL  DEFAULT 'admin' CHECK (role IN ('admin', 'user', 'moderator')),
                                            refresh_token   TEXT,
                                          refresh_token_expires TIMESTAMPTZ
);
