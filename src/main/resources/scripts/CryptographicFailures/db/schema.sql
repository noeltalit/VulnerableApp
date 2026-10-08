-- Table is seeded by CryptographicFailuresSeeder in vulnerability.service.cryptographicFailures

DROP TABLE IF EXISTS cryptographic_failures_vault;

CREATE TABLE cryptographic_failures_vault (
    level INT PRIMARY KEY ,
    password VARCHAR(500),
    algorithm VARCHAR(50)
);

-- Application user has full access (for functional purposes)
GRANT ALL ON cryptographic_failures_vault TO application;
