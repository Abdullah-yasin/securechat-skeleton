CREATE DATABASE securechat;
USE securechat;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwdhash CHAR(64) NOT NULL
);

SELECT username, HEX(salt), pwdhash FROM users;
