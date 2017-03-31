CREATE TABLE user (
	username VARCHAR(255),
	enc_password VARCHAR(255),
	isadmin BOOLEAN
);
INSERT INTO user VALUES ("admin", "***censored***", 1);
