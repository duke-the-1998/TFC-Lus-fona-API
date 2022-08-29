PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `Host` (
				`Address`	TEXT,
				`Name`	TEXT,
				PRIMARY KEY(`Address`)
		);
INSERT INTO Host VALUES('94.46.171.146',NULL);
CREATE TABLE `Port` (
				`Address`	TEXT,
				`Nr`	INTEGER,
				`Protocol`	TEXT,
				`Description`	TEXT,
				`State`	TEXT,
				`SSL`	INTEGER,
				PRIMARY KEY(`Address`,`Nr`, `Protocol`)
			);
INSERT INTO Port VALUES('94.46.171.146',22,'tcp','ssh','open',0);
INSERT INTO Port VALUES('94.46.171.146',80,'tcp','http','open',0);
INSERT INTO Port VALUES('94.46.171.146',443,'tcp','http','open',1);
COMMIT;
