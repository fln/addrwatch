CREATE TABLE IF NOT EXISTS `origin` (
	`id` INT(11) NOT NULL,
	`name` VARCHAR(16) NOT NULL,
	`description` VARCHAR(255) NOT NULL,
	PRIMARY KEY (`id`)
);
INSERT INTO `origin`
	VALUES
	(0,'ARP_REQ','ARP Request packet'),
	(1,'ARP_REP','ARP Reply packet'),
	(2,'ARP_ACD','ARP Address collision detection packet'),
	(3,'ND_NS','Neighbor Solicitation packet'),
	(4,'ND_NA','Neighbor Advertisement packet'),
	(5,'ND_DAD','Duplicate Address Detection packet');

ALTER TABLE `addrwatch`
	CHANGE `tstamp` `tstamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHANGE `hostname` `hostname` varchar(255) NOT NULL DEFAULT 'localhost',
	CHANGE `vlan_tag` `vlan_tag` int(11) NOT NULL DEFAULT '0',
	CHANGE `mac_address` `mac_address_old` varchar(17) NOT NULL,
	CHANGE `ip_address` `ip_address_old` varchar(42) NOT NULL,
	ADD `mac_address` binary(6) NOT NULL,
	ADD `ip_address` varbinary(16) NOT NULL,
	ADD `origin_id` int(11) NOT NULL,
	ADD KEY `mac_address` (`mac_address`);

UPDATE addrwatch
	LEFT JOIN origin AS o ON o.name = origin
	SET
	mac_address = UNHEX(REPLACE(mac_address_old,':','')),
	ip_address = INET6_ATON(ip_address_old),
	origin_id = o.id;

ALTER TABLE `addrwatch`
	DROP mac_address_old,
	DROP ip_address_old,
	DROP origin,
	RENAME log;

CREATE VIEW `log_plaintext` AS
	SELECT
		`l`.`tstamp` AS `tstamp`,
		`l`.`hostname` AS `hostname`,
		`l`.`interface` AS `interface`,
		`l`.`vlan_tag` AS `vlan_tag`,
		HEX(`l`.`mac_address`) AS `mac_address`,
		HEX(`l`.`ip_address`) AS `ip_address`,
		`o`.`name` AS `origin`
	FROM `log` AS `l`
	JOIN `origin` AS `o` ON `o`.`id` = `l`.`origin_id`;
