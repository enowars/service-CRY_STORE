create table if not exists 
flags(
	--id integer given by rowid
	tick integer,
	key BLOB,
	encoded BLOB
);
