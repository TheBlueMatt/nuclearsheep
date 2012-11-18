<?php
header("Content-Type: text/plain");

$conn = new mysqli($_ENV['OPENSHIFT_MYSQL_DB_HOST'], $_ENV['OPENSHIFT_MYSQL_DB_USERNAME'], $_ENV['OPENSHIFT_MYSQL_DB_PASSWORD'],
			"nuclearsheep", $_ENV['OPENSHIFT_MYSQL_DB_PORT']);
if ($result = $conn->query("SELECT url_regex, var_match, user_var, pass_var, displayname_var FROM regexps;")) {
	while ($next_row = $result->fetch_assoc()) {
		echo("\n".$next_row['url_regex']);
		echo("\n".$next_row['var_match']);
		echo("\n".$next_row['user_var']);
		echo("\n".$next_row['pass_var']);
		echo("\n".$next_row['displayname_var']);
	}
	$result->close();
}
?>
