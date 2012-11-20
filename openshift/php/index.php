<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
  <title>Welcome to NuclearSheep</title>
</head>
<body>
  <h2>NuclearSheep</h2>
  <img src=Sheep_icon_05.jpg alt="SHEEP" /><br>
  This is a program designed to show off how rediculously easy simple SSLStrip-based attacks are to perform against many popular websites (including many banks!), even nearly 4 years after Moxie Marlinspike released <a href="http://www.thoughtcrime.org/software/sslstrip/">SSLStrip to the public</a><br>
  It currently only runs on Linux (as if SSLStrip weren't already easy enough on Linux...) but work is ongoing to get it working on Windows.<br>
<!--Yes, I know this is just an HTML comment, but if you can see this, you should be running linux and then SSLStrip is easy enough to pull off anyway...
  Before you can run it, you need libpcap, sslstrip (get these from your local package manager) and the Jpcap package for your OS (see <a href="http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/download.html">their download page</a>).<br>
  Grab <a href=nuclearsheep.jar>the jar</a> and run (as root) with java -jar nuclearsheep.jar<br>
  You can find a copy of the code at <a href="https://github.com/TheBlueMatt/nuclearsheep">GitHub</a>.<br>
-->
  <br>
  <br>
  <h3>FAQ</h3>
  <ol>
	<li>How do I protect myself online from attacks like these?<br>
		There are a number of things you should do as an internet user to ensure your own security online, like:<br>
		<ol>
			<li>Use the EFF's <a href="https://www.eff.org/https-everywhere">HTTPSEverywhere</a> browser extension in Firefox or Chrome.</li>
			<li>Don't browse secure sites (anything which requires you to enter a username and password) from insecure locations.<br>
				This means anywhere that doesn't have WPA2 wireless encryption or where you do not completely trust everyone on the same network as you.</li>
			<li>Use a different (randomly generated) password for every site you visit.<br>
				If you are human (and thus can't keep every password in your feebile little memory), use a Password Manager (like <a href="https://lastpass.com/">LastPass</a> or <a href="http://keepass.info">KeePass</a>).</li>
		</ol>
	</li>
	<li>I'm a webmaster on a site where people have to enter a username and password, what should I do?<br>
		Let's face it, many people are lazy and will completely ignore #3 above, so you need to make sure that people can't have their login information stolen from your site even if your site has no personal information on its users.<br>
		There are a number of things you should keep in mind when securing your website against simple SSLStrip attacks:<br>
		<ol>
			<li>Ensure that your entire site is HTTPS-enabled.<br>
				This means redirecting (301 Moved Permanently) anyone who accesses your site using regular HTTP to the HTTPS version so that browsers will cache this information.</li>
			<li>Ensure that your website has rules in HTTPSEverywhere (see <a href="https://www.eff.org/https-everywhere/rulesets">their page on creating rules</a>).</li>
			<li>Support <a href="https://en.wikipedia.org/wiki/SPDY">SPDY</a> for HTTPS 2.0 (specifically its requirement that all connections be over SSL/TLS).</li>
		</ol>
	</li>
	<li>I'm a webmaster on a site that stores some kind of personal information on its users, what should I do?<br>
		Wait...you aren't already secure against simple SSLStrip attacks??? You realize SSLStrip is nearly 4 years old now? What have you been doing this whole time?<br>
		Anyway...see the list above.
	</li>
  </ol>
</body>
</html>
