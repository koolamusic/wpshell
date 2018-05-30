#!/bin/bash -e
clear
echo "============================================"
echo "WordPress Install Script"
echo "============================================"
echo "Do you need to setup new MySQL database? (y/n)"
read -e setupmysql
if [ "$setupmysql" == y ] ; then
	echo "MySQL Admin User: "
	read -e mysqluser
	echo "MySQL Admin Password: "
	read -s mysqlpass
	echo "MySQL Host (Enter for default 'localhost'): "
	read -e mysqlhost
		mysqlhost=${mysqlhost:-localhost}
fi
echo "WP Database Name: "
read -e dbname
echo "WP Database User: "
read -e dbuser
echo "WP Database Password: "
read -s dbpass
echo "WP Database Table Prefix [numbers, letters, and underscores only] (Enter for default 'wp_'): "
read -e dbtable
	dbtable=${dbtable:-wp_}
echo "Do basic hardening of wp-config and htaccess? (y/n)"
read -e harden
if [ "$harden" == y ] ; then
	echo "Key for updating: "
	read -e hardenkey
fi
echo "Last chance - sure you want to run the install? (y/n)"
read -e run
if [ "$run" == y ] ; then
	if [ "$setupmysql" == y ] ; then
		echo "============================================"
		echo "Setting up the database."
		echo "============================================"
		#login to MySQL, add database, add user and grant permissions
		dbsetup="create database $dbname;GRANT ALL PRIVILEGES ON $dbname.* TO $dbuser@$mysqlhost IDENTIFIED BY '$dbpass';FLUSH PRIVILEGES;"
		mysql -u $mysqluser -p$mysqlpass -e "$dbsetup"
		if [ $? != "0" ]; then
			echo "============================================"
			echo "[Error]: Database creation failed. Aborting."
			echo "============================================"
			exit 1
		fi
	fi
	echo "============================================"
	echo "Installing WordPress for you."
	echo "============================================"
	#download wordpress
	echo "Downloading..."
	curl -O https://wordpress.org/latest.tar.gz
	#unzip wordpress
	echo "Unpacking..."
	tar -zxf latest.tar.gz
	#move /wordpress/* files to this dir
	echo "Moving..."
	mv wordpress/* ./
	echo "Configuring..."
	#create wp config
	mv wp-config-sample.php wp-config.php
	#set database details with perl find and replace
	perl -pi -e "s'database_name_here'"$dbname"'g" wp-config.php
	perl -pi -e "s'username_here'"$dbuser"'g" wp-config.php
	perl -pi -e "s'password_here'"$dbpass"'g" wp-config.php
	perl -pi -e "s/\'wp_\'/\'$dbtable\'/g" wp-config.php
	#set WP salts
	perl -i -pe'
	  BEGIN {
	    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
	    push @chars, split //, "!@#$%^&*()-_ []{}<>~\`+=,.;:/?|";
	    sub salt { join "", map $chars[ rand @chars ], 1 .. 64 }
	  }
	  s/put your unique phrase here/salt()/ge
	' wp-config.php
	#create uploads folder and set permissions
	mkdir wp-content/uploads
	chmod 775 wp-content/uploads
	if [ "$harden" == y ] ; then
		echo "============================================"
		echo "Hardening."
		echo "============================================"
		#remove readme.html
		rm readme.html
		#debug extras
		perl -pi -e "s/define\('WP_DEBUG', false\);/define('WP_DEBUG', false);\n\/** Useful extras *\/ \nif (WP_DEBUG) { \n\tdefine('WP_DEBUG_LOG', true); \n\tdefine('WP_DEBUG_DISPLAY', false); \n\t\@ini_set('display_errors',0);\n}/" wp-config.php
		# key access to mods
			find="/* That's all, stop editing! Happy blogging. */"
			replace="/** Disallow theme and plugin editor in admin. Updates only with query var */\ndefine( 'DISALLOW_FILE_EDIT', true );\nif ( \\$\_REQUEST['key'] == '$hardenkey' ) {\n\tsetcookie( 'updatebypass', 1 );\n} elseif ( ! \\$\_COOKIE['updatebypass'] ) {\n\tdefine( 'DISALLOW_FILE_MODS', true );\n}\n\n/* That's all, stop editing! Happy blogging. */"
		perl -pi -e "s{\Q$find\E}{$replace}" wp-config.php
		#create root .htaccess with some useful starters
		cat > .htaccess <<'EOL'
# Protect this file
<Files ~ "^\.ht">
Order allow,deny
Deny from all
</Files>



# Prevent directory listing
Options -Indexes



## BEGIN 6G Firewall from https://perishablepress.com/6g/
# 6G:[QUERY STRINGS]
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000}) [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST METHOD]
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|delete|move|put|trace|track) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REFERRERS]
<IfModule mod_rewrite.c>
	RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000}) [NC,OR]
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
	RewriteRule .* - [F]
</IfModule>

# 6G:[REQUEST STRINGS]
<IfModule mod_alias.c>
	RedirectMatch 403 (?i)([a-z0-9]{2000})
	RedirectMatch 403 (?i)(https?|ftp|php):/
	RedirectMatch 403 (?i)(base64_encode)(.*)(\()
	RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
	RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&amp;?)/?$
	RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
	RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\s|\{|\}|\[|\]|\|)
	RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|etc/passwd|muieblack)
	RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
	RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
	RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
</IfModule>

# 6G:[USER AGENTS]
<IfModule mod_setenvif.c>
	SetEnvIfNoCase User-Agent ([a-z0-9]{2000}) bad_bot
	SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot
	<limit GET POST PUT>
		Order Allow,Deny
		Allow from All
		Deny from env=bad_bot
	</limit>
</IfModule>

# 6G:[BAD IPS]
<Limit GET HEAD OPTIONS POST PUT>
	Order Allow,Deny
	Allow from All
	# uncomment/edit/repeat next line to block IPs
	# Deny from 123.456.789
</Limit>

## END 6G Firewall



## BEGIN htauth basic authentication

# STAGING
Require all denied
AuthType Basic
AuthUserFile /etc/apache2/wp-login
AuthName "Please Authenticate"
Require valid-user

# LIVE - prevent wp-login brute force attacks from causing load
#<FilesMatch "^(wp-login|xmlrpc)\.php$">
#	AuthType Basic
#	AuthUserFile /etc/apache2/wp-login
#	AuthName "Please Authenticate"
#	Require valid-user
#</FilesMatch>

# Exclude the file upload and WP CRON scripts from authentication
#<FilesMatch "(async-upload\.php|wp-cron\.php)$">
#	Satisfy Any
#	Order allow,deny
#	Allow from all
#	Deny from none
#</FilesMatch>

## END htauth



## BEGIN WP file protection

<Files wp-config.php>
	order allow,deny
	deny from all
</Files>

# WP includes directories
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /
	RewriteRule ^wp-admin/includes/ - [F,L]
	RewriteRule !^wp-includes/ - [S=3]
	# note - comment out next line on multisite
	RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
	RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
	RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

## END WP file protection



# Prevent author enumeration
RewriteCond %{REQUEST_URI} !^/wp-admin [NC]
RewriteCond %{QUERY_STRING} author=\d
RewriteRule ^ /? [L,R=301]
EOL
		#create .htaccess to protect uploads directory
		cat > wp-content/uploads/.htaccess <<'EOL'
# Protect this file
<Files .htaccess>
Order Deny,Allow
Deny from All
</Files>



# whitelist file extensions to prevent executables being
# accessed if they get uploaded
order deny,allow
deny from all
<Files ~ ".(docx?|xlsx?|pptx?|txt|pdf|xml|css|jpe?g|png|gif)$">
allow from all
</Files>
EOL
	fi
	echo "Cleaning..."
	#remove wordpress/ dir
	rmdir wordpress
	#remove zip file
	rm latest.tar.gz
	#remove bash script if it exists in this dir
	[[ -f "install.sh" ]] && rm "install.sh"
	echo "========================="
	echo "[Success]: Installation is complete."
	echo "========================="
else
	exit
fi

