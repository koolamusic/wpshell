# Wp Shell Script
This Script will initialize a new wordpress development folder on a local or production server, and will setup your MySQL Database without the need for phpmyadmin or any other MySQL Management Tool.
Also includes some security configuration, and htaccess hardening to secure your wordpress install. Now you can deploy wordpress sites with ease


### Prerequisite 
- Linux (Ubuntu preferably)
- Git Installed 
- Apache Setup 
- PHP 5.4 or more Installed 
- MySQL Database Installed


### Getting Started
- `cd` into your configured virtual host directory, in some distros this is `var/www/html/ OR /var/www/*`
- clone this repository `git clone https://github.com/tecmie/wpshell`
- get into the directory using `cd wpshell`
- make the shell script executable `chmod +x install.sh`
- run the script `bash install.sh`

#### Install 2 
- Optionally you can run this script directly without git by pasting this into the command line or terminal 
`curl -L -o 'install.sh' https://raw.githubusercontent.com/tecmie/wpshell/master/install.sh && chmod +x install.sh && bash install.sh`


### Todo
Create configuration to work with [https://roots.io/bedrock/] a WordPress boilerplate with modern development tools, easier configuration, and an improved folder structure and dependency management with composer.


### Bugs and Errors
you can always use the github issues for any bugs or errors. 
