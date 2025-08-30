 * Purpose : 
 * Linux security and activity report for ports 22, 80, 443.
 * - SSH log from /var/log/auth.log
 * - Report log from /var/log/syslog"
 * - Apache log from /var/log/apache2/access.log and /var/www/yourwebsite(s)...
 * Sends HTML email via local SMTP with integrated email sending class.
 * Useful for personal single Linux servers/Online VPS
 * 
 * Author : Michael DALLA RIVA - 30-Aug-2025
 * 
 * CRON - Runs 6 times a day from 8am to 10pm/Adapt to your needs : 0 08,10,14,16,18,20 * * * /usr/bin/php /usr/local/bin/security-report.php
 * Run once : /usr/local/bin# php security-report.php
 * 
 * Considerations : Preferable not to use the ROOT account on a regular basis and use a dedicated account per user with the minimum rights required when required only.
 * Connecting to port 22 using a username and password is not recommended either. Best practice is to use a SSH key instead of a password.

