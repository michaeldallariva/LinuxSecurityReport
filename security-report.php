#!/usr/bin/env php
<?php
/**
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
 */

date_default_timezone_set('UTC');

// ----- Debug configuration -----
$DEBUG = true; // Set to false to disable debug output

function debug($message) {
    global $DEBUG;
    if ($DEBUG) {
        echo "[DEBUG] " . date('Y-m-d H:i:s') . " - $message\n";
    }
}

$MAX_SSH_EVENTS = 25;        // Recent SSH events to show
$MAX_HTTP_EVENTS = 25;       // Recent HTTP events to show  
$MAX_ERROR_EVENTS = 25;      // Recent error events to show
$MAX_TOP_ITEMS = 25;         // Items in "top" lists (IPs, paths, etc.)
$MAX_LOG_LINES = 2000;       // Max lines to read from log files
$MAX_TOP_IPS = 25;           // Top IPs to show
$MAX_TOP_PATHS = 25;         // Top paths to show  
$MAX_TOP_ERRORS = 25;        // Top error types to show
$SYSLOG_FILE = "/var/log/syslog";    // System log file
$MAX_SYSLOG_EVENTS = 50;      

class SecurityReportEmailSender {
    private $smtp_host = 'localhost';
    private $smtp_port = 25;
    private $from_email;
    private $from_name;
    
    public function __construct($from_email, $from_name = 'Security Report') {
        $this->from_email = $from_email;
        $this->from_name = $from_name;
    }
    
    public function sendEmail($to_email, $subject, $message, $is_html = true) {
        try {
            // Validate email address
            if (!filter_var($to_email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception('Invalid email address: ' . $to_email);
            }
            
            debug("SMTP: Connecting to {$this->smtp_host}:{$this->smtp_port}");
            
            // Create socket connection
            $socket = $this->createConnection();
            
            // Send SMTP commands
            $this->sendSMTPCommands($socket, $to_email, $subject, $message, $is_html);
            
            // Close connection
            fclose($socket);
            
            debug("SMTP: Email sent successfully to $to_email");
            
            return [
                'success' => true,
                'message' => 'Email sent successfully'
            ];
            
        } catch (Exception $e) {
            debug("SMTP ERROR: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Failed to send email: ' . $e->getMessage()
            ];
        }
    }
    
    private function createConnection() {
        $socket = @fsockopen($this->smtp_host, $this->smtp_port, $errno, $errstr, 30);
        
        if (!$socket) {
            throw new Exception("Cannot connect to SMTP server: $errstr ($errno)");
        }
        
        // Read initial response (220 Service ready)
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) !== '220') {
            throw new Exception('SMTP server not ready: ' . trim($response));
        }
        
        debug("SMTP: Connected, server response: " . trim($response));
        
        return $socket;
    }
    
    private function sendSMTPCommands($socket, $to_email, $subject, $message, $is_html) {
        // Send EHLO
        fputs($socket, "EHLO " . $this->smtp_host . "\r\n");
        $response = fgets($socket, 515);
        
        while (substr($response, 3, 1) === '-') {
            $response = fgets($socket, 515);
        }
        
        if (substr($response, 0, 3) !== '250') {
            throw new Exception('EHLO failed: ' . trim($response));
        }
        
        debug("SMTP: EHLO successful");
        
        // Send MAIL FROM
        fputs($socket, "MAIL FROM: <" . $this->from_email . ">\r\n");
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) !== '250') {
            throw new Exception('MAIL FROM failed: ' . trim($response));
        }
        
        debug("SMTP: MAIL FROM accepted");
        
        fputs($socket, "RCPT TO: <$to_email>\r\n");
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) !== '250') {
            throw new Exception("RCPT TO failed for $to_email: " . trim($response));
        }
        
        debug("SMTP: RCPT TO accepted");
        
        fputs($socket, "DATA\r\n");
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) !== '354') {
            throw new Exception('DATA command failed: ' . trim($response));
        }
        
        debug("SMTP: DATA command accepted, sending message");
        
        $headers = "From: " . $this->from_name . " <" . $this->from_email . ">\r\n";
        $headers .= "Reply-To: " . $this->from_email . "\r\n";
        $headers .= "To: $to_email\r\n";
        $headers .= "Subject: $subject\r\n";
        $headers .= "Date: " . date('r') . "\r\n";
        $headers .= "Message-ID: <" . uniqid() . "@" . $this->smtp_host . ">\r\n";
        $headers .= "X-Mailer: Security Report System\r\n";
        
        if ($is_html) {
            $headers .= "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
            $headers .= "Content-Transfer-Encoding: 8bit\r\n";
        } else {
            $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
        }
        
        $headers .= "\r\n";
        
        fputs($socket, $headers . $message . "\r\n.\r\n");
        
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) !== '250') {
            throw new Exception('Message sending failed: ' . trim($response));
        }
        
        debug("SMTP: Message accepted by server");
        
        // Send QUIT
        fputs($socket, "QUIT\r\n");
        $response = fgets($socket, 515);
        
        return trim($response);
    }
    
    public function testConnection() {
        try {
            debug("SMTP: Testing connection...");
            $socket = $this->createConnection();
            
            // Try EHLO
            fputs($socket, "EHLO " . $this->smtp_host . "\r\n");
            $response = fgets($socket, 515);
            
            // Read all EHLO responses
            while (substr($response, 3, 1) === '-') {
                $response = fgets($socket, 515);
            }
            
            if (substr($response, 0, 3) !== '250') {
                throw new Exception('EHLO test failed: ' . trim($response));
            }
            
            fputs($socket, "QUIT\r\n");
            fclose($socket);
            
            debug("SMTP: Connection test successful");
            
            return [
                'success' => true,
                'message' => 'SMTP connection test successful'
            ];
            
        } catch (Exception $e) {
            debug("SMTP: Connection test failed - " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'SMTP connection test failed: ' . $e->getMessage()
            ];
        }
    }
}

// ----- Fixed configuration (edit these) -----
$RECIPIENT = "YourEmailAddress@YourDomain.com";        // destination address
$HOSTNAME  = "YourServerName";                         // fixed FQDN to show in subject/report
$SENDER    = "YourSenderAddress@YourDomain.com";       // fixed From address (FQDN)
$SSH_LOG   = "/var/log/auth.log";                      // Debian/Ubuntu SSH auth log
$APACHE_LOG= "/var/log/apache2/access.log";            // Debian/Ubuntu Apache access log
$APACHE_SSL_LOG = "/var/log/apache2/ssl_access.log";   // if exists, will be read
$APACHE_ERROR_LOG = "/var/log/apache2/error.log";      // Apache error log

// Domain-specific Apache logs (add all your domains here)
$DOMAIN_LOGS = [
    // website1.com logs
    "/var/log/apache2/website1.com_access.log",
    "/var/log/apache2/website1.com_ssl_access.log",
    
    // website2.com logs  
    "/var/log/apache2/website2.com_access.log",
    "/var/log/apache2/website2-ssl_access.log",
    
    // website3.com logs
    "/var/log/apache2/website3.com_access.log",
	"/var/log/apache2/website3.com_ssl_access.log",
    
    // Add more websites as needed
    // "/var/log/apache2/yourdomain.com_access.log",
    // "/var/log/apache2/yourdomain.com_ssl_access.log",
];

$LOOKBACK_HOURS = 12; // scan last 12 hours

function readRecentLines($filepath, $hours) {
    debug("Attempting to read file: $filepath");
    $lines = [];
    if (!is_readable($filepath)) {
        debug("File not readable: $filepath");
        return $lines;
    }
    $fh = fopen($filepath, 'r');
    if (!$fh) {
        debug("Failed to open file: $filepath");
        return $lines;
    }

    $lineCount = 0;
    while (($line = fgets($fh)) !== false) {
        $lines[] = rtrim($line, "\r\n");
        $lineCount++;
    }
    fclose($fh);
    debug("Read $lineCount lines from $filepath");
    return $lines;
}

function parseSyslogTimestampToEpoch($prefix) {
    // Example: "Aug 28 21:54:03"
    $parts = explode(' ', trim($prefix));
    $parts = array_values(array_filter($parts, fn($p)=>$p!==''));
    if (count($parts) < 3) {
        debug("Invalid syslog timestamp format: '$prefix' (parts: " . count($parts) . ")");
        return null;
    }
    $month = $parts[0];
    $day   = $parts[1];
    $time  = $parts[2];
    $year  = (int)date('Y');
    $epoch = strtotime("$month $day $year $time");
    if ($epoch === false) {
        debug("Failed to parse timestamp: '$month $day $year $time'");
        return null;
    }

    if ($epoch - time() > 30*86400) {
        $epoch = strtotime("$month $day ".($year-1)." $time");
        debug("Adjusted timestamp to previous year: '$month $day ".($year-1)." $time'");
    }
    return $epoch ?: null;
}

function parseApacheTimeToEpoch($timeField) {
    // Example: [28/Aug/2025:21:54:03 +0000]
    $timeField = trim($timeField, '[]');
    $epoch = strtotime($timeField);
    return $epoch ?: null;
}

function htmlEscape($s) {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function topN($assoc, $n=10) {
    arsort($assoc);
    return array_slice($assoc, 0, $n, true);
}

function parseApacheErrorLog($filepath, $cutoff) {
    global $MAX_LOG_LINES, $MAX_ERROR_EVENTS;
	
    debug("=== Starting Apache error log parsing ===");
    debug("Attempting to read file: $filepath");
    
    $error_events = [];
    $error_types = [];
    $error_ips = [];
    $suspicious_patterns = [
        'File does not exist',
        'script not found or unable to stat',
        'Invalid URI in request',
        'PHP Fatal error',
        'PHP Parse error', 
        'PHP Warning',
        'segmentation fault',
        'ModSecurity',
        'suspicious',
        'attack',
        'exploit',
        'injection',
        'admin',
        'wp-admin',
        '.env',
        'config.php'
    ];
	
   
    if (!is_readable($filepath)) {
        debug("Apache error log not readable: $filepath");
        return ['events' => [], 'types' => [], 'ips' => []];
    }
    
    $lines = [];
    $fh = fopen($filepath, 'r');
    if (!$fh) {
        debug("Failed to open Apache error log: $filepath");
        return ['events' => [], 'types' => [], 'ips' => []];
    }
    
    $cmd = "tail -$MAX_LOG_LINES " . escapeshellarg($filepath);
    $output = shell_exec($cmd);
    if ($output) {
        $lines = explode("\n", trim($output));
    }
    fclose($fh);
    
    debug("Processing " . count($lines) . " error log lines");
    
    $processed = 0;
    $matched = 0;
    $in_window = 0;
    
    foreach ($lines as $line) {
        $processed++;
        if (empty(trim($line))) continue;
        
		if (preg_match('/^\[([^\]]+)\]\s+\[([^\]]+)\](?:\s+\[([^\]]+)\])?\s+(.*)$/', $line, $m)) {
			$timestamp_str = $m[1];
			$level = $m[2];
			$pid_info = $m[3] ?? '';  // Optional pid:tid section
			$message = $m[4];
            
            // Parse timestamp
            $ts = strtotime($timestamp_str);
            if ($ts === false || $ts < $cutoff) {
                continue;
            }
            $in_window++;
            
            // Extract IP if present
            $ip = null;
            if (preg_match('/client\s+([0-9a-fA-F\:\.]+)/', $message, $ip_match)) {
                $ip = $ip_match[1];
                $error_ips[$ip] = ($error_ips[$ip] ?? 0) + 1;
            }
            
            $is_suspicious = false;
            $matched_pattern = '';
            foreach ($suspicious_patterns as $pattern) {
                if (stripos($message, $pattern) !== false) {
                    $is_suspicious = true;
                    $matched_pattern = $pattern;
                    break;
                }
            }
            
            if ($is_suspicious || in_array($level, ['error', 'crit', 'alert', 'emerg'])) {
                $error_events[] = [
                    'time' => $ts,
                    'level' => $level,
                    'ip' => $ip ?: '-',
                    'message' => substr($message, 0, 200), // Limit message length
                    'pattern' => $matched_pattern,
                    'suspicious' => $is_suspicious
                ];
            }
            
            $error_types[$level] = ($error_types[$level] ?? 0) + 1;
        }
    }
    
    debug("Apache error parsing complete:");
    debug("- Lines processed: $processed");
    debug("- Lines matched pattern: $matched");
    debug("- Lines in time window: $in_window");
    debug("- Error events found: " . count($error_events));
    debug("- Error types: " . count($error_types));
    debug("- IPs with errors: " . count($error_ips));
    
    usort($error_events, fn($a,$b)=>$b['time']<=>$a['time']);
    $error_events = array_slice($error_events, 0, $MAX_ERROR_EVENTS);
    
    return [
        'events' => $error_events,
        'types' => $error_types,
        'ips' => $error_ips
    ];
}

function parseSyslogFile($filepath, $cutoff) {
    global $MAX_LOG_LINES, $MAX_SYSLOG_EVENTS;
    
    debug("=== Starting syslog parsing ===");
    debug("Attempting to read file: $filepath");
    
    $syslog_events = [];
    $syslog_services = [];
    $syslog_levels = [];
    $suspicious_patterns = [
        'error',
        'failed',
        'failure',
        'critical',
        'warning',
        'denied',
        'blocked',
        'timeout',
        'segfault',
        'panic',
        'killed',
        'oom-killer',
        'out of memory',
        'authentication failure',
        'connection refused',
		'CRON',           // Not suspicious but can be included for overview - Show cron jobs
		'postfix',        // Show mail activity  
		'systemd',        // Show systemd events
		'connect',        // Show connections
		'disconnect',     // Show disconnections
        'permission denied'
    ];
    
    if (!is_readable($filepath)) {
        debug("Syslog file not readable: $filepath");
        return ['events' => [], 'services' => [], 'levels' => []];
    }
    
    $cmd = "tail -$MAX_LOG_LINES " . escapeshellarg($filepath);
    $output = shell_exec($cmd);
    if (!$output) {
        debug("Failed to read syslog file: $filepath");
        return ['events' => [], 'services' => [], 'levels' => []];
    }
    
    $lines = explode("\n", trim($output));
    debug("Processing " . count($lines) . " syslog lines");
    
    $processed = 0;
    $matched = 0;
    $in_window = 0;
    
    foreach ($lines as $line) {
        $processed++;
        if (empty(trim($line))) continue;
        
           if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$/', $line, $m)) {
            $matched++;
            $timestamp_str = $m[1];
            $hostname = $m[2];
            $service = $m[3];
            $pid = $m[4] ?? '';
            $message = $m[5];
            
             $ts = parseSyslogTimestampToEpoch($timestamp_str);
            if ($ts === false || $ts < $cutoff) {
                continue;
            }
            $in_window++;
            
            $syslog_services[$service] = ($syslog_services[$service] ?? 0) + 1;
            
            $level = 'info'; // default
            if (stripos($message, 'error') !== false) $level = 'error';
            elseif (stripos($message, 'warning') !== false || stripos($message, 'warn') !== false) $level = 'warning';
            elseif (stripos($message, 'critical') !== false || stripos($message, 'crit') !== false) $level = 'critical';
            elseif (stripos($message, 'failed') !== false || stripos($message, 'failure') !== false) $level = 'error';
            
            $syslog_levels[$level] = ($syslog_levels[$level] ?? 0) + 1;
            
            $is_suspicious = false;
            $matched_pattern = '';
            foreach ($suspicious_patterns as $pattern) {
                if (stripos($message, $pattern) !== false) {
                    $is_suspicious = true;
                    $matched_pattern = $pattern;
                    break;
                }
            }
            
			if (true) { 
                $syslog_events[] = [
                    'time' => $ts,
                    'hostname' => $hostname,
                    'service' => $service,
                    'pid' => $pid,
                    'level' => $level,
                    'message' => substr($message, 0, 150), // Limit message length
                    'pattern' => $matched_pattern,
                    'suspicious' => $is_suspicious
                ];
            }
        }
    }
    
    debug("Syslog parsing complete:");
    debug("- Lines processed: $processed");
    debug("- Lines matched pattern: $matched");
    debug("- Lines in time window: $in_window");
    debug("- Syslog events found: " . count($syslog_events));
    debug("- Services: " . count($syslog_services));
    debug("- Log levels: " . count($syslog_levels));
    
    usort($syslog_events, fn($a,$b)=>$b['time']<=>$a['time']);
    $syslog_events = array_slice($syslog_events, 0, $MAX_SYSLOG_EVENTS);
    
    return [
        'events' => $syslog_events,
        'services' => $syslog_services,
        'levels' => $syslog_levels
    ];
}

$now = time();
$cutoff = $now - ($LOOKBACK_HOURS*3600);

debug("Current time: " . date('Y-m-d H:i:s', $now) . " UTC");
debug("Cutoff time: " . date('Y-m-d H:i:s', $cutoff) . " UTC (last $LOOKBACK_HOURS hours)");
debug("Configuration - SSH_LOG: $SSH_LOG");
debug("Configuration - APACHE_LOG: $APACHE_LOG");
debug("Configuration - APACHE_SSL_LOG: $APACHE_SSL_LOG");
debug("Configuration - DOMAIN_LOGS: " . count($DOMAIN_LOGS) . " additional logs");
debug("Configuration - RECIPIENT: $RECIPIENT");
debug("Configuration - SYSLOG_FILE: $SYSLOG_FILE");
debug("Configuration - APACHE_ERROR_LOG: $APACHE_ERROR_LOG");
debug("Configuration - HOSTNAME: $HOSTNAME");
debug("Configuration - SENDER: $SENDER");

debug("=== Starting SSH log parsing ===");
$ssh_lines = readRecentLines($SSH_LOG, $LOOKBACK_HOURS);
$ssh_events = [];
$ssh_ips = [];
$ssh_fail_ips = [];
$ssh_ok_ips = [];
$ssh_totals = ['accepted'=>0, 'failed'=>0, 'invalid'=>0, 'disconnected'=>0];

$ssh_processed = 0;
$ssh_matched = 0;
$ssh_in_window = 0;

foreach ($ssh_lines as $line) {
    $ssh_processed++;
    if (preg_match('/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.*)$/', $line, $m)) {
        $ssh_matched++;
        $ts = parseSyslogTimestampToEpoch($m[1]);
        if ($ts === null || $ts < $cutoff) {
            if ($ssh_matched <= 5) debug("SSH line outside time window or parse failed: " . substr($line, 0, 100));
            continue;
        }
        $ssh_in_window++;
        $msg = $m[2];

        $ip = null;
        if (preg_match('/from\s+([0-9a-fA-F\:\.]+)\s+port\s+\d+/', $msg, $mm)) {
            $ip = $mm[1];
        } elseif (preg_match('/rhost=([0-9a-fA-F\:\.]+)/', $msg, $mm)) {
            $ip = $mm[1];
        }

        $type = null;
        if (stripos($msg, 'Accepted') !== false) {
            $type = 'accepted';
            $ssh_totals['accepted']++;
            if ($ip) $ssh_ok_ips[$ip] = ($ssh_ok_ips[$ip] ?? 0) + 1;
        } elseif (stripos($msg, 'Failed password') !== false || stripos($msg, 'authentication failure') !== false) {
            $type = 'failed';
            $ssh_totals['failed']++;
            if ($ip) $ssh_fail_ips[$ip] = ($ssh_fail_ips[$ip] ?? 0) + 1;
        } elseif (stripos($msg, 'Invalid user') !== false) {
            $type = 'invalid';
            $ssh_totals['invalid']++;
            if ($ip) $ssh_fail_ips[$ip] = ($ssh_fail_ips[$ip] ?? 0) + 1;
        } elseif (stripos($msg, 'Disconnected from') !== false) {
            $type = 'disconnected';
            $ssh_totals['disconnected']++;
        }

        if ($ip) $ssh_ips[$ip] = ($ssh_ips[$ip] ?? 0) + 1;

        if ($type) {
            $ssh_events[] = [
                'time' => $ts,
                'ip'   => $ip ?: '-',
                'type' => $type,
                'msg'  => $msg,
            ];
        }
    }
}

debug("SSH parsing complete:");
debug("- Lines processed: $ssh_processed");
debug("- Lines matched SSH pattern: $ssh_matched");
debug("- Lines in time window: $ssh_in_window");
debug("- Events found: " . count($ssh_events));
debug("- Accepted: {$ssh_totals['accepted']}, Failed: {$ssh_totals['failed']}, Invalid: {$ssh_totals['invalid']}, Disconnected: {$ssh_totals['disconnected']}");
debug("- Unique IPs: " . count($ssh_ips) . ", Failed IPs: " . count($ssh_fail_ips));

debug("=== Starting Apache log parsing ===");
$apache_lines = [];

foreach ([$APACHE_LOG, $APACHE_SSL_LOG] as $p) {
    if (is_readable($p)) {
        $lines = readRecentLines($p, $LOOKBACK_HOURS);
        $apache_lines = array_merge($apache_lines, $lines);
        debug("Added " . count($lines) . " lines from $p");
    } else {
        debug("Apache log not readable: $p");
    }
}

$domain_data = [];
foreach ($DOMAIN_LOGS as $p) {
    if (is_readable($p)) {
        $lines = readRecentLines($p, $LOOKBACK_HOURS);
        debug("Added " . count($lines) . " lines from $p");
        
        $re1 = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]*?)\s+HTTP\/[0-9.]+"\s+(\d{3})\s+(\S+)/';
        $re2 = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\S+)/';
        
        $domain_name = basename($p);
		if (strpos($domain_name, '-ssl_access.log') !== false) {
			$domain_name = str_replace('-ssl_access.log', '_ssl', $domain_name);
		} elseif (strpos($domain_name, '_ssl_access.log') !== false) {
			$domain_name = str_replace('_ssl_access.log', '_ssl', $domain_name);
		} elseif (strpos($domain_name, '.com_access.log') !== false) {
			$domain_name = str_replace('.com_access.log', '', $domain_name);
		} elseif (strpos($domain_name, '_access.log') !== false) {
			$domain_name = str_replace('_access.log', '', $domain_name);
		}
		$domain_name = str_replace('.com', '', $domain_name);
        
        $domain_http_ips = [];
        $domain_http_paths = [];
        $domain_http_events = [];
        $domain_http_totals = 0;
        
        foreach ($lines as $line) {
            // Use the same parsing logic as before
            $ip = $tstr = $method = $path = '';
            $status = null;

            if (preg_match($re1, $line, $m) === 1) {
                $ip     = $m[1];
                $tstr   = $m[2];
                $method = $m[3];
                $path   = $m[4];
                $status = (int)$m[5];
            } elseif (preg_match($re2, $line, $m) === 1) {
                $ip   = $m[1];
                $tstr = $m[2];
                $rq   = $m[3];
                $parts = preg_split('/\s+/', $rq);
                if (count($parts) >= 2) {
                    $method = strtoupper($parts[0]);
                    if (preg_match('/HTTP\/[0-9.]+$/', end($parts))) {
                        array_pop($parts);
                    }
                    $path = implode(' ', array_slice($parts, 1));
                } else {
                    continue;
                }
                $status = (int)$m[4];
            } else {
                continue;
            }

            $ts = parseApacheTimeToEpoch($tstr);
            if ($ts === null || $ts < $cutoff) {
                continue;
            }

            $domain_http_totals++;
            $domain_http_ips[$ip] = ($domain_http_ips[$ip] ?? 0) + 1;
            $pkey = ($path === '' ? '/' : $path);
            $domain_http_paths[$pkey] = ($domain_http_paths[$pkey] ?? 0) + 1;

            $domain_http_events[] = [
                'time' => $ts,
                'ip'   => $ip,
                'method'=> $method,
                'path' => $pkey,
                'status'=> $status
            ];
        }
        
        usort($domain_http_events, fn($a,$b)=>$b['time']<=>$a['time']);
        $domain_http_events = array_slice($domain_http_events, 0, $MAX_HTTP_EVENTS);
        
        $domain_data[$domain_name] = [
            'totals' => $domain_http_totals,
            'ips' => topN($domain_http_ips, $MAX_TOP_IPS),
            'paths' => topN($domain_http_paths, $MAX_TOP_PATHS),
            'events' => $domain_http_events,
            'log_file' => basename($p)
        ];
        
        $apache_lines = array_merge($apache_lines, $lines);
    } else {
        debug("Domain log not readable: $p");
    }
}

debug("Total Apache log lines collected: " . count($apache_lines));

$re1 = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]*?)\s+HTTP\/[0-9.]+"\s+(\d{3})\s+(\S+)/';

$re2 = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\S+)/';

$http_totals = 0;
foreach ($domain_data as $data) {
    $http_totals += $data['totals'];
}

debug("Apache parsing complete:");
debug("- Total HTTP requests across all domains: $http_totals");
debug("- Domains processed: " . count($domain_data));

debug("Apache parsing complete:");
debug("=== Starting Apache error log analysis ===");
$apache_errors = parseApacheErrorLog($APACHE_ERROR_LOG, $cutoff);
$error_events = $apache_errors['events'];
$error_types = $apache_errors['types'];
$error_ips = $apache_errors['ips'];

$top_error_types = topN($error_types, 10);
$top_error_ips = topN($error_ips, 10);

debug("=== Apache error log summary ===");
debug("=== Starting syslog analysis ===");
$syslog_data = parseSyslogFile($SYSLOG_FILE, $cutoff);
$syslog_events = $syslog_data['events'];
$syslog_services = $syslog_data['services'];
$syslog_levels = $syslog_data['levels'];

$top_syslog_services = topN($syslog_services, $MAX_TOP_ITEMS);
$top_syslog_levels = topN($syslog_levels, $MAX_TOP_ITEMS);

debug("=== Syslog summary ===");
debug("Syslog events found: " . count($syslog_events));
debug("Services: " . count($syslog_services));
debug("Log levels: " . count($syslog_levels));
debug("Error events found: " . count($error_events));
debug("Error types: " . count($error_types));
debug("IPs with errors: " . count($error_ips));
foreach ($domain_data as $domain_name => $data) {
    debug("- $domain_name: {$data['totals']} requests, " . count($data['ips']) . " unique IPs, " . count($data['paths']) . " unique paths");
}


usort($ssh_events, fn($a,$b)=>$b['time']<=>$a['time']);
$ssh_events = array_slice($ssh_events, 0, $MAX_SSH_EVENTS);

$top_ssh_ips = topN($ssh_ips, $MAX_TOP_IPS);
$top_ssh_fail_ips = topN($ssh_fail_ips, $MAX_TOP_IPS);

debug("=== Report summary ===");
debug("Recent SSH events: " . count($ssh_events));
debug("Recent HTTP events: " . count($http_events));
debug("Top SSH IPs: " . count($top_ssh_ips));
debug("Top HTTP IPs: " . count($top_http_ips));

$style = "
    body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color:#222; }
    h1 { font-size:18px; }
    h2 { font-size:16px; margin-top:24px; }
    table { border-collapse: collapse; width: 100%; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; }
    th { background: #f6f8fa; text-align: left; }
	.section-header { background-color: #e3f2fd; color: #1565c0; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .muted { color:#666; font-size:12px; }
    .ok { color:#0a7f3f; }
    .warn { color:#b15e00; }
    .bad { color:#b00020; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
";

$nowStr = gmdate('Y-m-d H:i:s') . " UTC";
$subject = "[Security Report] $HOSTNAME ports 22/80/443 - $nowStr";

ob_start();
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title><?= htmlEscape($subject) ?></title>
<style><?= $style ?></style>
</head>
<body>
<h1>Security Activity Report for <?= htmlEscape($HOSTNAME) ?></h1>
<p class="muted">Generated at <?= htmlEscape($nowStr) ?>; last <?= (int)$LOOKBACK_HOURS ?> hours window.</p>

<h2><span class="section-header">SSH (port 22)</span></h2>
<ul>
  <li>Total accepted: <span class="ok"><?= (int)$ssh_totals['accepted'] ?></span></li>
  <li>Total failed: <span class="bad"><?= (int)$ssh_totals['failed'] ?></span></li>
  <li>Invalid users: <span class="warn"><?= (int)$ssh_totals['invalid'] ?></span></li>
  <li>Disconnected notices: <?= (int)$ssh_totals['disconnected'] ?></li>
</ul>

<table>
  <thead><tr><th>Top SSH source IPs</th><th>Count</th></tr></thead>
  <tbody>
  <?php foreach ($top_ssh_ips as $ip=>$cnt): ?>
    <tr><td class="mono"><?= htmlEscape($ip) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>

<table>
  <thead><tr><th>Top SSH failed IPs</th><th>Failures</th></tr></thead>
  <tbody>
  <?php foreach ($top_ssh_fail_ips as $ip=>$cnt): ?>
    <tr><td class="mono"><?= htmlEscape($ip) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>

<table>
  <thead><tr><th>Recent SSH events</th><th>IP</th><th>Type</th><th>When</th></tr></thead>
  <tbody>
  <?php foreach ($ssh_events as $e): ?>
    <tr>
      <td class="mono"><?= htmlEscape(substr($e['msg'], 0, 140)) ?></td>
      <td class="mono"><?= htmlEscape($e['ip']) ?></td>
      <td><?= htmlEscape($e['type']) ?></td>
      <td><?= htmlEscape(gmdate('Y-m-d H:i:s', $e['time'])) ?> UTC</td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<h2><span class="section-header">HTTP/HTTPS (ports 80/443) - Combined Overview</span></h2>
<ul>
  <li>Total requests (all sites): <?= (int)$http_totals ?></li>
</ul>

<?php if (!empty($domain_data)): ?>
  <?php foreach ($domain_data as $domain_name => $data): ?>
    <h3><span class="section-header"><?= htmlEscape(ucfirst($domain_name)) ?> Website</span></h3>
    <p class="muted">Source: <?= htmlEscape($data['log_file']) ?></p>
    
    <ul>
      <li>Requests: <?= (int)$data['totals'] ?></li>
    </ul>

    <table>
      <thead><tr><th>Top client IPs</th><th>Requests</th></tr></thead>
      <tbody>
      <?php foreach ($data['ips'] as $ip=>$cnt): ?>
        <tr><td class="mono"><?= htmlEscape($ip) ?></td><td><?= (int)$cnt ?></td></tr>
      <?php endforeach; ?>
      </tbody>
    </table>

    <table>
      <thead><tr><th>Top request paths</th><th>Requests</th></tr></thead>
      <tbody>
      <?php foreach ($data['paths'] as $path=>$cnt): ?>
        <tr><td class="mono"><?= htmlEscape($path) ?></td><td><?= (int)$cnt ?></td></tr>
      <?php endforeach; ?>
      </tbody>
    </table>

    <table>
      <thead><tr><th>Recent HTTP events</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>When</th></tr></thead>
      <tbody>
      <?php foreach ($data['events'] as $e): ?>
        <tr>
          <td></td>
          <td class="mono"><?= htmlEscape($e['ip']) ?></td>
          <td><?= htmlEscape($e['method']) ?></td>
          <td class="mono"><?= htmlEscape($e['path']) ?></td>
          <td><?= (int)$e['status'] ?></td>
          <td><?= htmlEscape(gmdate('Y-m-d H:i:s', $e['time'])) ?> UTC</td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  <?php endforeach; ?>
<?php endif; ?>

<h2><span class="section-header">Apache Error Log Analysis</span></h2>
<ul>
  <li>Total error events: <?= count($error_events) ?></li>
  <li>Error types found: <?= count($error_types) ?></li>
  <li>IPs with errors: <?= count($error_ips) ?></li>
</ul>

<?php if (!empty($top_error_types)): ?>
<table>
  <thead><tr><th>Error Types</th><th>Count</th></tr></thead>
  <tbody>
  <?php foreach ($top_error_types as $type=>$cnt): ?>
    <tr><td><?= htmlEscape($type) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($top_error_ips)): ?>
<table>
  <thead><tr><th>Top IPs with Errors</th><th>Errors</th></tr></thead>
  <tbody>
  <?php foreach ($top_error_ips as $ip=>$cnt): ?>
    <tr><td class="mono"><?= htmlEscape($ip) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($error_events)): ?>
<table>
  <thead><tr><th>Recent Error Events</th><th>Level</th><th>IP</th><th>Pattern</th><th>When</th></tr></thead>
  <tbody>
  <?php foreach ($error_events as $e): ?>
    <tr class="<?= $e['suspicious'] ? 'bad' : '' ?>">
      <td class="mono"><?= htmlEscape(substr($e['message'], 0, 80)) ?>...</td>
      <td><?= htmlEscape($e['level']) ?></td>
      <td class="mono"><?= htmlEscape($e['ip']) ?></td>
      <td><?= htmlEscape($e['pattern']) ?></td>
      <td><?= htmlEscape(gmdate('Y-m-d H:i:s', $e['time'])) ?> UTC</td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<h2><span class="section-header">System Log Analysis</span></h2>
<ul>
  <li>Total syslog events: <?= count($syslog_events) ?></li>
  <li>Services found: <?= count($syslog_services) ?></li>
  <li>Log levels: <?= count($syslog_levels) ?></li>
</ul>

<?php if (!empty($top_syslog_services)): ?>
<table>
  <thead><tr><th>Top Services</th><th>Events</th></tr></thead>
  <tbody>
  <?php foreach ($top_syslog_services as $service=>$cnt): ?>
    <tr><td><?= htmlEscape($service) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($top_syslog_levels)): ?>
<table>
  <thead><tr><th>Log Levels</th><th>Count</th></tr></thead>
  <tbody>
  <?php foreach ($top_syslog_levels as $level=>$cnt): ?>
    <tr><td><?= htmlEscape($level) ?></td><td><?= (int)$cnt ?></td></tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($syslog_events)): ?>
<table>
  <thead><tr><th>Recent System Events</th><th>Service</th><th>Level</th><th>Pattern</th><th>When</th></tr></thead>
  <tbody>
  <?php foreach ($syslog_events as $e): ?>
    <tr class="<?= $e['suspicious'] ? 'bad' : '' ?>">
      <td class="mono"><?= htmlEscape(substr($e['message'], 0, 150)) ?>...</td>
      <td><?= htmlEscape($e['service']) ?></td>
      <td><?= htmlEscape($e['level']) ?></td>
      <td><?= htmlEscape($e['pattern']) ?></td>
      <td><?= htmlEscape(gmdate('Y-m-d H:i:s', $e['time'])) ?> UTC</td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<p class="muted">Sources: SSH from <?= htmlEscape($SSH_LOG) ?>; Domain-specific logs processed separately; Apache errors from <?= htmlEscape($APACHE_ERROR_LOG) ?>; System log from <?= htmlEscape($SYSLOG_FILE) ?>.</p>
</body>
</html>
<?php
$html = ob_get_clean();

debug("=== Sending email ===");
debug("HTML report length: " . strlen($html) . " bytes");
debug("Subject: $subject");

$emailSender = new SecurityReportEmailSender($SENDER, "Security Report System");

$connectionTest = $emailSender->testConnection();
if (!$connectionTest['success']) {
    debug("WARNING: SMTP connection test failed: " . $connectionTest['message']);
    debug("Continuing with email send attempt anyway...");
}

$result = $emailSender->sendEmail($RECIPIENT, $subject, $html, true);

if ($result['success']) {
    debug("SUCCESS: " . $result['message']);
} else {
    debug("ERROR: " . $result['message']);
    file_put_contents('php://stderr', "Email sending failed: " . $result['message'] . "\n");
    exit(1);
}

debug("=== Script completed ===");
?>