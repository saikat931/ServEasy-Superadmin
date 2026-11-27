<?php
/**
 * Standalone Database Connection Fallback for Split-Domain Super Admin Portal
 * Automatically connects to MySQL database whether running locally (XAMPP)
 * or standalone on Hostinger (e.g. inviting-royalblue-gerbil-79.hostingersite.com).
 */
date_default_timezone_set('Asia/Kolkata');

if (!class_exists('Database')) {
    class Database
    {
        private static ?PDO $pdo = null;

        private static function loadEnvFiles(): array
        {
            $vars = [];
            $rootDir = dirname(__DIR__);
            $parentDir = dirname($rootDir);
            $envFiles = [
                $rootDir . '/.env',
                $rootDir . '/host.env',
                $rootDir . '/db.env',
                $rootDir . '/.env.local',
                $parentDir . '/.env',
                $parentDir . '/host.env',
                $parentDir . '/db.env',
            ];
            foreach ($envFiles as $envFile) {
                if (!@file_exists($envFile) || !@is_readable($envFile)) {
                    continue;
                }
                $lines = @file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if (!is_array($lines)) {
                    continue;
                }
                foreach ($lines as $line) {
                    $trimmed = ltrim(trim($line), "\xEF\xBB\xBF");
                    if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                        continue;
                    }
                    if (str_contains($trimmed, '=')) {
                        [$k, $v] = explode('=', $trimmed, 2);
                        $key = ltrim(trim($k), "\xEF\xBB\xBF");
                        $val = trim($v, " \t\n\r\0\x0B\"'");
                        if ($key !== '' && (!isset($vars[$key]) || $vars[$key] === '')) {
                            $vars[$key] = $val;
                            $_ENV[$key] = $val;
                        }
                    }
                }
            }
            return $vars;
        }

        private static function getVar(array $vars, array $keys, string $default = ''): string
        {
            foreach ($keys as $k) {
                if (!empty($vars[$k])) return (string)$vars[$k];
                if (!empty($_ENV[$k])) return (string)$_ENV[$k];
                if (!empty($_SERVER[$k])) return (string)$_SERVER[$k];
                $g = getenv($k);
                if ($g !== false && $g !== '') return (string)$g;
            }
            return $default;
        }

        public static function connect(): PDO
        {
            if (self::$pdo !== null) {
                return self::$pdo;
            }

            $vars = self::loadEnvFiles();

            $httpHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $isLocal = in_array($httpHost, ['localhost', '127.0.0.1', '::1']) || str_starts_with($httpHost, 'localhost:');

            $dbHost = self::getVar($vars, ['DB_HOST'], $isLocal ? '127.0.0.1' : 'localhost');
            $dbPort = self::getVar($vars, ['DB_PORT'], '3306');
            $dbName = self::getVar($vars, ['DB_DATABASE', 'DB_NAME'], $isLocal ? 'serveasy_v2' : 'u923365340_serveasy');
            $dbUser = self::getVar($vars, ['DB_USERNAME', 'DB_USER'], $isLocal ? 'root' : 'u923365340_serveasy');
            $dbPass = self::getVar($vars, ['DB_PASSWORD', 'DB_PASS'], $isLocal ? '' : 'Serveasy@931');

            $dsn = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4";
            self::$pdo = new PDO($dsn, $dbUser, $dbPass, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);

            // Auto-heal id_verifications schema if verification_id lacks AUTO_INCREMENT / Primary Key
            try {
                $chk = self::$pdo->query("SHOW COLUMNS FROM `id_verifications` WHERE `Field` = 'verification_id'")->fetch(PDO::FETCH_ASSOC);
                if ($chk && empty($chk['Key'])) {
                    self::$pdo->exec("UPDATE `id_verifications` SET `verification_id` = 1 WHERE `verification_id` = 0");
                    self::$pdo->exec("ALTER TABLE `id_verifications` MODIFY COLUMN `verification_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, ADD PRIMARY KEY (`verification_id`)");
                }
            } catch (\Throwable $migErr) {}

            return self::$pdo;
        }

        public static function getConnection(?string $dbName = null): PDO
        {
            return self::connect();
        }
    }

    if (!class_exists('App\Helpers\DB')) {
        class_alias('Database', 'App\Helpers\DB');
    }
}
