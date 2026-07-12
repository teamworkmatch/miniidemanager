<?php
// ============================================================================
// --- 1. SETUP SESSION, DIRECTORY & KEAMANAN SISTEM ---
// ============================================================================

// Memastikan session PHP aktif (dengan fallback ke temporary directory jika gagal)
if (session_status() === PHP_SESSION_NONE) {
    if (!@session_start()) {
        session_save_path(sys_get_temp_dir());
        session_id(bin2hex(random_bytes(16)));
        @session_start();
    }
}

// Menentukan direktori kerja utama dan path file konfigurasi internal
$target_dir = realpath(__DIR__);
$current_script = basename(__FILE__);
$users_file = $target_dir . DIRECTORY_SEPARATOR . '.app_users.php';
$lockout_file = $target_dir . DIRECTORY_SEPARATOR . '.app_lockout.php';
$config_file = $target_dir . DIRECTORY_SEPARATOR . '.app_config.php';
$plugins_file = $target_dir . DIRECTORY_SEPARATOR . '.app_plugins.php'; 
$plugins_dir = $target_dir . DIRECTORY_SEPARATOR . 'plugins'; 

// Membuat folder plugins jika belum tersedia
if (!is_dir($plugins_dir)) @mkdir($plugins_dir, 0755, true);

// Generate CSRF Token untuk mencegah serangan Cross-Site Request Forgery
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Pengaturan keamanan ekstensi file yang diizinkan dan dilarang keras
$allowed_upload_extensions = ''; 
$allowed_file_extensions = '';
$forbidden_exts = ['phtml', 'php3', 'php4', 'php5', 'phar', 'pht', 'htaccess', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'jsp', 'exe'];
$forbidden_filenames = ['.htaccess', '.user.ini', 'php.ini', '.htpasswd'];
$trust_proxy_header = false;

// Fungsi untuk mendapatkan IP asli klien
function get_client_ip($trust_proxy) {
    if ($trust_proxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

// Fungsi validasi keamanan nama dan ekstensi file
function isExtensionAllowed($filename, $allowed_str, $forbidden, $forbidden_filenames = []) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $lowerName = strtolower($filename);

    foreach ($forbidden_filenames as $fn) {
        if ($lowerName === strtolower($fn)) return false;
    }
    if (in_array($ext, $forbidden)) return false;

    $allowed_str = trim($allowed_str);
    if (!empty($allowed_str)) {
        $allowed_arr = array_map('trim', explode(',', strtolower($allowed_str)));
        if (!in_array($ext, $allowed_arr) && !empty($ext)) return false;
    }
    return true;
}

// ============================================================================
// --- 2. MANAJEMEN DATABASE INTERNAL (JSON DALAM FILE PHP) ---
// ============================================================================

// Mengambil konfigurasi aplikasi (Nama & Logo)
function get_app_config($file) {
    if (!file_exists($file)) {
        $default = ['app_name' => 'Mini File Manager IDE', 'app_logo' => ''];
        file_put_contents($file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($default), LOCK_EX);
        return $default;
    }
    $content = file_get_contents($file);
    $json = preg_replace('/^<\?php exit\(".*?"\); \?>\s*/', '', $content);
    return json_decode($json, true) ?: ['app_name' => 'Mini File Manager IDE', 'app_logo' => ''];
}
$app_config = get_app_config($config_file);

// Mengambil konfigurasi plugin
function get_plugins_config($file) {
    if (!file_exists($file)) {
        $default = [];
        file_put_contents($file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($default), LOCK_EX);
        return $default;
    }
    $content = file_get_contents($file);
    $json = preg_replace('/^<\?php exit\(".*?"\); \?>\s*/', '', $content);
    return json_decode($json, true) ?: [];
}
$plugins_config = get_plugins_config($plugins_file);

// Mengambil database user & guest
function get_users_db($file) {
    if (!file_exists($file)) {
        $default_users = [
            'admin' => [
                'password' => password_hash('admin123', PASSWORD_DEFAULT),
                'role' => 'admin',
                'mode' => 'read-write',
                'allowed_paths' => ['/'],
                'theme' => 'dark'
            ],
            '__GUEST__' => [
                'role' => 'guest',
                'mode' => 'read-only',
                'allowed_paths' => ['/'],
                'theme' => 'dark',
                'is_active' => true
            ]
        ];
        save_users_db($file, $default_users);
        return $default_users;
    }
    $content = file_get_contents($file);
    $json = preg_replace('/^<\?php exit\(".*?"\); \?>\s*/', '', $content);
    $db = json_decode($json, true) ?: [];

    if (!isset($db['__GUEST__'])) {
        $db['__GUEST__'] = ['role' => 'guest', 'mode' => 'read-only', 'allowed_paths' => ['/'], 'theme' => 'dark', 'is_active' => true];
        save_users_db($file, $db);
    }
    return $db;
}

// Menyimpan perubahan database user
function save_users_db($file, $data) {
    $header = '<?php exit("Access Denied"); ?>' . "\n";
    file_put_contents($file, $header . json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}
$users_db = get_users_db($users_file);

// ============================================================================
// --- 3. ROUTER OTENTIKASI (LOGIN & LOGOUT) ---
// ============================================================================
if (isset($_GET['auth_action'])) {
    header('Content-Type: application/json');
    $action = $_GET['auth_action'];

    if ($action === 'login') {
        $ip = get_client_ip($trust_proxy_header);
        $now = time();
        $lockouts = [];
        if (file_exists($lockout_file)) {
            $lockout_content = @file_get_contents($lockout_file);
            $lockouts = json_decode(preg_replace('/^<\?php exit\(".*?"\); \?>\s*/', '', $lockout_content), true) ?: [];
        }

        // Bersihkan data lockout yang sudah kedaluwarsa (> 5 menit)
        foreach ($lockouts as $k => $v) { if ($now - $v['last_time'] > 300) unset($lockouts[$k]); }

        // Proteksi Brute-Force (Maksimal 5x gagal)
        if (isset($lockouts[$ip]) && $lockouts[$ip]['attempts'] >= 5) {
            if ($now - $lockouts[$ip]['last_time'] < 300) {
                $wait = 300 - ($now - $lockouts[$ip]['last_time']);
                echo json_encode(['error' => "Terlalu banyak percobaan gagal. Coba lagi dalam $wait detik."]); exit;
            } else { unset($lockouts[$ip]); }
        }

        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';

        if (isset($users_db[$user]) && $user !== '__GUEST__' && password_verify($pass, $users_db[$user]['password'])) {
            if (isset($lockouts[$ip])) {
                unset($lockouts[$ip]);
                @file_put_contents($lockout_file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($lockouts), LOCK_EX);
            }
            $_SESSION['user'] = [
                'username' => $user,
                'role' => $users_db[$user]['role'] ?? 'user',
                'mode' => $users_db[$user]['mode'] ?? 'read-write',
                'allowed_paths' => $users_db[$user]['allowed_paths'] ?? ['/'],
                'theme' => $users_db[$user]['theme'] ?? 'dark'
            ];
            echo json_encode(['status' => 'ok', 'theme' => $_SESSION['user']['theme']]);
        } else {
            sleep(1); // Delay penahan brute-force
            if (!isset($lockouts[$ip])) $lockouts[$ip] = ['attempts' => 0];
            $lockouts[$ip]['attempts']++;
            $lockouts[$ip]['last_time'] = $now;
            @file_put_contents($lockout_file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($lockouts), LOCK_EX);
            echo json_encode(['error' => 'Username atau Password salah!']);
        }
        exit;
    }

    if ($action === 'logout') {
        unset($_SESSION['user']);
        session_destroy();
        echo json_encode(['status' => 'ok']);
        exit;
    }
    exit;
}

// ============================================================================
// --- 4. CEK HAK AKSES SISTEM (NORMAL VS GUEST/EMBED) ---
// ============================================================================
$is_embed = isset($_GET['embed']) && $_GET['embed'] == '1';
$is_logged_in = isset($_SESSION['user']);
$is_guest = !$is_logged_in && $is_embed;
$guest_denied = false;

if ($is_guest) {
    $guest_conf = $users_db['__GUEST__'] ?? ['is_active' => false];
    if (empty($guest_conf['is_active'])) {
        $guest_denied = true;
    } else {
        $current_user = [
            'username' => 'Guest (Viewer)',
            'role' => 'guest',
            'mode' => 'read-only',
            'allowed_paths' => $guest_conf['allowed_paths'] ?? ['/'],
            'theme' => $guest_conf['theme'] ?? 'dark'
        ];
    }
} else {
    $current_user = $_SESSION['user'] ?? null;
}

// ============================================================================
// --- 5. SYSTEM LOADER PLUGIN ---
// ============================================================================
$active_plugin_js = [];
$active_plugin_css = [];
$plugin_errors = [];

if (is_dir($plugins_dir)) {
    foreach (scandir($plugins_dir) as $p) {
        if ($p === '.' || $p === '..') continue;
        if (is_dir($plugins_dir . DIRECTORY_SEPARATOR . $p) && !empty($plugins_config[$p]['active'])) {
            $plugin_roles = $plugins_config[$p]['allowed_roles'] ?? ['admin', 'user', 'guest'];
            $user_role = $current_user['role'] ?? 'guest';
            $user_name = strtolower($current_user['username'] ?? '');
            if ($user_role === 'guest' || $is_guest) $user_name = 'guest';

            // Pengecekan izin plugin: Allow jika admin, ATAU role/username user ada di dalam daftar akun yang diizinkan
            $allowed_lower = array_map('strtolower', $plugin_roles);
            if ($user_role !== 'admin' && !in_array(strtolower($user_role), $allowed_lower) && !in_array($user_name, $allowed_lower)) continue; 

            $p_path = $plugins_dir . DIRECTORY_SEPARATOR . $p;
            try {
                if (file_exists($p_path . DIRECTORY_SEPARATOR . 'backend.php')) {
                    ob_start();
                    include_once $p_path . DIRECTORY_SEPARATOR . 'backend.php';
                    $plugin_output = ob_get_clean(); 
                }
                if (file_exists($p_path . DIRECTORY_SEPARATOR . 'frontend.js')) {
                    $active_plugin_js[] = 'plugins/' . $p . '/frontend.js';
                }
                if (file_exists($p_path . DIRECTORY_SEPARATOR . 'style.css')) {
                    $active_plugin_css[] = 'plugins/' . $p . '/style.css';
                }
            } catch (\Throwable $e) {
                $plugin_errors[] = "Plugin [{$p}] dinonaktifkan sistem akibat error fatal: " . $e->getMessage();
                $plugins_config[$p]['active'] = false;
                file_put_contents($plugins_file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($plugins_config), LOCK_EX);
            }
        }
    }
}

// ============================================================================
// --- 6. ROUTER AJAX & FILE OPERATIONS (CRUD FILE/FOLDER) ---
// ============================================================================
if (($is_logged_in || $is_guest) && !$guest_denied && isset($_GET['ajax'])) {
    if (ob_get_length()) ob_clean(); 

    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $client_csrf = $headers['X-CSRF-Token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    $action = $_GET['action'] ?? '';

    // Validasi CSRF untuk aksi sensitif (Tulis/Modifikasi)
    $csrf_protected = ['batch_zip', 'batch_action', 'save', 'backup', 'create', 'rename', 'delete', 'upload', 'remote_download', 'change_pw', 'add_user', 'delete_user', 'save_theme', 'update_guest', 'save_config', 'save_plugin_config'];
    if (in_array($action, $csrf_protected) && !hash_equals($_SESSION['csrf_token'], $client_csrf)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'CSRF Token tidak valid atau sesi telah habis!']); exit;
    }

    // Blokir aksi tulis jika mode user adalah Read-Only (Demo/Guest)
    $write_actions = ['save', 'backup', 'create', 'rename', 'delete', 'upload', 'remote_download', 'batch_action', 'change_pw', 'add_user', 'delete_user', 'update_guest', 'save_config', 'save_plugin_config'];
    if (in_array($action, $write_actions) && ($current_user['mode'] ?? 'read-write') === 'read-only') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Akses Ditolak! Anda berada dalam MODE READ-ONLY (Viewer/Demo).']); exit;
    }

    // --- API: Manajemen Plugin ---
    if ($action === 'list_plugins') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $available_plugins = [];
        if (is_dir($plugins_dir)) {
            foreach (scandir($plugins_dir) as $p) {
                if ($p === '.' || $p === '..') continue;
                if (is_dir($plugins_dir . DIRECTORY_SEPARATOR . $p)) {
                    $is_active = !empty($plugins_config[$p]['active']);
                    $roles = $plugins_config[$p]['allowed_roles'] ?? ['admin', 'user', 'guest'];
                    $available_plugins[] = [
                        'id' => $p, 
                        'name' => ucfirst(str_replace(['-', '_'], ' ', $p)), 
                        'active' => $is_active,
                        'roles' => implode(', ', $roles)
                    ];
                }
            }
        }
        // Ambil daftar semua akun terdaftar + guest + role dasar untuk saran Autocomplete
        $all_accounts = ['admin', 'user', 'guest'];
        foreach ($users_db as $u => $d) {
            if ($u === '__GUEST__') $all_accounts[] = 'guest';
            else $all_accounts[] = $u;
        }
        $suggestions = array_values(array_unique($all_accounts));
        echo json_encode(['status' => 'ok', 'plugins' => $available_plugins, 'suggestions' => $suggestions]); exit;
    }

    if ($action === 'save_plugin_config') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $data = json_decode(file_get_contents('php://input'), true);
        $pid = preg_replace('/[^a-zA-Z0-9_-]/', '', $data['plugin_id'] ?? '');
        if ($pid) {
            $plugins_config[$pid]['active'] = (bool)($data['active'] ?? false);
            $raw_roles = array_map('trim', array_filter(explode(',', $data['roles'] ?? '')));
            $plugins_config[$pid]['allowed_roles'] = empty($raw_roles) ? ['admin'] : $raw_roles;
            file_put_contents($plugins_file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($plugins_config), LOCK_EX);
        }
        echo json_encode(['status' => 'ok']); exit;
    }

    // --- API: Autocomplete Folder/File lokal ---
    if ($action === 'autocomplete') {
        header('Content-Type: application/json');
        if (($current_user['role'] ?? '') !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }

        $query = $_GET['query'] ?? '';
        $query = ltrim(str_replace('\\', '/', $query), '/');
        $lastSlash = strrpos($query, '/');

        if ($lastSlash !== false) {
            $dir = substr($query, 0, $lastSlash);
            $term = substr($query, $lastSlash + 1);
        } else {
            $dir = ''; $term = $query;
        }

        $searchDir = $target_dir . ($dir ? DIRECTORY_SEPARATOR . $dir : '');
        $realSearch = realpath($searchDir);
        $results = [];

        if ($realSearch !== false && stripos($realSearch, $target_dir) === 0 && is_dir($realSearch)) {
            $items = scandir($realSearch);
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                if ($term === '' || stripos($item, $term) === 0) {
                    $fullPath = $realSearch . DIRECTORY_SEPARATOR . $item;
                    $type = is_dir($fullPath) ? 'folder' : 'file';
                    $relPath = '/' . ltrim($dir . '/' . $item, '/');
                    $results[] = ['path' => $relPath, 'type' => $type];
                }
            }
        }
        echo json_encode(['status' => 'ok', 'results' => $results]); exit;
    }

    // --- API: Simpan Konfigurasi Aplikasi (Logo & Nama) ---
    if ($action === 'save_config') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $data = json_decode(file_get_contents('php://input'), true);
        $app_config['app_name'] = strip_tags(trim($data['app_name'] ?? 'Mini File Manager IDE'));
        $app_config['app_logo'] = $data['app_logo'] ?? '';
        file_put_contents($config_file, '<?php exit("Access Denied"); ?>' . "\n" . json_encode($app_config), LOCK_EX);
        echo json_encode(['status' => 'ok', 'app_name' => $app_config['app_name'], 'app_logo' => $app_config['app_logo']]); exit;
    }

    // --- API: Sinkronisasi & Ubah Tema UI ---
    if ($action === 'check_theme') {
        header('Content-Type: application/json');
        if ($is_guest) { echo json_encode(['status' => 'ok', 'theme' => $current_user['theme']]); exit; }
        $uname = $current_user['username'];
        $fresh_users = get_users_db($users_file);
        $current_theme = $fresh_users[$uname]['theme'] ?? 'dark';
        $_SESSION['user']['theme'] = $current_theme;
        echo json_encode(['status' => 'ok', 'theme' => $current_theme]); exit;
    }

    if ($action === 'save_theme') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $new_theme = $data['theme'] ?? 'dark';
        $uname = $current_user['username'];
        if (isset($users_db[$uname])) {
            $users_db[$uname]['theme'] = $new_theme;
            save_users_db($users_file, $users_db);
            $_SESSION['user']['theme'] = $new_theme;
            echo json_encode(['status' => 'ok']);
        } else { echo json_encode(['error' => 'User tidak ditemukan']); }
        exit;
    }

    // --- HELPER RESOLUSI PATH & KEAMANAN DIREKTORI ---
    $relPath = $_GET['path'] ?? $_GET['file'] ?? '';
    $relPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relPath), DIRECTORY_SEPARATOR);
    $fullPath = $target_dir . ($relPath ? DIRECTORY_SEPARATOR . $relPath : '');
    $realPath = realpath($fullPath) ?: $fullPath;

    // Memastikan path yang diakses berada dalam cakupan folder yang diizinkan (Path Traversal Protection)
    function isSafePath($path, $base, $allowed_paths) {
        $real = realpath($path);
        if ($real === false && !file_exists($path)) $real = realpath(dirname($path));
        if ($real === false || stripos($real, $base) !== 0) return false;
        if (in_array('/', $allowed_paths) || in_array('*', $allowed_paths)) return true;

        $relativePath = '/' . ltrim(str_replace('\\', '/', substr($real, strlen($base))), '/');
        if ($relativePath === '/') return true; 

        foreach ($allowed_paths as $allowed) {
            $cleanAllowed = '/' . ltrim(str_replace('\\', '/', trim($allowed)), '/');
            if ($relativePath === $cleanAllowed) return true;
            if (stripos($relativePath, $cleanAllowed . '/') === 0) return true;
            if (stripos($cleanAllowed, $relativePath . '/') === 0) return true;
        }
        return false;
    }
    $user_allowed_paths = $current_user['allowed_paths'] ?? ['/'];

    // --- API: Ubah Password Akun ---
    if ($action === 'change_pw') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $old_pw = $data['old_password'] ?? '';
        $new_pw = $data['new_password'] ?? '';
        $uname = $current_user['username'];

        if (!password_verify($old_pw, $users_db[$uname]['password'])) { echo json_encode(['error' => 'Password lama salah!']); exit; }
        if (strlen($new_pw) < 4) { echo json_encode(['error' => 'Password baru minimal 4 karakter!']); exit; }
        $users_db[$uname]['password'] = password_hash($new_pw, PASSWORD_DEFAULT);
        save_users_db($users_file, $users_db);
        echo json_encode(['status' => 'ok']); exit;
    }

    // --- API: Manajemen User (List, Add, Delete, Update Guest) ---
    if ($action === 'list_users') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $list = [];
        foreach ($users_db as $u => $d) {
            if ($u === '__GUEST__') continue;
            $list[] = [
                'username' => $u, 
                'role' => $d['role'] ?? 'user', 
                'mode' => $d['mode'] ?? 'read-write',
                'allowed_paths' => implode(', ', $d['allowed_paths'] ?? ['/'])
            ];
        }
        $guest = $users_db['__GUEST__'] ?? ['is_active' => true, 'allowed_paths' => ['/']];
        echo json_encode(['status' => 'ok', 'users' => $list, 'guest' => $guest]); exit;
    }

    if ($action === 'update_guest') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $data = json_decode(file_get_contents('php://input'), true);
        $paths = array_map('trim', array_filter(explode(',', $data['allowed_paths'] ?? '/')));
        $users_db['__GUEST__']['allowed_paths'] = empty($paths) ? ['/'] : $paths;
        $users_db['__GUEST__']['is_active'] = $data['is_active'] ?? false;
        save_users_db($users_file, $users_db);
        echo json_encode(['status' => 'ok']); exit;
    }

    if ($action === 'add_user') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $data = json_decode(file_get_contents('php://input'), true);
        $new_u = trim($data['username'] ?? '');
        $new_p = $data['password'] ?? '';
        $new_mode = $data['mode'] ?? 'read-write';
        $paths = array_map('trim', array_filter(explode(',', $data['allowed_paths'] ?? '/')));

        if (!$new_u || !$new_p) { echo json_encode(['error' => 'Username dan Password wajib diisi!']); exit; }
        if (isset($users_db[$new_u]) || $new_u === '__GUEST__') { echo json_encode(['error' => 'Username sudah ada/tidak valid!']); exit; }

        $users_db[$new_u] = [
            'password' => password_hash($new_p, PASSWORD_DEFAULT),
            'role' => 'user',
            'mode' => $new_mode,
            'allowed_paths' => empty($paths) ? ['/'] : $paths,
            'theme' => 'dark'
        ];
        save_users_db($users_file, $users_db);
        echo json_encode(['status' => 'ok']); exit;
    }

    if ($action === 'delete_user') {
        header('Content-Type: application/json');
        if ($current_user['role'] !== 'admin') { echo json_encode(['error' => 'Akses ditolak']); exit; }
        $data = json_decode(file_get_contents('php://input'), true);
        $del_u = $data['username'] ?? '';
        if ($del_u === $current_user['username']) { echo json_encode(['error' => 'Tidak dapat menghapus akun sendiri!']); exit; }
        if (isset($users_db[$del_u]) && $del_u !== '__GUEST__') {
            unset($users_db[$del_u]);
            save_users_db($users_file, $users_db);
            echo json_encode(['status' => 'ok']);
        } else { echo json_encode(['error' => 'User tidak ditemukan']); }
        exit;
    }

    // --- API: Detail Metadata File / Folder ---
    if ($action === 'info') {
        header('Content-Type: application/json');
        if ($is_guest || ($current_user['role'] ?? '') === 'guest') {
            echo json_encode(['error' => 'Demi keamanan server, detail metadata & struktur path dinonaktifkan pada akses publik (Guest Mode).']); 
            exit;
        }
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || !file_exists($fullPath)) {
            echo json_encode(['error' => 'Item tidak ditemukan atau akses ditolak']); exit;
        }
        $is_dir = is_dir($fullPath);
        $modified = date('d M Y, H:i:s', filemtime($fullPath));
        $perms = substr(sprintf('%o', fileperms($fullPath)), -4);

        if ($is_dir) {
            $file_count = 0; $dir_count = 0; $total_size = 0;
            $fi = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($fullPath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach ($fi as $file) {
                if ($file->isDir()) { $dir_count++; }
                else { $file_count++; $total_size += $file->getSize(); }
            }
            $units = ['B', 'KB', 'MB', 'GB', 'TB'];
            $power = $total_size > 0 ? floor(log($total_size, 1024)) : 0;
            $formatSize = number_format($total_size / pow(1024, $power), 2, '.', ',') . ' ' . $units[$power];
            echo json_encode([
                'name' => basename($fullPath), 'type' => 'folder',
                'full_path' => str_replace('/', DIRECTORY_SEPARATOR, realpath($fullPath)),
                'size' => $formatSize, 'contents' => "$dir_count Folder, $file_count File",
                'modified' => $modified, 'permissions' => $perms, 'mime' => 'Directory / Folder'
            ]); exit;
        }

        $size = filesize($fullPath);
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $power = $size > 0 ? floor(log($size, 1024)) : 0;
        $formatSize = number_format($size / pow(1024, $power), 2, '.', ',') . ' ' . $units[$power];

        $mime = 'application/octet-stream';
        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) { $mime = finfo_file($finfo, $fullPath); finfo_close($finfo); }
        }

        $dimensions = 'N/A';
        if (strpos($mime, 'image/') === 0) {
            $imgInfo = @getimagesize($fullPath);
            if ($imgInfo) { $dimensions = $imgInfo[0] . ' x ' . $imgInfo[1] . ' pixels'; }
        }
        echo json_encode([
            'name' => basename($fullPath), 'type' => 'file',
            'full_path' => str_replace('/', DIRECTORY_SEPARATOR, realpath($fullPath)),
            'size' => $formatSize, 'size_raw' => $size, 'mime' => $mime,
            'dimensions' => $dimensions, 'modified' => $modified, 'permissions' => $perms
        ]); exit;
    }

    // --- API: Batch Kompresi ke file ZIP ---
    if ($action === 'batch_zip') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $items = $data['items'] ?? [];
        if (empty($items)) { echo json_encode(['error' => 'Tidak ada item dipilih']); exit; }
        if (!class_exists('ZipArchive')) { echo json_encode(['error' => 'Ekstensi ZipArchive PHP tidak aktif!']); exit; }

        $zipName = 'archive_selected_' . date('Ymd_His') . '.zip';
        $zipPath = $target_dir . DIRECTORY_SEPARATOR . $zipName;
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            echo json_encode(['error' => 'Gagal membuat file ZIP']); exit;
        }

        foreach ($items as $relItem) {
            $relItemClean = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relItem), DIRECTORY_SEPARATOR);
            $itemFull = $target_dir . DIRECTORY_SEPARATOR . $relItemClean;
            if (!isSafePath($itemFull, $target_dir, $user_allowed_paths) || !file_exists($itemFull) || basename($itemFull) === $current_script || basename($itemFull) === basename($users_file) || basename($itemFull) === basename($lockout_file) || basename($itemFull) === basename($config_file)) continue;

            if (is_dir($itemFull)) {
                $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($itemFull, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
                foreach ($files as $name => $file) {
                    if (!$file->isDir()) {
                        $filePath = $file->getRealPath();
                        if (!isSafePath($filePath, $target_dir, $user_allowed_paths)) continue;
                        $relativePath = substr($filePath, strlen($target_dir) + 1);
                        $zip->addFile($filePath, $relativePath);
                    }
                }
            } else {
                $zip->addFile($itemFull, $relItemClean);
            }
        }
        $zip->close();
        $dlUrl = '?ajax=1&action=download&path=' . urlencode($zipName);
        if ($is_guest) $dlUrl .= '&embed=1';
        echo json_encode(['status' => 'ok', 'zip_url' => $dlUrl, 'zip_name' => $zipName]); exit;
    }

    // --- API: Batch Action (Copy / Move file massal) ---
    if ($action === 'batch_action') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $items = $data['items'] ?? [];
        $destRel = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['dest'] ?? ''), DIRECTORY_SEPARATOR);
        $destFull = $target_dir . ($destRel ? DIRECTORY_SEPARATOR . $destRel : '');
        $mode = $data['mode'] ?? 'copy';

        if (!isSafePath($destFull, $target_dir, $user_allowed_paths) || !is_dir($destFull)) {
            echo json_encode(['error' => 'Direktori tujuan tidak valid atau akses ditolak']); exit;
        }

        function customCopyRecursive($src, $dst) {
            if (is_dir($src)) {
                @mkdir($dst, 0777, true);
                $files = scandir($src);
                foreach ($files as $file) {
                    if ($file != "." && $file != "..") customCopyRecursive("$src/$file", "$dst/$file");
                }
            } else if (file_exists($src)) { copy($src, $dst); }
        }

        foreach ($items as $relItem) {
            $relItemClean = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relItem), DIRECTORY_SEPARATOR);
            $srcFull = $target_dir . DIRECTORY_SEPARATOR . $relItemClean;
            if (!isSafePath($srcFull, $target_dir, $user_allowed_paths) || !file_exists($srcFull) || $srcFull === $destFull || basename($srcFull) === $current_script || basename($srcFull) === basename($users_file) || basename($srcFull) === basename($lockout_file) || basename($srcFull) === basename($config_file)) continue;

            $itemName = basename($srcFull);
            $targetItemFull = $destFull . DIRECTORY_SEPARATOR . $itemName;
            if ($mode === 'move') { rename($srcFull, $targetItemFull); }
            else { customCopyRecursive($srcFull, $targetItemFull); }
        }
        echo json_encode(['status' => 'ok']); exit;
    }

    // --- API: List direktori (Untuk Explorer Tree) ---
    if ($action === 'list') {
        header('Content-Type: application/json');
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || !is_dir($fullPath)) {
            echo json_encode(['error' => 'Folder tidak valid atau akses ditolak']); exit;
        }

        $items = scandir($fullPath);
        $folders = []; $files = [];
        $lowerForbiddenNames = array_map('strtolower', $forbidden_filenames);

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || in_array(strtolower($item), $lowerForbiddenNames)) continue;
            if (realpath($fullPath) === $target_dir && ($item === $current_script || $item === basename($users_file) || $item === basename($lockout_file) || $item === basename($config_file) || $item === basename($plugins_file))) continue;

            $itemFullPath = $fullPath . DIRECTORY_SEPARATOR . $item;
            if (!isSafePath($itemFullPath, $target_dir, $user_allowed_paths)) continue;

            $itemRelPath = ltrim(str_replace('\\', '/', $relPath . '/' . $item), '/');
            if (is_dir($itemFullPath)) {
                $folders[] = ['name' => $item, 'type' => 'folder', 'path' => $itemRelPath];
            } else {
                $files[] = ['name' => $item, 'type' => 'file', 'path' => $itemRelPath];
            }
        }
        echo json_encode(['items' => array_merge($folders, $files)]); exit;
    }

    // --- API: Membaca isi file text/code ---
    if ($action === 'read') {
        header('Content-Type: application/json');
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || is_dir($fullPath) || basename($fullPath) === $current_script || basename($fullPath) === basename($users_file) || basename($fullPath) === basename($lockout_file) || basename($fullPath) === basename($config_file)) {
            echo json_encode(['error' => 'Akses tidak diizinkan atau file tidak ditemukan']); exit;
        }
        echo json_encode(['content' => file_get_contents($fullPath)]); exit;
    }

    // --- API: Streaming / Download File (Mendukung Range Request / Resume) ---
    if ($action === 'raw' || $action === 'download') {
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || is_dir($fullPath) || basename($fullPath) === $current_script || basename($fullPath) === basename($users_file) || basename($fullPath) === basename($lockout_file) || basename($fullPath) === basename($config_file)) {
            http_response_code(403); exit('Access Denied');
        }

        $ext = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
        $mimes = [
            'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'svg' => 'image/svg+xml', 'webp' => 'image/webp', 'ico' => 'image/x-icon', 'pdf' => 'application/pdf',
            'mp4' => 'video/mp4', 'webm' => 'video/webm', 'ogg' => 'video/ogg', 'mp3' => 'audio/mpeg', 'wav' => 'audio/wav', 'zip' => 'application/zip', 'rar' => 'application/x-rar-compressed',
            'doc' => 'application/msword', 'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'xls' => 'application/vnd.ms-excel', 'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt' => 'application/vnd.ms-powerpoint', 'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'csv' => 'text/csv'
        ];
        $mime = $mimes[$ext] ?? (function_exists('mime_content_type') ? mime_content_type($fullPath) : 'application/octet-stream');

        if ($action === 'download') {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.basename($fullPath).'"');
            header('Expires: 0'); header('Cache-Control: must-revalidate'); header('Pragma: public');
            header('Content-Length: ' . filesize($fullPath));
            readfile($fullPath); exit;
        }

        $size = filesize($fullPath);
        $fm = @fopen($fullPath, 'rb');
        if (!$fm) { http_response_code(404); exit; }

        $begin = 0; $end = $size - 1;
        if (isset($_SERVER['HTTP_RANGE'])) {
            if (preg_match('/bytes=\h*(\d+)-(\d*)[\D.*]?/i', $_SERVER['HTTP_RANGE'], $matches)) {
                $begin = intval($matches[1]);
                if (!empty($matches[2])) $end = intval($matches[2]);
            }
            http_response_code(206);
            header("Content-Range: bytes $begin-$end/$size");
        } else { http_response_code(200); }

        header("Content-Type: $mime"); header("Cache-Control: public, must-revalidate, max-age=0");
        header("Accept-Ranges: bytes"); header("Content-Length: " . (($end - $begin) + 1));

        $cur = $begin; fseek($fm, $begin, 0);
        while (!feof($fm) && $cur <= $end && (connection_status() == 0)) {
            print fread($fm, min(1024 * 16, ($end - $cur) + 1));
            $cur += 1024 * 16; flush();
        }
        fclose($fm); exit;
    }

    // --- API: Simpan perubahan file code ---
    if ($action === 'save') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $saveRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $saveFullPath = $target_dir . DIRECTORY_SEPARATOR . $saveRelPath;

        if (isSafePath(dirname($saveFullPath), $target_dir, $user_allowed_paths) && basename($saveFullPath) !== $current_script && basename($saveFullPath) !== basename($users_file) && basename($saveFullPath) !== basename($lockout_file) && basename($saveFullPath) !== basename($config_file) && !is_dir($saveFullPath)) {
            file_put_contents($saveFullPath, $data['content']);
            echo json_encode(['status' => 'ok']);
        } else { echo json_encode(['error' => 'Gagal menyimpan. Path tidak valid atau akses ditolak!']); }
        exit;
    }

    // --- API: Buat backup duplikasi (.bak) ---
    if ($action === 'backup') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $backupRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $backupFullPath = $target_dir . DIRECTORY_SEPARATOR . $backupRelPath;

        if (isSafePath($backupFullPath, $target_dir, $user_allowed_paths) && file_exists($backupFullPath) && !is_dir($backupFullPath) && basename($backupFullPath) !== $current_script && basename($backupFullPath) !== basename($users_file) && basename($backupFullPath) !== basename($lockout_file) && basename($backupFullPath) !== basename($config_file)) {
            $backupName = $backupFullPath . '_' . date('Ymd_His') . '.bak';
            if (copy($backupFullPath, $backupName)) {
                echo json_encode(['status' => 'ok', 'backup_file' => basename($backupName)]);
            } else { echo json_encode(['error' => 'Gagal menduplikasi file backup!']); }
        } else { echo json_encode(['error' => 'File tidak valid atau tidak dapat di-backup!']); }
        exit;
    }

    // --- API: Buat File atau Folder Baru (HANYA UNTUK ADMIN) ---
    if ($action === 'create') {
        header('Content-Type: application/json');
        if (($current_user['role'] ?? '') !== 'admin') {
            echo json_encode(['error' => 'Akses Ditolak! Hanya Admin yang diizinkan menambah file atau folder baru.']); exit;
        }
        $data = json_decode(file_get_contents('php://input'), true);
        $newRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $newFullPath = $target_dir . DIRECTORY_SEPARATOR . $newRelPath;

        if (isSafePath(dirname($newFullPath), $target_dir, $user_allowed_paths)) {
            if ($data['type'] !== 'folder' && !isExtensionAllowed(basename($newFullPath), $allowed_file_extensions, $forbidden_exts, $forbidden_filenames)) {
                echo json_encode(['error' => 'Ekstensi/nama file tidak diizinkan! (Dilarang oleh sistem)']); exit;
            }
            if (file_exists($newFullPath)) echo json_encode(['error' => 'Nama sudah digunakan!']);
            else {
                if ($data['type'] === 'folder') mkdir($newFullPath, 0777, true);
                else file_put_contents($newFullPath, '');
                echo json_encode(['status' => 'ok']);
            }
        } else { echo json_encode(['error' => 'Lokasi tidak valid atau akses ditolak']); }
        exit;
    }

    // --- API: Ganti Nama (Rename) ---
    if ($action === 'rename') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $oldPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['old_path'] ?? ''), DIRECTORY_SEPARATOR);
        $newPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['new_path'] ?? ''), DIRECTORY_SEPARATOR);

        if (isSafePath($oldPath, $target_dir, $user_allowed_paths) && isSafePath(dirname($newPath), $target_dir, $user_allowed_paths) && basename($oldPath) !== $current_script && basename($oldPath) !== basename($users_file) && basename($oldPath) !== basename($lockout_file) && basename($oldPath) !== basename($config_file)) {
            if (!is_dir($oldPath) && !isExtensionAllowed(basename($newPath), $allowed_file_extensions, $forbidden_exts, $forbidden_filenames)) {
                echo json_encode(['error' => 'Ekstensi/nama file baru tidak diizinkan! (Dilarang oleh sistem)']); exit;
            }
            if (file_exists($newPath)) echo json_encode(['error' => 'Nama target sudah ada!']);
            else { rename($oldPath, $newPath); echo json_encode(['status' => 'ok']); }
        } else { echo json_encode(['error' => 'Aksi ditolak']); }
        exit;
    }

    // --- API: Hapus File / Folder ---
    if ($action === 'delete') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $delPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);

        if (isSafePath($delPath, $target_dir, $user_allowed_paths) && basename($delPath) !== $current_script && basename($delPath) !== basename($users_file) && basename($delPath) !== basename($lockout_file) && basename($delPath) !== basename($config_file)) {
            function deleteRecursive($dir) {
                if (!file_exists($dir)) return true;
                if (!is_dir($dir)) return unlink($dir);
                foreach (scandir($dir) as $item) {
                    if ($item == '.' || $item == '..') continue;
                    if (!deleteRecursive($dir . DIRECTORY_SEPARATOR . $item)) return false;
                }
                return rmdir($dir);
            }
            deleteRecursive($delPath);
            echo json_encode(['status' => 'ok']);
        } else { echo json_encode(['error' => 'Gagal menghapus item ini atau akses ditolak']); }
        exit;
    }

    // --- API: Upload File ---
    if ($action === 'upload') {
        header('Content-Type: application/json');
        $uploadDirRel = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $_POST['path'] ?? ''), DIRECTORY_SEPARATOR);
        $uploadDirFull = $target_dir . ($uploadDirRel ? DIRECTORY_SEPARATOR . $uploadDirRel : '');

        if (!isSafePath($uploadDirFull, $target_dir, $user_allowed_paths) || !is_dir($uploadDirFull)) { echo json_encode(['error' => 'Direktori upload tidak valid']); exit; }

        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $fileName = basename($_FILES['file']['name']);
            if (!isExtensionAllowed($fileName, $allowed_upload_extensions, $forbidden_exts, $forbidden_filenames)) {
                echo json_encode(['error' => 'Upload ditolak: Ekstensi/nama file tidak diizinkan!']); exit;
            }
            $targetFile = $uploadDirFull . DIRECTORY_SEPARATOR . $fileName;
            if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) echo json_encode(['status' => 'ok']);
            else echo json_encode(['error' => 'Gagal memindahkan file yang diunggah']);
        } else { echo json_encode(['error' => 'Tidak ada file atau terjadi kesalahan upload']); }
        exit;
    }

    // --- API: Remote Download dari URL (Dengan Proteksi SSRF) ---
    if ($action === 'remote_download') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $url = trim($data['url'] ?? '');
        $targetFolderRel = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $targetFolderFull = $target_dir . ($targetFolderRel ? DIRECTORY_SEPARATOR . $targetFolderRel : '');

        if (!filter_var($url, FILTER_VALIDATE_URL)) { echo json_encode(['error' => 'URL tidak valid']); exit; }
        if (!isSafePath($targetFolderFull, $target_dir, $user_allowed_paths) || !is_dir($targetFolderFull)) { echo json_encode(['error' => 'Direktori tujuan tidak valid']); exit; }

        $parsed = parse_url($url);
        $scheme = strtolower($parsed['scheme'] ?? '');
        $host = $parsed['host'] ?? '';

        if (!in_array($scheme, ['http', 'https']) || empty($host)) {
            echo json_encode(['error' => 'URL tidak diizinkan (hanya skema http/https yang diperbolehkan)']); exit;
        }

        $port = $parsed['port'] ?? ($scheme === 'https' ? 443 : 80);
        $forbidden_ports = [22, 23, 25, 3306, 6379, 5432, 11211, 21, 20, 445, 139, 135];
        if (in_array($port, $forbidden_ports)) {
            echo json_encode(['error' => 'URL tidak diizinkan (Port ditolak karena alasan keamanan)']); exit;
        }

        $ips = @gethostbynamel($host);
        if (!$ips) { echo json_encode(['error' => 'URL tidak dapat dijangkau (Host tidak ditemukan)']); exit; }

        $safeIp = null;
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                echo json_encode(['error' => 'URL tidak diizinkan (Akses ke Internal/Private Network dicegah - SSRF Protection)']); exit;
            }
            if ($safeIp === null) $safeIp = $ip;
        }

        $fileName = basename(parse_url($url, PHP_URL_PATH));
        if (!$fileName || $fileName === '/') $fileName = 'downloaded_file_' . time();
        if (!isExtensionAllowed($fileName, $allowed_upload_extensions, $forbidden_exts, $forbidden_filenames)) {
            echo json_encode(['error' => 'Ekstensi file tujuan download tidak diizinkan!']); exit;
        }

        $targetFile = $targetFolderFull . DIRECTORY_SEPARATOR . $fileName;

        if (!function_exists('curl_init')) {
            echo json_encode(['error' => 'Fitur download URL membutuhkan ekstensi cURL PHP yang tidak aktif di server']); exit;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RESOLVE, ["$host:$port:$safeIp"]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); 
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mini-File-Manager-IDE/1.0');
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($content === false || $content === '' || $httpCode >= 400) {
            $msg = $curlErr ? "Gagal mengambil file: $curlErr" : "Gagal mengambil file dari URL tersebut (HTTP $httpCode)";
            echo json_encode(['error' => $msg]); exit;
        }

        file_put_contents($targetFile, $content);
        echo json_encode(['status' => 'ok', 'filename' => $fileName]);
        exit;
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($app_config['app_name']); ?></title>
    <?php if (!empty($app_config['app_logo'])): ?>
    <link rel="icon" href="<?php echo htmlspecialchars($app_config['app_logo']); ?>">
    <?php endif; ?>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs/loader.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/dist/tabler-icons.min.css" />
    <style>
        /* ==================================================================== */
        /* --- SEMANTIC THEME VARIABLES FOR UI (DARK, LIGHT, OCEAN, TERMINAL) --- */
        /* ==================================================================== */
        :root {
            --bg-main: #1e1e1e; --bg-sidebar: #252526; --bg-tab: #2d2d2d; --bg-hover: rgba(255,255,255,0.08);
            --text-main: #d4d4d4; --text-muted: #888888;
            --border-color: #444444; --accent: #007acc;
            --input-bg: #1e1e1e; --btn-text: #ffffff;
            --color-warning: #fbbf24; --color-danger: #ef4444; --color-success: #4ade80; --color-info: #60a5fa;
        }
        [data-theme="light"] {
            --bg-main: #f3f4f6; --bg-sidebar: #ffffff; --bg-tab: #e5e7eb; --bg-hover: rgba(0,0,0,0.06);
            --text-main: #1f2937; --text-muted: #6b7280;
            --border-color: #d1d5db; --accent: #2563eb;
            --input-bg: #ffffff; --btn-text: #ffffff;
            --color-warning: #d97706; --color-danger: #dc2626; --color-success: #16a34a; --color-info: #2563eb;
        }
        [data-theme="ocean"] {
            --bg-main: #0f111a; --bg-sidebar: #090b10; --bg-tab: #1a1c23; --bg-hover: rgba(255,255,255,0.06);
            --text-main: #8f93a2; --text-muted: #546e7a;
            --border-color: #1e212b; --accent: #82aaff;
            --input-bg: #090b10; --btn-text: #090b10;
            --color-warning: #44ff00; --color-danger: #f07178; --color-success: #c3e88d; --color-info: #82aaff;
        }
        [data-theme="terminal"] {
            --bg-main: #000000; --bg-sidebar: #000000; --bg-tab: #000000; --bg-hover: #0000000f;
            --text-main: #d4d4d4; --text-muted: #808080;
            --border-color: #333333; --accent: #007acc;
            --input-bg: #000000; --btn-text: #000000;
            --color-warning: #dcdcaa; --color-danger: #f44747; --color-success: #6a9955; --color-info: #569cd6;
        }

        body { background-color: var(--bg-main); color: var(--text-main); transition: background-color 0.3s, color 0.3s; }
        aside, #context-menu { background-color: var(--bg-sidebar); border-color: var(--border-color); }
        #tab-bar, .modal-bg > div { background-color: var(--bg-tab); border-color: var(--border-color); }
        .border-theme { border-color: var(--border-color); }
        
        input, select, textarea { background-color: var(--input-bg) !important; color: var(--text-main) !important; border-color: var(--border-color) !important; outline: none; }
        input:focus, select:focus, textarea:focus { border-color: var(--accent) !important; }
        button.bg-\\[var\\(--accent\\)\\] { color: var(--btn-text) !important; }
        .hover-bg:hover { background-color: var(--bg-hover) !important; }

        .text-warning { color: var(--color-warning); }
        .text-danger { color: var(--color-danger); }
        .text-success { color: var(--color-success); }
        .text-info { color: var(--color-info); }
        .text-accent { color: var(--accent); }
        .text-muted { color: var(--text-muted); }

        .bg-warning-soft { background-color: color-mix(in srgb, var(--color-warning) 15%, transparent); color: var(--color-warning); border: 1px solid color-mix(in srgb, var(--color-warning) 30%, transparent); }
        .bg-danger-soft { background-color: color-mix(in srgb, var(--color-danger) 15%, transparent); color: var(--color-danger); border: 1px solid color-mix(in srgb, var(--color-danger) 30%, transparent); }
        .bg-success-soft { background-color: color-mix(in srgb, var(--color-success) 15%, transparent); color: var(--color-success); border: 1px solid color-mix(in srgb, var(--color-success) 30%, transparent); }
        .bg-info-soft { background-color: color-mix(in srgb, var(--color-info) 15%, transparent); color: var(--color-info); border: 1px solid color-mix(in srgb, var(--color-info) 30%, transparent); }

        ::-webkit-scrollbar { height: 6px; width: 6px; }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
        
        #preview-content.hidden, #editor-wrapper.hidden, #empty-state.hidden { display: none !important; }

        .resizer { width: 4px; cursor: col-resize; background-color: transparent; position: absolute; right: 0; top: 0; bottom: 0; z-index: 10; }
        .resizer:hover, .resizer.active { background-color: var(--accent); }

        .folder-content { position: relative; }
        .folder-content::before {
            content: ''; position: absolute; top: 0; bottom: 0; left: var(--line-x); border-left: 1px solid var(--border-color); opacity: 0.7; pointer-events: none; z-index: 0;
        }

        .unsaved-dot {
            width: 8px; height: 8px; border-radius: 50%; background-color: var(--text-main); box-shadow: 0 0 8px var(--text-main); display: inline-block; margin-left: 6px; animation: pulse-glow 1.5s infinite alternate;
        }
        @keyframes pulse-glow {
            0% { transform: scale(0.9); opacity: 0.8; box-shadow: 0 0 4px var(--text-main); }
            100% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 10px var(--color-warning), 0 0 4px var(--text-main); }
        }

        @keyframes scale-up {
            0% { transform: scale(0.95); opacity: 0; }
            100% { transform: scale(1); opacity: 1; }
        }
        .animate-scale-up { animation: scale-up 0.15s ease-out forwards; }

        /* Animasi Dropdown Autocomplete yang halus */
        @keyframes dropdown-fade {
            0% { opacity: 0; transform: translateY(-6px) scale(0.98); }
            100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        .animate-dropdown { animation: dropdown-fade 0.15s cubic-bezier(0.16, 1, 0.3, 1) forwards; transform-origin: top center; }

        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }

        .tree-checkbox { display: none; }
        .multi-select-active .tree-checkbox { display: inline-block !important; }

        @media (max-width: 768px) {
            .resizer { display: none; }
            #sidebar { width: 85% !important; max-width: 320px; }
        }
    </style>
    <?php foreach($active_plugin_css as $css_file): ?>
        <link rel="stylesheet" href="<?php echo htmlspecialchars($css_file); ?>">
    <?php endforeach; ?>
</head>
<body class="flex flex-col md:flex-row h-screen overflow-hidden font-sans select-none text-sm" data-theme="<?php echo $current_user['theme'] ?? 'dark'; ?>">

<?php if (isset($guest_denied) && $guest_denied): ?>
    <div class="fixed inset-0 bg-[var(--bg-main)] flex items-center justify-center z-50 p-4">
        <div class="bg-[var(--bg-tab)] border border-theme rounded-2xl shadow-2xl p-8 max-w-sm w-full text-center animate-scale-up">
            <div class="w-16 h-16 rounded-full bg-danger-soft flex items-center justify-center mx-auto mb-4 text-3xl">
                <i class="ti ti-lock-off"></i>
            </div>
            <h1 class="text-xl font-bold mb-2">Akses Ditolak</h1>
            <p class="text-sm text-muted mb-6 leading-relaxed">Mode Embed (Guest Viewer) untuk aplikasi ini telah dinonaktifkan secara permanen atau sementara oleh Administrator.</p>
            <a href="?" class="inline-block w-full py-2.5 bg-[var(--accent)] hover:opacity-90 font-bold rounded-lg shadow-lg transition active:scale-95 text-[var(--btn-text)]">Ke Halaman Login</a>
        </div>
    </div>
</body></html>
<?php exit; endif; ?>

<?php if (!$is_logged_in && !$is_guest): ?>
    <div class="fixed inset-0 bg-[var(--bg-main)] flex items-center justify-center z-50 p-4">
        <div class="bg-[var(--bg-tab)] border border-theme rounded-2xl shadow-2xl p-8 max-w-sm w-full animate-scale-up text-center">
            <?php if (!empty($app_config['app_logo'])): ?>
                <img src="<?php echo htmlspecialchars($app_config['app_logo']); ?>" class="h-16 mx-auto mb-4 object-contain">
            <?php else: ?>
                <div class="w-16 h-16 rounded-full bg-info-soft flex items-center justify-center mx-auto mb-4 text-3xl">
                    <i class="ti ti-lock"></i>
                </div>
            <?php endif; ?>
            <h1 class="text-xl font-bold tracking-wide mb-1"><?php echo htmlspecialchars($app_config['app_name']); ?></h1>
            <p class="text-xs text-muted mb-6">SECURE SYSTEM LOGIN</p>

            <form id="login-form" onsubmit="handleLogin(event)" class="space-y-4 text-left">
                <div>
                    <label class="block text-xs font-semibold mb-1 opacity-70">Username</label>
                    <div class="relative">
                        <i class="ti ti-user absolute left-3 top-2.5 text-muted"></i>
                        <input type="text" id="login-user" required class="w-full border border-theme rounded-lg pl-9 pr-3 py-2 text-sm" placeholder="Masukkan username...">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold mb-1 opacity-70">Password</label>
                    <div class="relative">
                        <i class="ti ti-key absolute left-3 top-2.5 text-muted"></i>
                        <input type="password" id="login-pass" required class="w-full border border-theme rounded-lg pl-9 pr-3 py-2 text-sm" placeholder="Masukkan password...">
                    </div>
                </div>
                <div id="login-error" class="hidden text-xs bg-danger-soft p-2.5 rounded-lg text-center font-medium"></div>
                <button type="submit" id="login-btn" class="w-full py-2.5 bg-[var(--accent)] hover:opacity-90 font-bold rounded-lg shadow-lg transition active:scale-95 flex items-center justify-center gap-2 text-[var(--btn-text)]">
                    <i class="ti ti-login"></i> Masuk Sistem
                </button>
            </form>
            <div class="mt-6 pt-4 border-t border-theme text-[10px] text-muted flex flex-col gap-2">
                <a href="?embed=1" class="text-accent hover:underline inline-flex items-center justify-center gap-1 mt-1"><i class="ti ti-eye"></i> Masuk Mode Guest Viewer</a>
            </div>
        </div>
    </div>
    <script>
        function handleLogin(e) {
            e.preventDefault();
            const btn = document.getElementById('login-btn');
            const err = document.getElementById('login-error');
            btn.disabled = true; btn.innerHTML = '<i class="ti ti-loader-2 animate-spin"></i> Memverifikasi...';
            err.classList.add('hidden');

            const formData = new FormData();
            formData.append('username', document.getElementById('login-user').value);
            formData.append('password', document.getElementById('login-pass').value);

            fetch('?auth_action=login', { method: 'POST', body: formData })
            .then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    window.location.reload();
                } else {
                    err.innerText = res.error || 'Gagal login';
                    err.classList.remove('hidden');
                    btn.disabled = false; btn.innerHTML = '<i class="ti ti-login"></i> Masuk Sistem';
                }
            }).catch(() => {
                err.innerText = 'Terjadi kesalahan jaringan!';
                err.classList.remove('hidden');
                btn.disabled = false; btn.innerHTML = '<i class="ti ti-login"></i> Masuk Sistem';
            });
        }
    </script>
<?php else: ?>
    <div class="md:hidden flex items-center justify-between p-3 border-b border-theme bg-[var(--bg-sidebar)] z-20 flex-shrink-0 shadow-md w-full">
        <div class="font-bold tracking-widest text-accent flex items-center gap-2 text-sm truncate">
            <?php if (!empty($app_config['app_logo'])): ?>
                <img src="<?php echo htmlspecialchars($app_config['app_logo']); ?>" class="h-5 object-contain inline-block">
            <?php else: ?>
                <i class="ti ti-code"></i>
            <?php endif; ?>
            <span class="truncate"><?php echo strtoupper(htmlspecialchars($app_config['app_name'])); ?></span>
        </div>
        <button onclick="toggleSidebar()" class="text-[var(--text-main)] focus:outline-none p-1 rounded hover-bg">
            <i class="ti ti-menu-2 text-2xl"></i>
        </button>
    </div>

    <div id="mobile-overlay" class="hidden fixed inset-0 bg-black/60 z-30 md:hidden transition-opacity" onclick="toggleSidebar()"></div>

    <aside id="sidebar" class="fixed md:relative inset-y-0 left-0 z-40 transform -translate-x-full md:translate-x-0 transition-transform duration-300 w-64 flex flex-col border-r border-theme flex-shrink-0 h-full shadow-2xl md:shadow-none bg-[var(--bg-sidebar)]" oncontextmenu="showContextMenu(event, currentExplorerRoot, 'root', this)">
        <div class="resizer" id="drag-handle"></div>

        <?php if (($current_user['mode'] ?? '') === 'read-only'): ?>
        <div class="bg-warning-soft text-center text-[11px] font-bold px-3 py-1.5 flex items-center justify-center gap-1.5 border-b border-theme">
            <i class="ti ti-shield-lock"></i> <?php echo $is_guest ? 'GUEST VIEWER (READ-ONLY)' : 'MODE DEMO (READ-ONLY)'; ?>
        </div>
        <?php endif; ?>

        <div id="explorer-header" class="p-3 text-[11px] font-bold uppercase tracking-widest text-muted border-b border-theme flex justify-between items-center bg-[var(--bg-hover)]">
            <span>Explorer</span>
            <div class="flex gap-2 text-base">
                <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-accent" title="Pilih Banyak (Multi-Select Mode)"><i class="ti ti-checkbox"></i></span>
                <?php if (($current_user['role'] ?? '') === 'admin'): ?>
                <span onclick="openModal('create', currentExplorerRoot, 'file')" class="cursor-pointer hover:text-accent" title="Buat File Baru"><i class="ti ti-file-plus"></i></span>
                <span onclick="openModal('create', currentExplorerRoot, 'folder')" class="cursor-pointer hover:text-accent" title="Buat Folder Baru"><i class="ti ti-folder-plus"></i></span>
                <?php endif; ?>
                <span onclick="loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-accent font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
            </div>
        </div>

        <div class="px-2 py-2 border-b border-theme">
            <div class="relative">
                <i class="ti ti-search absolute left-2 top-1.5 text-muted"></i>
                <input type="text" id="search-input" placeholder="Cari di explorer..." class="w-full border border-theme rounded px-2 pl-7 py-1 text-xs">
            </div>
        </div>

        <ul id="file-tree" class="flex-1 overflow-y-auto py-2">
            <li class="px-4 text-xs italic"><i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memuat folder...</li>
        </ul>

        <div id="batch-action-bar" class="hidden border-t border-theme p-2.5 bg-[var(--bg-tab)] shadow-2xl flex flex-col gap-2 text-xs z-20">
            <div class="flex justify-between items-center font-bold text-warning">
                <span><i class="ti ti-checkbox text-sm"></i> <span id="selected-count">0</span> item terpilih</span>
                <span onclick="disableMultiSelectMode()" class="cursor-pointer text-danger hover:underline">Batal</span>
            </div>
            <div class="grid <?php echo ($current_user['mode'] ?? '') === 'read-only' ? 'grid-cols-1' : 'grid-cols-2'; ?> gap-1.5 font-medium">
                <button onclick="batchZipDownload()" class="bg-warning-soft hover:opacity-80 py-1 rounded flex items-center justify-center gap-1 shadow transition text-[var(--text-main)]"><i class="ti ti-file-zip"></i> ZIP Download</button>
                <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
                <button onclick="openModal('batch_copy_move')" class="bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] py-1 rounded flex items-center justify-center gap-1 shadow transition"><i class="ti ti-copy"></i> Copy/Move</button>
                <?php endif; ?>
            </div>
        </div>

        <div class="p-2 border-t border-theme flex flex-col gap-2 text-xs text-muted flex-shrink-0 bg-[var(--bg-hover)]">
            <div class="flex items-center justify-between font-bold text-[var(--text-main)]">
                <span class="flex items-center gap-1.5 truncate">
                    <?php if ($is_guest): ?>
                        <i class="ti ti-user-circle text-muted"></i> Guest Mode
                    <?php else: ?>
                        <i class="ti ti-user-check text-success"></i> <?php echo htmlspecialchars($current_user['username']); ?>
                    <?php endif; ?>
                </span>
                <span class="bg-info-soft px-1.5 py-0.5 rounded text-[10px] uppercase font-mono border border-theme"><?php echo $current_user['role']; ?></span>
            </div>
            <div class="flex items-center justify-between">
                <span>Tema UI:</span>
                <select id="theme-selector" class="border border-theme rounded p-1 w-28 text-[11px]" onchange="changeTheme(this.value)">
                    <option value="dark" <?php echo ($current_user['theme'] ?? '') === 'dark' ? 'selected' : ''; ?>>Dark</option>
                    <option value="light" <?php echo ($current_user['theme'] ?? '') === 'light' ? 'selected' : ''; ?>>Light</option>
                    <option value="ocean" <?php echo ($current_user['theme'] ?? '') === 'ocean' ? 'selected' : ''; ?>>Ocean</option>
                    <option value="terminal" <?php echo ($current_user['theme'] ?? '') === 'terminal' ? 'selected' : ''; ?>>Terminal</option>
                </select>
            </div>
            <div class="flex gap-1 pt-1 border-t border-theme">
                <?php if (!$is_guest): ?>
                    <button onclick="openSettingsTab()" class="flex-1 bg-info-soft hover-bg py-1 rounded transition flex items-center justify-center gap-1 text-[var(--text-main)]" title="Pengaturan Sistem & User"><i class="ti ti-settings text-info"></i> Settings</button>
                    <button onclick="logoutApp()" class="flex-1 bg-danger-soft hover-bg py-1 rounded transition flex items-center justify-center gap-1 text-[var(--text-main)]" title="Keluar"><i class="ti ti-logout text-danger"></i> Exit</button>
                <?php else: ?>
                    <div class="flex-1 bg-[var(--input-bg)] text-muted font-bold py-1 text-center rounded border border-theme cursor-not-allowed">
                        EMBEDDED READ-ONLY MODE
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </aside>

    <main class="flex-1 flex flex-col min-w-0 h-[calc(100vh-50px)] md:h-screen bg-[var(--bg-main)] relative z-10 overflow-hidden">
        <div class="flex items-center justify-between border-b border-theme bg-[var(--bg-tab)] min-h-[36px] flex-shrink-0 pr-2">
            <div id="tab-bar" class="flex overflow-x-auto flex-1 min-h-[36px] scrollbar-hide"></div>

            <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
            <div id="editor-top-actions" class="hidden flex items-center gap-1.5 pl-2 border-l border-theme my-1 flex-shrink-0">
                <button id="btn-top-backup" onclick="backupCurrentFile()" class="hidden md:flex bg-warning-soft hover:opacity-80 px-2.5 py-1 rounded text-xs font-medium items-center gap-1 shadow transition active:scale-95 text-[var(--text-main)]" title="Duplikasi Backup (.bak)">
                    <i class="ti ti-copy text-sm text-warning"></i> <span>Backup</span>
                </button>
                <button id="btn-top-save" onclick="saveCurrentFile()" class="bg-[var(--accent)] hover:opacity-85 text-[var(--btn-text)] px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition active:scale-95" title="Simpan Perubahan (Ctrl+S)">
                    <i class="ti ti-device-floppy text-sm"></i> <span id="top-save-text" class="hidden md:inline">Simpan</span>
                </button>
            </div>
            <?php else: ?>
            <div id="editor-top-actions" class="hidden flex items-center gap-1.5 pl-2 border-l border-theme my-1 flex-shrink-0">
                <span class="bg-warning-soft px-2 py-1 rounded text-xs font-bold"><i class="ti ti-lock"></i> Read-Only</span>
            </div>
            <?php endif; ?>
        </div>

        <div id="empty-state" class="flex-1 flex flex-col items-center justify-center opacity-50 min-h-0 text-center px-4 transition-all text-muted">
            <?php if (!empty($app_config['app_logo'])): ?>
                <img src="<?php echo htmlspecialchars($app_config['app_logo']); ?>" class="h-24 md:h-32 mb-4 object-contain filter grayscale opacity-60">
            <?php else: ?>
                <i class="ti ti-code text-6xl md:text-8xl mb-4"></i>
            <?php endif; ?>
            <h2 class="text-lg md:text-xl font-bold tracking-wide text-[var(--text-main)]"><?php echo htmlspecialchars($app_config['app_name']); ?></h2>
            <p class="text-xs md:text-sm mt-2">FILE MANAGEMENT SYSTEM</p>
        </div>

        <div id="editor-wrapper" class="flex-1 relative hidden min-h-0 w-full">
            <div id="editor" class="absolute inset-0 w-full h-full"></div>
        </div>

        <div id="preview-wrapper" class="flex-1 relative hidden bg-[var(--bg-hover)] min-h-0 w-full overflow-hidden">
            <div id="preview-content" class="absolute inset-0 overflow-auto w-full h-full flex items-center justify-center p-4"></div>
        </div>

        <div class="h-8 flex-shrink-0 bg-[var(--accent)] text-[var(--btn-text)] flex items-center justify-between px-2 md:px-4 text-[10px] md:text-xs z-10 w-full">
            <div class="flex items-center gap-2 md:gap-4 truncate">
                <span id="status" class="font-mono flex items-center gap-1 truncate"><i class="ti ti-info-circle text-sm"></i> Siap</span>
                <div id="editor-tools" class="hidden border-l border-[var(--bg-hover)] pl-2 md:pl-4 flex items-center gap-2 md:gap-3 flex-shrink-0">
                    <span onclick="editor.trigger('', 'actions.find')" class="cursor-pointer hover:underline flex items-center gap-1" title="Cari di file ini"><i class="ti ti-search text-sm"></i> <span class="hidden md:inline">Find (Ctrl+F)</span></span>
                    <span onclick="editor.trigger('', 'editor.action.startFindReplaceAction')" class="cursor-pointer hover:underline flex items-center gap-1" title="Ganti kata"><i class="ti ti-replace text-sm"></i> <span class="hidden md:inline">Replace</span></span>
                </div>
            </div>
            <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
            <div class="flex gap-2 md:gap-4 hidden" id="save-action-bar">
                <span onclick="backupCurrentFile()" class="cursor-pointer hover:underline font-bold flex items-center gap-1 text-[var(--btn-text)] opacity-80 hover:opacity-100" title="Duplikasi jadi .bak"><i class="ti ti-copy text-sm"></i> <span class="hidden md:inline">Backup (.bak)</span></span>
                <span onclick="saveCurrentFile()" class="cursor-pointer hover:underline font-bold flex items-center gap-1"><i class="ti ti-device-floppy text-sm"></i> <span class="hidden md:inline">Save (Ctrl+S)</span></span>
            </div>
            <?php else: ?>
            <div class="flex gap-2 md:gap-4 hidden font-bold opacity-80" id="save-action-bar">
                <span><i class="ti ti-ban"></i> Mode Demo: Simpan Dinonaktifkan</span>
            </div>
            <?php endif; ?>
        </div>
    </main>

    <div id="context-menu" class="hidden absolute z-50 border shadow-2xl rounded py-1.5 text-sm min-w-[210px] max-w-[260px]"></div>

    <div id="modal-overlay" class="hidden fixed inset-0 bg-black/60 z-[100] flex items-center justify-center backdrop-blur-sm p-4 transition-opacity">
        <div id="modal-container" class="bg-[var(--bg-tab)] border border-theme rounded-xl shadow-2xl w-full max-w-[500px] max-h-[90vh] flex flex-col overflow-hidden text-[var(--text-main)] animate-scale-up">
            <div class="px-4 py-3 border-b border-theme font-bold flex justify-between items-center bg-[var(--bg-hover)]">
                <span id="modal-title">Judul Modal</span>
                <i class="ti ti-x cursor-pointer hover:text-danger text-lg" onclick="closeModal()"></i>
            </div>
            <div class="p-4 overflow-y-auto" id="modal-body"></div>
            <div class="px-4 py-3 border-t border-theme bg-[var(--bg-hover)] flex justify-end gap-2 flex-shrink-0" id="modal-footer">
                <button onclick="closeModal()" class="px-4 py-1.5 rounded text-sm hover-bg transition border border-theme">Batal</button>
                <button id="modal-btn-submit" class="px-4 py-1.5 bg-[var(--accent)] text-[var(--btn-text)] rounded text-sm font-semibold hover:opacity-80 transition">Simpan</button>
            </div>
        </div>
    </div>

    <div id="confirm-overlay" class="hidden fixed inset-0 bg-black/60 z-[150] flex items-center justify-center backdrop-blur-sm p-4 transition-opacity">
        <div class="bg-[var(--bg-tab)] border border-theme rounded-xl shadow-2xl w-full max-w-[380px] overflow-hidden text-[var(--text-main)] p-6 flex flex-col items-center text-center animate-scale-up">
            <div id="confirm-icon-box" class="w-14 h-14 rounded-full flex items-center justify-center mb-4 text-2xl shadow-inner">
                <i id="confirm-icon" class="ti ti-alert-triangle"></i>
            </div>
            <h3 id="confirm-title" class="font-bold text-lg mb-1 tracking-wide">Konfirmasi</h3>
            <p id="confirm-message" class="text-xs text-muted mb-6 leading-relaxed break-all">Pesan konfirmasi disini...</p>
            <div class="flex gap-3 w-full">
                <button id="confirm-btn-cancel" class="flex-1 py-2.5 rounded-lg text-xs font-medium border border-theme transition text-[var(--text-main)] active:scale-95 hover-bg">Batal</button>
                <button id="confirm-btn-yes" class="flex-1 py-2.5 rounded-lg text-xs font-bold shadow-lg transition active:scale-95 text-white">Ya, Lanjutkan</button>
            </div>
        </div>
    </div>

    <script>
        // Sistem Hook untuk ekstensi plugin internal
        window.IDEHooks = {
            hooks: {},
            add: function(action, callback) {
                if (!this.hooks[action]) this.hooks[action] = [];
                this.hooks[action].push(callback);
            },
            do: function(action, ...args) {
                if (this.hooks[action]) {
                    for (let cb of this.hooks[action]) {
                        if (cb(...args) === false) return false; 
                    }
                }
                return true;
            }
        };

        const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
        const USER_MODE = "<?php echo $current_user['mode'] ?? 'read-write'; ?>";
        const USER_ROLE = "<?php echo $current_user['role'] ?? 'user'; ?>";
        const isGuestMode = <?php echo $is_guest ? 'true' : 'false'; ?>;
        
        let APP_NAME = <?php echo json_encode($app_config['app_name']); ?>;
        let APP_LOGO = <?php echo json_encode($app_config['app_logo']); ?>;

        let editor; let tabs = {}; let activeTab = null; let activeContextElement = null; 
        let currentExplorerRoot = ''; 
        let selectedItems = new Set(); 
        let isMultiSelectMode = false;

        function getHeaders(extra = {}) {
            return Object.assign({ 'X-CSRF-Token': CSRF_TOKEN }, extra);
        }

        function logoutApp() {
            fetch('?auth_action=logout').then(() => window.location.reload());
        }

        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('mobile-overlay');
            if (sidebar.classList.contains('-translate-x-full')) {
                sidebar.classList.remove('-translate-x-full'); overlay.classList.remove('hidden');
            } else {
                sidebar.classList.add('-translate-x-full'); overlay.classList.add('hidden');
            }
        }

        function getMonacoThemeName(theme) {
            if (theme === 'light') return 'vs';
            if (theme === 'ocean') return 'theme-ocean';
            if (theme === 'terminal') return 'theme-terminal';
            return 'vs-dark'; // default untuk tema 'dark'
        }

        function applyThemeSilently(theme) {
            if (!theme) return;
            const currentTheme = document.body.getAttribute('data-theme');
            if (currentTheme === theme) return;

            document.body.setAttribute('data-theme', theme);
            const selector = document.getElementById('theme-selector');
            if (selector) selector.value = theme;
            
            if (typeof monaco !== 'undefined' && monaco.editor) {
                monaco.editor.setTheme(getMonacoThemeName(theme));
            }
            
            localStorage.setItem('ide_theme', theme);
        }

        let isThemeSyncing = false;

        function changeTheme(theme) {
            applyThemeSilently(theme);
            if(isGuestMode) return;
            isThemeSyncing = true;
            fetch(getApiUrl('save_theme', 'csrf_token=' + CSRF_TOKEN), { 
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ theme: theme }) 
            }).finally(() => { setTimeout(() => isThemeSyncing = false, 1000); });
        }

        setInterval(() => {
            if (!document.hidden && !isGuestMode && !isThemeSyncing) { 
                fetch(getApiUrl('check_theme')).then(r => r.json()).then(res => {
                    if (res.status === 'ok' && res.theme) applyThemeSilently(res.theme);
                }).catch(() => {});
            }
        }, 3000);

        window.addEventListener('storage', (e) => {
            if (e.key === 'ide_theme' && e.newValue) applyThemeSilently(e.newValue);
        });

        function toggleMultiSelectMode(autoSelectPath = null) {
            if (isMultiSelectMode) disableMultiSelectMode();
            else enableMultiSelectMode(autoSelectPath);
        }

        function enableMultiSelectMode(autoSelectPath = null) {
            isMultiSelectMode = true; document.body.classList.add('multi-select-active'); updateBatchActionBar();
            if (autoSelectPath) {
                selectedItems.add(autoSelectPath);
                const cb = document.querySelector(`input[data-path="${CSS.escape(autoSelectPath)}"]`);
                if (cb) cb.checked = true;
                updateBatchActionBar();
            }
        }

        function disableMultiSelectMode() {
            isMultiSelectMode = false; document.body.classList.remove('multi-select-active');
            selectedItems.clear(); document.querySelectorAll('.tree-checkbox').forEach(cb => cb.checked = false); updateBatchActionBar();
        }

        function toggleSelect(path, event) {
            event.stopPropagation(); const checkbox = event.target;
            if (checkbox.checked) selectedItems.add(path); else selectedItems.delete(path);
            updateBatchActionBar();
        }

        function updateBatchActionBar() {
            const bar = document.getElementById('batch-action-bar'); const count = document.getElementById('selected-count');
            if (isMultiSelectMode && selectedItems.size > 0) { bar.classList.remove('hidden'); count.innerText = selectedItems.size; } 
            else { bar.classList.add('hidden'); }
        }

        function showConfirm(title, message, isDanger = true, btnYesText = 'Ya, Lanjutkan') {
            return new Promise((resolve) => {
                const overlay = document.getElementById('confirm-overlay');
                const titleEl = document.getElementById('confirm-title');
                const msgEl = document.getElementById('confirm-message');
                const iconBox = document.getElementById('confirm-icon-box');
                const icon = document.getElementById('confirm-icon');
                const btnYes = document.getElementById('confirm-btn-yes');
                const btnCancel = document.getElementById('confirm-btn-cancel');

                titleEl.innerText = title; msgEl.innerHTML = message; btnYes.innerText = btnYesText;

                if (isDanger) {
                    iconBox.className = 'w-14 h-14 rounded-full bg-danger-soft flex items-center justify-center mb-4 text-2xl text-danger shadow-inner';
                    icon.className = 'ti ti-alert-triangle animate-bounce';
                    btnYes.className = 'flex-1 py-2.5 rounded-lg text-xs font-bold bg-[#ef4444] hover:opacity-90 text-white shadow-lg transition active:scale-95';
                } else {
                    iconBox.className = 'w-14 h-14 rounded-full bg-warning-soft flex items-center justify-center mb-4 text-2xl text-warning shadow-inner';
                    icon.className = 'ti ti-alert-circle';
                    btnYes.className = 'flex-1 py-2.5 rounded-lg text-xs font-bold bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] shadow-lg transition active:scale-95';
                }

                overlay.classList.remove('hidden');
                const cleanup = (result) => { overlay.classList.add('hidden'); btnYes.onclick = null; btnCancel.onclick = null; resolve(result); };
                btnYes.onclick = () => cleanup(true); btnCancel.onclick = () => cleanup(false);
            });
        }

        const getApiUrl = (action, params = '') => {
            const baseUrl = window.location.href.split('?')[0];
            let url = baseUrl + '?ajax=1&action=' + action + (params ? '&' + params : '');
            if (isGuestMode) url += '&embed=1'; 
            return url;
        };

        const dragHandle = document.getElementById('drag-handle');
        const sidebar = document.getElementById('sidebar');
        let isResizing = false;

        dragHandle.addEventListener('mousedown', () => { isResizing = true; document.body.style.cursor = 'col-resize'; });
        document.addEventListener('mousemove', (e) => {
            if (!isResizing || window.innerWidth <= 768) return;
            let newWidth = e.clientX;
            if (newWidth < 200) newWidth = 200; if (newWidth > 600) newWidth = 600;
            sidebar.style.width = newWidth + 'px'; if (editor) editor.layout();
        });
        document.addEventListener('mouseup', () => { isResizing = false; document.body.style.cursor = 'default'; });

        document.getElementById('search-input').addEventListener('input', function(e) {
            const term = e.target.value.toLowerCase();
            document.querySelectorAll('#file-tree .tree-item').forEach(li => {
                const name = li.querySelector('.truncate').innerText.toLowerCase(); 
                if (name.includes(term)) {
                    li.style.display = 'block'; let parentUl = li.closest('ul.folder-content');
                    while(parentUl) { parentUl.classList.remove('hidden'); parentUl = parentUl.parentElement.closest('ul.folder-content'); }
                } else { li.style.display = 'none'; }
            });
        });

        function batchZipDownload() {
            if (selectedItems.size === 0) return;
            document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memproses kompresi ZIP...`;
            fetch(getApiUrl('batch_zip'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ items: Array.from(selectedItems) })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check"></i> ZIP Berhasil Dibuat! Mengunduh...`;
                    window.open(res.zip_url, '_blank'); disableMultiSelectMode();
                } else {
                    alert(res.error || 'Gagal membuat file ZIP'); document.getElementById('status').innerHTML = `<i class="ti ti-alert-circle"></i> Gagal membuat ZIP`;
                }
            });
        }

        function drillDownFolder(path) {
            currentExplorerRoot = path; localStorage.setItem('ide_explorer_root', path);
            renderSidebarHeader(); loadFolder(path, document.getElementById('file-tree'), 0);
        }

        function drillUpFolder() {
            if (!currentExplorerRoot) return;
            const parent = currentExplorerRoot.substring(0, currentExplorerRoot.lastIndexOf('/'));
            currentExplorerRoot = parent; localStorage.setItem('ide_explorer_root', parent);
            renderSidebarHeader(); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0);
        }

        function renderSidebarHeader() {
            const header = document.getElementById('explorer-header');
            const createBtns = USER_ROLE === 'admin' ? `
                <span onclick="openModal('create', currentExplorerRoot, 'file')" class="cursor-pointer hover:text-accent" title="Buat File Baru"><i class="ti ti-file-plus"></i></span>
                <span onclick="openModal('create', currentExplorerRoot, 'folder')" class="cursor-pointer hover:text-accent" title="Buat Folder Baru"><i class="ti ti-folder-plus"></i></span>
            ` : '';
            if (currentExplorerRoot !== '') {
                header.innerHTML = `
                    <div class="flex items-center gap-1.5 text-warning font-bold truncate cursor-pointer hover:underline" onclick="drillUpFolder()" title="Kembali ke folder atas">
                        <i class="ti ti-arrow-left text-base"></i> <span class="truncate">${currentExplorerRoot.split('/').pop() || 'Root'}</span>
                    </div>
                    <div class="flex gap-2 text-base flex-shrink-0">
                        <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-accent" title="Pilih Banyak (Multi-Select)"><i class="ti ti-checkbox"></i></span>
                        <span onclick="drillDownFolder('')" class="cursor-pointer hover:text-accent" title="Ke Root Utama"><i class="ti ti-home"></i></span>
                        ${createBtns}
                        <span onclick="loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-accent font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
                    </div>
                `;
            } else {
                header.innerHTML = `
                    <span>Explorer</span>
                    <div class="flex gap-2 text-base">
                        <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-accent" title="Pilih Banyak (Multi-Select)"><i class="ti ti-checkbox"></i></span>
                        ${createBtns}
                        <span onclick="loadFolder('', document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-accent font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
                    </div>
                `;
            }
        }

        function openSettingsTab() {
            const tabId = '__SETTINGS__';
            tabs[tabId] = { type: 'settings', title: '⚙️ Settings', saved: true };
            switchTab(tabId);
        }

        function setupLocalAutocomplete(inputId, suggestions) {
            const input = document.getElementById(inputId); if (!input) return;
            let wrapper = input.parentNode; wrapper.style.position = 'relative';
            let listContainer = document.getElementById(inputId + '-ac-list');
            if (!listContainer) {
                listContainer = document.createElement('div'); listContainer.id = inputId + '-ac-list';
                listContainer.className = 'absolute z-[9999] left-0 top-full bg-[var(--bg-sidebar)] border border-theme w-full rounded-lg mt-1 shadow-2xl max-h-48 overflow-y-auto hidden animate-dropdown';
                wrapper.appendChild(listContainer);
            }
            input.addEventListener('input', function() {
                const val = this.value; const parts = val.split(','); const currentPart = parts[parts.length - 1].trim().toLowerCase();
                if (currentPart.length >= 1) {
                    const matches = suggestions.filter(s => s.toLowerCase().startsWith(currentPart) && !parts.slice(0, -1).map(p=>p.trim().toLowerCase()).includes(s.toLowerCase()));
                    if (matches.length > 0) {
                        listContainer.innerHTML = '';
                        matches.forEach(match => {
                            let div = document.createElement('div');
                            const icon = match === 'guest' ? '<i class="ti ti-user-circle text-warning"></i>' : (['admin','user'].includes(match) ? '<i class="ti ti-shield text-info"></i>' : '<i class="ti ti-user-check text-success"></i>');
                            div.innerHTML = `<div class="px-3 py-2 hover-bg cursor-pointer text-xs font-mono flex items-center gap-2 border-b border-theme transition-colors text-[var(--text-main)]">${icon} <span>${match}</span></div>`;
                            div.onclick = function() {
                                parts[parts.length - 1] = ' ' + match; input.value = parts.join(',').trim();
                                listContainer.classList.add('hidden'); input.focus();
                            };
                            listContainer.appendChild(div);
                        });
                        listContainer.classList.remove('hidden');
                    } else { listContainer.classList.add('hidden'); }
                } else { listContainer.classList.add('hidden'); }
            });
            document.addEventListener('click', function (e) {
                if (e.target !== input && !listContainer.contains(e.target)) listContainer.classList.add('hidden');
            });
        }

        // --- UI MANAJEMEN PLUGIN & USER ---
        function loadPluginManagementUI() {
            const container = document.getElementById('settings-plugin-content'); if(!container) return;
            fetch(getApiUrl('list_plugins')).then(r => r.json()).then(res => {
                if (res.error) { container.innerHTML = `<div class="p-4 bg-danger-soft text-sm rounded">${res.error}</div>`; return; }
                if (res.plugins.length === 0) {
                    container.innerHTML = `<div class="p-4 text-muted text-sm italic border border-theme rounded">Tidak ada plugin ditemukan di dalam folder /plugins.</div>`;
                    return;
                }
                let html = '<div class="space-y-4 overflow-visible">';
                res.plugins.forEach(p => {
                    html += `
                        <div class="flex flex-col p-3.5 bg-[var(--bg-sidebar)] rounded-lg border border-theme shadow-sm transition hover:border-[var(--accent)] relative overflow-visible group focus-within:z-[100]">
                            <div class="flex items-center justify-between mb-2.5">
                                <div class="flex items-center gap-3">
                                    <i class="ti ti-puzzle text-2xl ${p.active ? 'text-accent' : 'text-muted'}"></i>
                                    <div>
                                        <div class="font-bold text-[var(--text-main)]">${p.name}</div>
                                        <div class="text-[10px] text-muted font-mono">/plugins/${p.id}/</div>
                                    </div>
                                </div>
                                <label class="relative inline-flex items-center cursor-pointer">
                                    <input type="checkbox" id="plugin-active-${p.id}" class="sr-only peer" ${p.active ? 'checked' : ''}>
                                    <div class="w-9 h-5 bg-gray-400 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent)]"></div>
                                </label>
                            </div>
                            <div class="pl-9 pr-1">
                                <label class="block text-[10px] font-bold text-muted mb-1 flex items-center gap-1"><i class="ti ti-users text-xs"></i> Diizinkan Untuk (Username Terdaftar, 'admin', atau 'guest'):</label>
                                <div class="flex gap-2 relative overflow-visible">
                                    <input type="text" id="plugin-roles-${p.id}" value="${p.roles}" class="flex-1 border border-theme rounded px-2.5 py-1.5 text-xs font-mono" placeholder="Ketik nama akun terdaftar, misal: admin, arif, guest..." autocomplete="off">
                                    <button onclick="savePluginConfig('${p.id}')" class="bg-[var(--accent)] text-[var(--btn-text)] px-3 py-1 rounded text-xs font-bold hover:opacity-80 transition shadow flex items-center gap-1 flex-shrink-0"><i class="ti ti-device-floppy"></i> Simpan</button>
                                </div>
                            </div>
                        </div>
                    `;
                });
                html += '</div>'; container.innerHTML = html;
                res.plugins.forEach(p => { setupLocalAutocomplete(`plugin-roles-${p.id}`, res.suggestions || ['admin', 'user', 'guest']); });
            });
        }

        function savePluginConfig(pluginId) {
            const isActive = document.getElementById(`plugin-active-${pluginId}`).checked;
            const roles = document.getElementById(`plugin-roles-${pluginId}`).value.trim();
            fetch(getApiUrl('save_plugin_config'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ plugin_id: pluginId, active: isActive, roles: roles })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') {
                    if (confirm('Konfigurasi plugin berhasil disimpan! Muat ulang sistem agar efek perubahan berjalan maksimal?')) window.location.reload();
                    else loadPluginManagementUI();
                } else alert(res.error || 'Gagal mengubah konfigurasi plugin');
            });
        }

        function loadUserManagementUI() {
            const container = document.getElementById('settings-user-content'); if(!container) return;
            fetch(getApiUrl('list_users')).then(r => r.json()).then(res => {
                if (res.error) { container.innerHTML = `<div class="p-4 bg-danger-soft text-sm rounded">${res.error}</div>`; return; }
                let html = `
                    <div class="space-y-6">
                        <div class="bg-[var(--bg-main)] p-4 rounded-lg border border-theme shadow-inner">
                            <h4 class="font-bold text-sm uppercase text-info mb-3 flex items-center gap-2"><i class="ti ti-world"></i> Konfigurasi Link Embed / Guest</h4>
                            <div class="flex items-center gap-3 mb-4 bg-[var(--bg-hover)] p-3 rounded">
                                <input type="checkbox" id="guest-active" ${res.guest.is_active ? 'checked' : ''} class="cursor-pointer w-5 h-5 rounded">
                                <label class="text-sm font-bold text-[var(--text-main)] cursor-pointer" for="guest-active">Izinkan Akses Publik (?embed=1)</label>
                            </div>
                            <div class="relative w-full mb-4">
                                <label class="block text-xs text-muted mb-2 font-bold">Daftar Akses File & Folder Guest:</label>
                                <input type="text" id="guest-paths" value="${res.guest.allowed_paths.join(', ')}" class="w-full border border-theme rounded p-2 text-sm font-mono transition-colors" placeholder="/, /css/style.css" autocomplete="off">
                                <span class="text-[10px] text-muted mt-1 block">Pisahkan dengan koma. Ketik 1-2 huruf akan memunculkan autocompletion.</span>
                            </div>
                            <button onclick="executeUpdateGuest()" class="py-2 px-4 bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] rounded text-sm font-bold transition shadow active:scale-95 flex items-center justify-center gap-2 w-fit"><i class="ti ti-device-floppy"></i> Simpan Konfigurasi Guest</button>
                        </div>
                        
                        <div class="bg-[var(--bg-main)] p-4 rounded-lg border border-theme shadow-inner">
                            <h4 class="font-bold text-sm uppercase text-accent mb-3 flex items-center gap-2"><i class="ti ti-user-plus"></i> Tambah User Baru</h4>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                <div><label class="block text-xs text-muted mb-1 font-bold">Username</label><input type="text" id="new-u-name" placeholder="Ketik username..." class="w-full border border-theme rounded p-2 text-sm"></div>
                                <div><label class="block text-xs text-muted mb-1 font-bold">Password</label><input type="password" id="new-u-pass" placeholder="Ketik password..." class="w-full border border-theme rounded p-2 text-sm"></div>
                            </div>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                <div>
                                    <label class="block text-xs text-muted mb-1 font-bold">Mode Akses (RBAC):</label>
                                    <select id="new-u-mode" class="w-full border border-theme rounded p-2 text-sm">
                                        <option value="read-write">Normal (Bisa Edit, Simpan, Hapus)</option>
                                        <option value="read-only">Demo (Hanya Bisa Buka / Read-Only)</option>
                                    </select>
                                </div>
                                <div class="relative w-full">
                                    <label class="block text-xs text-muted mb-1 font-bold">Daftar Akses Path:</label>
                                    <input type="text" id="new-u-paths" placeholder="/, /js/main.js" class="w-full border border-theme rounded p-2 text-sm font-mono" autocomplete="off">
                                </div>
                            </div>
                            <button onclick="executeAddUser()" class="py-2 px-4 bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] rounded text-sm font-bold transition shadow active:scale-95 flex items-center justify-center gap-2 w-fit"><i class="ti ti-plus"></i> Tambahkan User</button>
                        </div>
                        
                        <div class="bg-[var(--bg-main)] p-4 rounded-lg border border-theme shadow-inner">
                            <h4 class="font-bold text-sm uppercase text-[var(--text-main)] mb-3 flex items-center gap-2"><i class="ti ti-users"></i> Daftar User Terdaftar</h4>
                            <div class="space-y-3">
                `;
                res.users.forEach(u => {
                    const delBtn = u.role === 'admin' ? '' : `<button onclick="executeDeleteUser('${u.username}')" class="text-danger hover-bg p-2 rounded transition border border-transparent hover:border-red-500/30" title="Hapus User"><i class="ti ti-trash"></i></button>`;
                    const modeBadge = u.mode === 'read-only' ? '<span class="bg-warning-soft text-[10px] px-2 py-0.5 rounded font-mono">DEMO</span>' : '<span class="bg-success-soft text-[10px] px-2 py-0.5 rounded font-mono">NORMAL</span>';
                    html += `
                        <div class="flex items-center justify-between p-3 bg-[var(--bg-sidebar)] rounded border border-theme text-sm shadow-sm">
                            <div class="min-w-0 flex-1 mr-4">
                                <div class="font-bold truncate flex items-center gap-2 mb-1">
                                    <i class="ti ti-user text-muted"></i> ${u.username} 
                                    <span class="bg-info-soft text-[10px] px-2 py-0.5 rounded uppercase font-mono">${u.role}</span>${modeBadge}
                                </div>
                                <div class="text-xs text-muted font-mono truncate" title="Akses: ${u.allowed_paths}">Akses Root: <span class="text-warning">${u.allowed_paths}</span></div>
                            </div>
                            ${delBtn}
                        </div>
                    `;
                });
                html += '</div></div></div>'; container.innerHTML = html;
                setupAutocomplete('guest-paths'); setupAutocomplete('new-u-paths');
            });
        }

        function handleLogoUpload(input) {
            if (input.files && input.files[0]) {
                const file = input.files[0];
                if (file.size > 1024 * 500) { alert('Ukuran logo maksimal 500KB untuk menjaga efisiensi config.'); return; }
                const reader = new FileReader();
                reader.onload = function(e) {
                    document.getElementById('set-app-logo').value = e.target.result;
                    const previewBox = document.getElementById('logo-preview-box');
                    previewBox.innerHTML = `<img src="${e.target.result}" class="h-16 object-contain rounded bg-[var(--bg-hover)] border border-theme p-2">`;
                };
                reader.readAsDataURL(file);
            }
        }

        function saveAppConfig() {
            const btn = document.getElementById('btn-save-identitas');
            const origText = btn.innerHTML;
            btn.innerHTML = '<i class="ti ti-loader-2 animate-spin"></i> Menyimpan...'; btn.disabled = true;

            const newName = document.getElementById('set-app-name').value.trim();
            const newLogo = document.getElementById('set-app-logo').value.trim();
            
            fetch(getApiUrl('save_config'), { 
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), 
                body: JSON.stringify({ app_name: newName, app_logo: newLogo }) 
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { 
                    APP_NAME = res.app_name; APP_LOGO = res.app_logo;
                    alert('Konfigurasi Identitas Aplikasi Berhasil Disimpan!\nHalaman akan dimuat ulang untuk menerapkan perubahan.');
                    window.location.reload();
                } else alert(res.error || 'Gagal menyimpan konfigurasi identitas.');
            }).finally(() => { btn.innerHTML = origText; btn.disabled = false; });
        }

        function executeChangePassword() {
            const old_pw = document.getElementById('pw-old').value; const new_pw = document.getElementById('pw-new').value;
            if(!old_pw || !new_pw) return alert('Semua kolom wajib diisi!');
            fetch(getApiUrl('change_pw'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ old_password: old_pw, new_password: new_pw })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { 
                    alert('Password berhasil diubah!'); 
                    document.getElementById('pw-old').value = ''; document.getElementById('pw-new').value = '';
                } else alert(res.error || 'Gagal mengubah password');
            });
        }

        let currentModalAction = null; let modalTargetPath = '';

        function setupAutocomplete(inputId) {
            const input = document.getElementById(inputId); if (!input) return;
            let wrapper = input.parentNode; wrapper.style.position = 'relative'; 
            let listContainer = document.getElementById(inputId + '-ac-list');
            if (!listContainer) {
                listContainer = document.createElement('div'); listContainer.id = inputId + '-ac-list';
                listContainer.className = 'absolute z-[9999] bg-[var(--bg-sidebar)] border border-theme w-full rounded-lg mt-1 shadow-2xl max-h-48 overflow-y-auto hidden animate-dropdown';
                wrapper.appendChild(listContainer);
            }
            input.addEventListener('input', function() {
                const val = this.value; const parts = val.split(','); const currentPart = parts[parts.length - 1].trim();
                if (currentPart.length >= 1) { 
                    fetch(getApiUrl('autocomplete', 'query=' + encodeURIComponent(currentPart))).then(r => r.json()).then(res => {
                        if (res.status === 'ok' && res.results.length > 0) {
                            listContainer.innerHTML = '';
                            res.results.forEach(item => {
                                let div = document.createElement('div');
                                const icon = item.type === 'folder' ? '<i class="ti ti-folder text-warning"></i>' : '<i class="ti ti-file text-info"></i>';
                                div.innerHTML = `<div class="px-3 py-2 hover-bg cursor-pointer text-[11px] font-mono flex items-center gap-2 border-b border-theme transition-colors">${icon} <span class="truncate">${item.path}</span></div>`;
                                div.onclick = function() {
                                    parts[parts.length - 1] = ' ' + item.path; input.value = parts.join(',').trim();
                                    listContainer.classList.add('hidden'); input.focus();
                                };
                                listContainer.appendChild(div);
                            });
                            listContainer.classList.remove('hidden');
                        } else { listContainer.classList.add('hidden'); }
                    });
                } else { listContainer.classList.add('hidden'); }
            });
            document.addEventListener('click', function (e) {
                if (e.target !== input && !listContainer.contains(e.target)) listContainer.classList.add('hidden');
            });
        }

        // --- SISTEM MODAL UTAMA ---
        function openModal(action, path = '', type = '') {
            if (USER_MODE === 'read-only' && ['create', 'rename', 'upload', 'remote', 'batch_copy_move', 'copy_move_single'].includes(action)) {
                return alert('Akses Ditolak! Akun Anda berada dalam Mode Read-Only / Demo.');
            }
            if (action === 'create' && USER_ROLE !== 'admin') {
                return alert('Akses Ditolak! Hanya Admin yang diizinkan membuat file atau folder baru.');
            }
            const overlay = document.getElementById('modal-overlay'); const title = document.getElementById('modal-title'); const body = document.getElementById('modal-body'); const btn = document.getElementById('modal-btn-submit'); const footer = document.getElementById('modal-footer');
            modalTargetPath = path || currentExplorerRoot; currentModalAction = { action, type }; footer.classList.remove('hidden');
            
            if (action === 'create') {
                title.innerText = type === 'folder' ? 'Buat Folder Baru' : 'Buat File Baru';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Lokasi: ${modalTargetPath || '/'}</label><input type="text" id="modal-input-name" class="w-full border border-theme rounded p-2 text-sm" placeholder="Nama ${type}...">`;
                btn.innerText = 'Buat'; btn.onclick = executeCreate;
            } else if (action === 'rename') {
                title.innerText = 'Ganti Nama'; const oldName = path.split('/').pop();
                body.innerHTML = `<input type="text" id="modal-input-name" class="w-full border border-theme rounded p-2 text-sm" value="${oldName}">`;
                btn.innerText = 'Simpan'; btn.onclick = executeRename;
            } else if (action === 'upload') {
                title.innerText = 'Upload File';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Ke Lokasi: ${modalTargetPath || '/'}</label><input type="file" id="modal-input-file" class="w-full border border-theme rounded p-2 text-sm cursor-pointer">`;
                btn.innerText = 'Upload'; btn.onclick = executeUpload;
            } else if (action === 'remote') {
                title.innerText = 'Download dari URL';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Simpan ke: ${modalTargetPath || '/'}</label><input type="url" id="modal-input-url" class="w-full border border-theme rounded p-2 text-sm" placeholder="https://contoh.com/gambar.jpg">`;
                btn.innerText = 'Download'; btn.onclick = executeRemoteDownload;
            } else if (action === 'batch_copy_move') {
                title.innerText = `Copy / Move (${selectedItems.size} Item Terpilih)`;
                body.innerHTML = `
                    <label class="block text-xs mb-1 opacity-70">Folder Tujuan (Kosongkan jika ke Root):</label>
                    <input type="text" id="modal-input-dest" class="w-full border border-theme rounded p-2 text-sm mb-4" placeholder="contoh: folder/backup" value="${currentExplorerRoot}">
                    <label class="block text-xs mb-1 opacity-70">Pilih Mode Tindakan:</label>
                    <div class="flex gap-3">
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs border border-theme px-3 py-2 rounded flex-1 transition hover-bg"><input type="radio" name="batch-mode" value="copy" checked> <i class="ti ti-copy text-info"></i> Copy</label>
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs border border-theme px-3 py-2 rounded flex-1 transition hover-bg"><input type="radio" name="batch-mode" value="move"> <i class="ti ti-cut text-danger"></i> Move</label>
                    </div>
                `;
                btn.innerText = 'Proses'; btn.onclick = executeBatchCopyMove;
            } else if (action === 'copy_move_single') {
                title.innerText = `Copy / Move: ${path.split('/').pop()}`;
                body.innerHTML = `
                    <div class="p-2.5 rounded border border-theme text-xs mb-4 font-mono truncate text-warning"><i class="ti ti-file text-sm"></i> Item: ${path}</div>
                    <label class="block text-xs mb-1 opacity-70">Folder Tujuan:</label>
                    <input type="text" id="modal-input-dest" class="w-full border border-theme rounded p-2 text-sm mb-4" placeholder="contoh: folder_backup" value="${currentExplorerRoot}">
                    <div class="flex gap-3">
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs border border-theme px-3 py-2 rounded flex-1 transition hover-bg"><input type="radio" name="single-mode" value="copy" checked> <i class="ti ti-copy text-info"></i> Copy</label>
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs border border-theme px-3 py-2 rounded flex-1 transition hover-bg"><input type="radio" name="single-mode" value="move"> <i class="ti ti-cut text-danger"></i> Move</label>
                    </div>
                `;
                btn.innerText = 'Eksekusi'; btn.onclick = () => executeSingleCopyMove(path);
            }
            overlay.classList.remove('hidden');
            setTimeout(() => { if(document.getElementById('modal-input-name')) document.getElementById('modal-input-name').focus(); }, 100);
        }

        function closeModal() { document.getElementById('modal-overlay').classList.add('hidden'); }

        function executeUpdateGuest() {
            const isActive = document.getElementById('guest-active').checked; const paths = document.getElementById('guest-paths').value.trim();
            fetch(getApiUrl('update_guest'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ is_active: isActive, allowed_paths: paths })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { alert('Konfigurasi Embed Guest berhasil disimpan!'); loadUserManagementUI(); } else alert(res.error || 'Gagal menyimpan konfigurasi');
            });
        }

        function executeAddUser() {
            const uname = document.getElementById('new-u-name').value.trim(); const pass = document.getElementById('new-u-pass').value; const mode = document.getElementById('new-u-mode').value; const paths = document.getElementById('new-u-paths').value.trim();
            if(!uname || !pass) return alert('Username & Password wajib diisi!');
            fetch(getApiUrl('add_user'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ username: uname, password: pass, mode: mode, allowed_paths: paths })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') loadUserManagementUI(); else alert(res.error || 'Gagal menambah user');
            });
        }

        function executeDeleteUser(uname) {
            if(!confirm(`Hapus user "${uname}" permanen?`)) return;
            fetch(getApiUrl('delete_user'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ username: uname })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') loadUserManagementUI(); else alert(res.error || 'Gagal menghapus user');
            });
        }

        function showMetadataModal(path, type) {
            if (isGuestMode) {
                return alert('Akses Ditolak: Detail metadata server dinonaktifkan pada akses publik (Guest Mode) demi keamanan jaringan!');
            }
            const overlay = document.getElementById('modal-overlay'); const title = document.getElementById('modal-title'); const body = document.getElementById('modal-body'); const footer = document.getElementById('modal-footer');
            title.innerText = `Detail Metadata ${type === 'folder' ? 'Folder' : 'File'}`;
            body.innerHTML = `<div class="py-8 text-center text-xs opacity-70"><i class="ti ti-loader-2 animate-spin text-2xl mb-2 inline-block"></i><br>Mengambil data metadata dari server...</div>`;
            footer.classList.remove('hidden'); footer.innerHTML = '<button onclick="closeModal()" class="px-4 py-1.5 rounded text-sm transition hover-bg border border-theme w-full text-center block text-[var(--text-main)]">Tutup</button>'; 
            overlay.classList.remove('hidden');
            fetch(getApiUrl('info', 'path=' + encodeURIComponent(path))).then(r => r.json()).then(data => {
                if (data.error) { body.innerHTML = `<div class="p-4 text-danger text-center text-xs">${data.error}</div>`; return; }
                const icon = type === 'folder' ? '<i class="ti ti-folder text-warning text-3xl"></i>' : getFileInfo(data.name).icon.replace('<i', '<i class="text-3xl"');
                let extraRow = type === 'folder' ? `<div class="flex justify-between py-1.5 border-b border-theme"><span class="text-muted font-medium">Isi Kandungan:</span><span class="font-bold text-warning">${data.contents || 'Kosong'}</span></div>` : (data.dimensions && data.dimensions !== 'N/A' ? `<div class="flex justify-between py-1.5 border-b border-theme"><span class="text-muted font-medium">Resolusi Gambar:</span><span class="font-bold text-info">${data.dimensions}</span></div>` : '');
                body.innerHTML = `
                    <div class="flex items-center gap-3 p-3 rounded-lg border border-theme mb-4">
                        <div class="text-3xl flex-shrink-0">${icon}</div>
                        <div class="min-w-0 flex-1"><h4 class="font-bold text-sm truncate" title="${data.name}">${data.name}</h4><span class="text-[11px] text-muted font-mono">${data.mime || type}</span></div>
                    </div>
                    <div class="text-xs space-y-1 font-mono">
                        <div class="py-1.5 border-b border-theme"><span class="text-muted block text-[10px] uppercase font-bold mb-0.5">Full Path Lokasi:</span><span class="font-bold text-warning block truncate select-all p-1.5 rounded border border-theme bg-[var(--bg-hover)]" title="${data.full_path}">${data.full_path}</span></div>
                        <div class="flex justify-between py-1.5 border-b border-theme"><span class="text-muted font-medium">Ukuran (Size):</span><span class="font-bold text-success">${data.size}</span></div>
                        ${extraRow}
                        <div class="flex justify-between py-1.5 border-b border-theme"><span class="text-muted font-medium">Terakhir Diubah:</span><span class="font-bold text-info">${data.modified || 'N/A'}</span></div>
                        <div class="flex justify-between py-1.5"><span class="text-muted font-medium">Hak Akses (Chmod):</span><span class="font-bold text-danger px-2 py-0.5 rounded border border-theme bg-[var(--bg-hover)]">${data.permissions || '0755'}</span></div>
                    </div>
                `;
            }).catch(() => { body.innerHTML = `<div class="p-4 text-danger text-center text-xs">Gagal mengambil data dari server.</div>`; });
        }

        function executeCreate() {
            if(USER_ROLE !== 'admin') return alert('Hanya Admin yang diizinkan membuat item baru!');
            const name = document.getElementById('modal-input-name').value.trim(); if(!name) return;
            const fullPath = (modalTargetPath ? modalTargetPath + '/' : '') + name;
            fetch(getApiUrl('create'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ path: fullPath, type: currentModalAction.type })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') { loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal(); } else alert(res.error || 'Gagal membuat item');
            });
        }

        function executeRename() {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat merename!');
            const newName = document.getElementById('modal-input-name').value.trim(); if(!newName) return;
            const parent = modalTargetPath.substring(0, modalTargetPath.lastIndexOf('/'));
            const newPath = (parent ? parent + '/' : '') + newName;
            fetch(getApiUrl('rename'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ old_path: modalTargetPath, new_path: newPath })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    if (tabs[modalTargetPath]) {
                        tabs[newPath] = tabs[modalTargetPath]; delete tabs[modalTargetPath];
                        if (activeTab === modalTargetPath) activeTab = newPath;
                        renderTabs(); saveSession();
                    }
                    loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal();
                } else alert(res.error || 'Gagal merename');
            });
        }

        function executeUpload() {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat mengupload!');
            const fileInput = document.getElementById('modal-input-file'); if(!fileInput.files.length) return;
            document.getElementById('modal-btn-submit').innerText = 'Mengupload...';
            const formData = new FormData(); formData.append('file', fileInput.files[0]); formData.append('path', modalTargetPath); formData.append('csrf_token', CSRF_TOKEN);
            fetch(getApiUrl('upload'), { method: 'POST', headers: { 'X-CSRF-Token': CSRF_TOKEN }, body: formData }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal(); } else alert(res.error);
            }).catch(() => alert('Terjadi kesalahan saat upload.'));
        }

        function executeRemoteDownload() {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat mendownload URL!');
            const url = document.getElementById('modal-input-url').value.trim(); if(!url) return;
            document.getElementById('modal-btn-submit').innerText = 'Mendownload...';
            fetch(getApiUrl('remote_download'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ url: url, path: modalTargetPath })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal(); } else alert(res.error);
            }).catch(() => alert('Terjadi kesalahan koneksi.'));
        }

        function executeBatchCopyMove() {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat memproses Copy/Move!');
            const dest = document.getElementById('modal-input-dest').value.trim(); const mode = document.querySelector('input[name="batch-mode"]:checked').value;
            document.getElementById('modal-btn-submit').innerText = 'Memproses...';
            fetch(getApiUrl('batch_action'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ items: Array.from(selectedItems), dest: dest, mode: mode })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') { disableMultiSelectMode(); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal(); } else alert(res.error || 'Gagal memproses aksi');
            });
        }

        function executeSingleCopyMove(itemPath) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat memproses Copy/Move!');
            const dest = document.getElementById('modal-input-dest').value.trim(); const mode = document.querySelector('input[name="single-mode"]:checked').value;
            document.getElementById('modal-btn-submit').innerText = 'Memproses...';
            fetch(getApiUrl('batch_action'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ items: [itemPath], dest: dest, mode: mode })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-success"></i> Berhasil di-${mode === 'copy' ? 'copy' : 'move'}: ${itemPath}`;
                    loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal();
                } else alert(res.error || 'Gagal memproses aksi copy/move');
            });
        }

        function backupItem(filePath) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat membuat file backup (.bak)!');
            document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Membuat backup: ${filePath}...`;
            fetch(getApiUrl('backup'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ path: filePath })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-success"></i> Backup sukses: ${res.backup_file}`;
                    loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0);
                    setTimeout(() => { if (activeTab === filePath) document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Editing: ${filePath}`; }, 3000);
                } else {
                    alert(res.error || 'Gagal membuat file backup (.bak)!'); document.getElementById('status').innerHTML = `<i class="ti ti-alert-circle text-danger"></i> Gagal backup file`;
                }
            }).catch(() => { alert('Terjadi kesalahan koneksi saat proses backup.'); });
        }

        function backupCurrentFile() { if (activeTab && tabs[activeTab] && tabs[activeTab].type === 'code') backupItem(activeTab); }

        const contextMenu = document.getElementById('context-menu');
        function clearContextMenuHighlight() { if (activeContextElement) { activeContextElement.classList.remove('bg-[var(--accent)]', 'text-[var(--btn-text)]'); activeContextElement = null; } }

        window.addEventListener('click', () => { contextMenu.classList.add('hidden'); clearContextMenuHighlight(); }, true);
        window.addEventListener('contextmenu', (e) => { if (!e.target.closest('aside') && !e.target.closest('#context-menu')) { contextMenu.classList.add('hidden'); clearContextMenuHighlight(); } }, true);

        function showContextMenu(e, path, type, element) {
            e.preventDefault(); e.stopPropagation(); clearContextMenuHighlight(); 
            if (element && type !== 'root') { activeContextElement = element; activeContextElement.classList.add('bg-[var(--accent)]', 'text-[var(--btn-text)]'); }
            contextMenu.innerHTML = ''; let menuHTML = '';
            const createItem = (icon, text, onClickFunc, extraClass='') => { return `<div class="px-4 py-2 hover-bg cursor-pointer flex items-center gap-2.5 transition-colors ${extraClass}" onclick="document.getElementById('context-menu').classList.add('hidden'); clearContextMenuHighlight(); ${onClickFunc}"><i class="${icon} text-[16px]"></i> <span>${text}</span></div>`; };
            const createDivider = () => `<div class="border-t border-theme my-1 mx-1"></div>`;

            if (type !== 'root') { menuHTML += createItem('ti ti-checkbox text-accent font-bold', 'Pilih Banyak (Multi-Select)', `enableMultiSelectMode('${path}');`); menuHTML += createDivider(); }

            if (type === 'folder' || type === 'root') {
                if (type === 'folder') {
                    menuHTML += createItem('ti ti-folder-open text-warning font-bold', 'Buka Full di Sidebar', `drillDownFolder('${path}');`);
                    if (USER_MODE !== 'read-only') { menuHTML += createItem('ti ti-copy text-info font-bold', 'Copy / Move ke Folder Lain', `openModal('copy_move_single', '${path}', 'folder');`); }
                    if (!isGuestMode) { menuHTML += createItem('ti ti-info-circle text-info font-bold', 'Detail & Metadata Folder', `showMetadataModal('${path}', 'folder');`); }
                    menuHTML += createDivider();
                }
                if (USER_ROLE === 'admin') {
                    menuHTML += createItem('ti ti-file-plus font-semibold text-success', 'Buat File Baru', `openModal('create', '${path}', 'file');`);
                    menuHTML += createItem('ti ti-folder-plus font-semibold text-warning', 'Buat Folder Baru', `openModal('create', '${path}', 'folder');`);
                }
                if (USER_MODE !== 'read-only') {
                    menuHTML += createItem('ti ti-upload', 'Upload File Kesini', `openModal('upload', '${path}');`);
                    menuHTML += createItem('ti ti-cloud-download', 'Download URL Kesini', `openModal('remote', '${path}');`);
                }
            }
            if (type !== 'root') {
                if (type === 'folder' && USER_MODE !== 'read-only') menuHTML += createDivider();
                if (type === 'file') {
                    menuHTML += createItem('ti ti-external-link text-accent font-bold', 'Buka File Langsung (Tab Baru)', `window.open(getApiUrl('raw', 'path=' + encodeURIComponent('${path}')), '_blank')`);
                    if (USER_MODE !== 'read-only') {
                        menuHTML += createItem('ti ti-copy text-warning font-bold', 'Buat Backup (.bak)', `backupItem('${path}')`);
                        menuHTML += createItem('ti ti-copy text-info font-bold', 'Copy / Move ke Folder Lain', `openModal('copy_move_single', '${path}', 'file');`);
                    }
                    if (!isGuestMode) { menuHTML += createItem('ti ti-info-circle text-info font-bold', 'Detail & Metadata File', `showMetadataModal('${path}', 'file');`); }
                    menuHTML += createItem('ti ti-download', 'Download File', `window.open(getApiUrl('download', 'path=' + encodeURIComponent('${path}')), '_blank')`);
                    if (USER_MODE !== 'read-only') menuHTML += createDivider();
                }
                if (USER_MODE !== 'read-only') {
                    menuHTML += createItem('ti ti-pencil', 'Ganti Nama (Rename)', `openModal('rename', '${path}');`);
                    menuHTML += createDivider();
                    menuHTML += createItem('ti ti-trash text-danger font-bold', '<span class="text-danger">Hapus Permanen</span>', `deleteItem('${path}');`);
                }
            }

            contextMenu.innerHTML = menuHTML; let x = e.clientX; let y = e.clientY; contextMenu.classList.remove('hidden');
            const menuRect = contextMenu.getBoundingClientRect();
            if (x + menuRect.width > window.innerWidth) x -= menuRect.width;
            if (y + menuRect.height > window.innerHeight) y -= menuRect.height;
            contextMenu.style.left = `${x}px`; contextMenu.style.top = `${y}px`;
        }

        function saveSession() {
            const codeFiles = Object.keys(tabs).filter(f => tabs[f].type === 'code' && f !== '__SETTINGS__');
            const activeIsCode = activeTab && tabs[activeTab] && tabs[activeTab].type === 'code';
            const sessionData = { files: codeFiles, active: activeIsCode ? activeTab : (codeFiles[codeFiles.length - 1] || null) };
            localStorage.setItem('ide_session', JSON.stringify(sessionData));
        }

        function restoreSession() {
            const savedTheme = "<?php echo $current_user['theme'] ?? 'dark'; ?>";
            if(savedTheme && savedTheme !== 'custom') { document.getElementById('theme-selector').value = savedTheme; applyThemeSilently(savedTheme); }
            try {
                const sessionData = localStorage.getItem('ide_session');
                if (sessionData) {
                    const { files, active } = JSON.parse(sessionData);
                    files.forEach(file => { openFile(file, null, file !== active); });
                    if(activeTab === null) showEmptyState();
                } else showEmptyState();
            } catch (e) { showEmptyState(); }
        }

        document.addEventListener('DOMContentLoaded', () => {
            const savedRoot = localStorage.getItem('ide_explorer_root'); if (savedRoot !== null) currentExplorerRoot = savedRoot;
            renderSidebarHeader(); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); restoreSession();
        });

        require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' }});
        require(['vs/editor/editor.main'], () => {
            
            // ============================================================================
            // TEMA: "Ocean" — Tema Editor Bergaya Deep Ocean / Material Ocean
            // ============================================================================
            // Deskripsi : Tema biru gelap terinspirasi warna laut dalam, dengan aksen
            //             warna-warni pastel (biru, hijau, oranye, kuning) pada syntax
            //             highlighting, cocok untuk mata yang nyaman di sesi coding lama.
            // Base      : vs-dark (mewarisi seluruh rules & warna default VS Dark)
            // Dipakai   : Saat user memilih tema "Ocean" di dropdown Tema UI (sidebar)
            // Cara pakai: monaco.editor.setTheme('theme-ocean')
            // ============================================================================
            monaco.editor.defineTheme('theme-ocean', {
                base: 'vs-dark',   // Tema dasar yang diwarisi sebelum rules di bawah diterapkan
                inherit: true,     // true = gabungkan rules ini dengan rules bawaan 'vs-dark'

                // --- ATURAN WARNA PER TOKEN SYNTAX (Syntax Highlighting Rules) ---
                rules: [
                    { token: 'comment', foreground: '546e7a', fontStyle: 'italic' }, // Komentar kode: biru abu-abu miring
                    { token: 'keyword', foreground: '82aaff', fontStyle: 'bold' },   // Keyword (if, function, dll): biru cerah tebal
                    { token: 'string', foreground: 'c3e88d' },                       // String/teks dalam kutip: hijau pastel
                    { token: 'number', foreground: 'f78c6c' },                       // Angka/numerik: oranye salmon
                    { token: 'type', foreground: 'ffcb6b' },                         // Tipe data (int, string, dll): kuning keemasan
                    { token: 'identifier', foreground: '8f93a2' },                   // Nama variabel/fungsi: abu-abu kebiruan
                    { token: 'delimiter', foreground: '8f93a2' },                    // Simbol pemisah (, ; { } dll): abu-abu kebiruan
                    { token: 'tag', foreground: 'f07178' },                          // Tag HTML/XML (<div>): merah muda salmon
                    { token: 'attribute.name', foreground: 'c792ea' }                // Atribut HTML (class=, id=): ungu pastel
                ],

                // --- WARNA ELEMEN UTAMA EDITOR (Background, Cursor, dll) ---
                colors: {
                    'editor.background': '#0f111a',               // Background editor: biru dongker gelap (ciri khas ocean theme)
                    'editor.foreground': '#8f93a2',               // Warna teks default: abu-abu kebiruan
                    'editorCursor.foreground': '#82aaff',         // Warna kursor blink: biru cerah
                    'editor.lineHighlightBackground': '#1a1c23',  // Highlight baris aktif: biru gelap sedikit terang
                    'editorLineNumber.foreground': '#546e7a',     // Warna nomor baris: biru abu-abu redup
                    'editor.selectionBackground': '#82aaff33',    // Warna blok teks yang diseleksi (transparan biru)
                    'editorIndentGuide.background': '#1e212b',    // Garis bantu indentasi
                    'editorGutter.background': '#0f111a'          // Background area gutter (kiri, tempat nomor baris)
                }
            });

            // ============================================================================
            // TEMA: "Terminal" — Tema Editor Bergaya Terminal/Console Klasik
            // ============================================================================
            // Deskripsi : Tema hitam pekat terinspirasi tampilan terminal/console lama,
            //             dengan aksen warna teal (#4ec9b0) khas VS Code Dark+ pada
            //             keyword & tipe data, cocok untuk suasana coding minimalis.
            // Base      : vs-dark (mewarisi seluruh rules & warna default VS Dark)
            // Dipakai   : Saat user memilih tema "Terminal" di dropdown Tema UI (sidebar)
            // Cara pakai: monaco.editor.setTheme('theme-terminal')
            // ============================================================================
            monaco.editor.defineTheme('theme-terminal', {
                base: 'vs-dark',   // Tema dasar yang diwarisi sebelum rules di bawah diterapkan
                inherit: true,     // true = gabungkan rules ini dengan rules bawaan 'vs-dark'

                // --- ATURAN WARNA PER TOKEN SYNTAX (Syntax Highlighting Rules) ---
                rules: [
                    { token: 'comment', foreground: '808080', fontStyle: 'italic' }, // Komentar kode: abu-abu miring
                    { token: 'keyword', foreground: '4ec9b0', fontStyle: 'bold' },   // Keyword (if, function, dll): teal tebal
                    { token: 'string', foreground: 'ce9178' },                       // String/teks dalam kutip: oranye soft
                    { token: 'number', foreground: 'b5cea8' },                       // Angka/numerik: hijau muda
                    { token: 'type', foreground: '4ec9b0' },                         // Tipe data (int, string, dll): teal
                    { token: 'identifier', foreground: 'd4d4d4' },                   // Nama variabel/fungsi: putih keabuan
                    { token: 'delimiter', foreground: 'd4d4d4' },                    // Simbol pemisah (, ; { } dll): putih keabuan
                    { token: 'tag', foreground: '569cd6' },                          // Tag HTML/XML (<div>): biru
                    { token: 'attribute.name', foreground: '9cdcfe' }                // Atribut HTML (class=, id=): biru muda
                ],

                // --- WARNA ELEMEN UTAMA EDITOR (Background, Cursor, dll) ---
                colors: {
                    'editor.background': '#000000',              // Background editor: hitam pekat (ciri khas terminal)
                    'editor.foreground': '#d4d4d4',               // Warna teks default
                    'editorCursor.foreground': '#4ec9b0',         // Warna kursor blink: teal
                    'editor.lineHighlightBackground': '#111111',  // Highlight baris aktif: hitam sedikit terang
                    'editorLineNumber.foreground': '#555555',     // Warna nomor baris: abu-abu gelap
                    'editor.selectionBackground': '#4ec9b033',    // Warna blok teks yang diseleksi (transparan teal)
                    'editorIndentGuide.background': '#333333',    // Garis bantu indentasi
                    'editorGutter.background': '#000000'          // Background area gutter (kiri, tempat nomor baris)
                }
            });

            const currentUITheme = document.body.getAttribute('data-theme') || 'dark';
            editor = monaco.editor.create(document.getElementById('editor'), { 
                theme: getMonacoThemeName(currentUITheme),
                automaticLayout: true, 
                fontSize: 14, 
                model: null,
                readOnly: USER_MODE === 'read-only',
                find: { addExtraClassToFindWidget: true, seedSearchStringFromSelection: 'always', autoSelectWithPaste: true },
                
                // --- PENGATURAN "FULL MENTOK" KE KANAN ---
                padding: { top: 10, bottom: 10 }, // Menghapus padding kiri/kanan agar editor full width
                minimap: { 
                    enabled: true, 
                    side: 'right',
                    showSlider: 'always' 
                },
                scrollbar: {
                    vertical: 'visible',
                    verticalScrollbarSize: 0, // Scrollbar dibuat sangat tipis
                    horizontal: 'visible',
                    horizontalScrollbarSize: 6
                },
                overviewRulerLanes: 0,
                overviewRulerBorder: false,
                hideCursorInOverviewRuler: true
            });


            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => { saveCurrentFile(); });
            if (activeTab && tabs[activeTab] && tabs[activeTab].type === 'code') switchTab(activeTab);
        });

        function getFileInfo(fileName) {
            const ext = fileName.split('.').pop().toLowerCase();
            if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp', 'tiff'].includes(ext)) return { type: 'image', icon: '<i class="ti ti-photo"></i>', color: 'text-info', label: 'File Gambar (Image)' };
            if (['mp4', 'webm', 'ogg', 'mkv', 'avi', 'mov', 'flv'].includes(ext)) return { type: 'video', icon: '<i class="ti ti-video"></i>', color: 'text-danger', label: 'File Video / Multimedia' };
            if (['mp3', 'wav', 'flac', 'aac', 'm4a', 'wma'].includes(ext)) return { type: 'audio', icon: '<i class="ti ti-music"></i>', color: 'text-warning', label: 'File Audio / Musik' };
            if (['pdf'].includes(ext)) return { type: 'pdf', icon: '<i class="ti ti-file-type-pdf"></i>', color: 'text-danger', label: 'Dokumen PDF' };
            if (['ppt', 'pptx', 'odp', 'key'].includes(ext)) return { type: 'ppt', icon: '<i class="ti ti-file-presentation"></i>', color: 'text-warning', label: 'Dokumen Presentasi PowerPoint' };
            if (['doc', 'docx', 'rtf', 'odt', 'pages', 'epub'].includes(ext)) return { type: 'word', icon: '<i class="ti ti-file-word"></i>', color: 'text-info', label: 'Dokumen Microsoft Word' };
            if (['xls', 'xlsx', 'ods', 'numbers'].includes(ext)) return { type: 'excel', icon: '<i class="ti ti-file-spreadsheet"></i>', color: 'text-success', label: 'Dokumen Spreadsheet Excel' };
            if (['zip', 'rar', 'tar', 'gz', '7z', 'bz2', 'xz', 'iso', 'tgz', 'cab', 'lz', 'zst'].includes(ext)) return { type: 'archive', icon: '<i class="ti ti-file-zip"></i>', color: 'text-warning', label: 'File Arsip / Terkompresi' };
            if (['exe', 'msi', 'com', 'dll', 'sys', 'ini_bin', 'ocx', 'drv', 'lib', 'a', 'o', 'obj', 'pdb', 'bin', 'dat', 'rom', 'firmware', 'hex', 'apk', 'xapk', 'aab', 'ipa', 'dmg', 'pkg', 'app', 'deb', 'rpm', 'so', 'appimage', 'flatpak', 'snap', 'db', 'sqlite', 'sqlite3', 'mdb', 'accdb', 'sqlitedb', 'frm', 'ibd', 'myd', 'myi', 'ttf', 'otf', 'woff', 'woff2', 'eot'].includes(ext)) return { type: 'binary', icon: '<i class="ti ti-cpu"></i>', color: 'text-[var(--text-muted)]', label: 'File Binary / System / App' };
            if (['bak'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-history"></i>', color: 'text-warning', label: 'File Backup Code/Text' };
            if (['csv', 'tsv'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-table"></i>', color: 'text-success', label: 'CSV / Tabular Data Text' };
            if (['php', 'phtml'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-php"></i>', color: 'text-info', label: 'PHP Script' };
            if (['js', 'jsx', 'mjs', 'ts', 'tsx'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-javascript"></i>', color: 'text-warning', label: 'JavaScript / TypeScript' };
            if (['html', 'htm', 'xhtml'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-html5"></i>', color: 'text-warning', label: 'HTML Document' };
            if (['css', 'scss', 'less', 'sass'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-css3"></i>', color: 'text-info', label: 'Stylesheet CSS' };
            if (['json', 'json5'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-braces"></i>', color: 'text-success', label: 'JSON Data' };
            if (['py', 'pyw', 'ipynb'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-python"></i>', color: 'text-info', label: 'Python Script' };
            if (['java', 'class', 'jar'].includes(ext)) {
                if (ext === 'jar' || ext === 'class') return { type: 'binary', icon: '<i class="ti ti-cup"></i>', color: 'text-danger', label: 'Java Compiled Binary/Archive' };
                return { type: 'code', icon: '<i class="ti ti-cup"></i>', color: 'text-danger', label: 'Java Source Code' };
            }
            if (['c', 'cpp', 'h', 'hpp', 'cs'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-cpp"></i>', color: 'text-info', label: 'C / C++ / C# Source Code' };
            if (['sql'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-database-export"></i>', color: 'text-info', label: 'SQL Query Script' };
            if (['md', 'markdown'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-markdown"></i>', color: 'text-info', label: 'Markdown Text' };
            return { type: 'code', icon: '<i class="ti ti-file-code"></i>', color: 'text-[var(--text-muted)]', label: 'Text / Code File' };
        }

        async function deleteItem(path) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat menghapus file!');
            const confirmed = await showConfirm('Hapus File Permanen?', `Yakin ingin menghapus:<br><span class="font-mono text-warning font-bold mt-1 inline-block select-all px-2 py-0.5 rounded border border-theme bg-[var(--bg-hover)]">${path}</span><br><span class="text-danger block mt-2">Tindakan ini tidak dapat dibatalkan!</span>`, true, 'Ya, Hapus Permanen');
            if (!confirmed) return;
            fetch(getApiUrl('delete'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ path: path })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') { if (tabs[path]) closeTab(path, null, true); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); } 
                else alert(res.error || 'Gagal menghapus');
            });
        }

        function loadFolder(path, containerEl, depth = 0) {
            const padLeft = 12 + (depth * 16); const lineX = padLeft + 7; 
            containerEl.innerHTML = `<li class="py-1 text-xs italic opacity-50 relative z-10" style="padding-left: ${padLeft + 16}px"><i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memuat...</li>`;

            fetch(getApiUrl('list', 'path=' + encodeURIComponent(path))).then(r => r.json()).then(data => {
                if (data.error) { 
                    if (path === currentExplorerRoot && path !== '') { drillDownFolder(''); return; }
                    containerEl.innerHTML = `<li class="py-1 text-xs text-danger" style="padding-left: ${padLeft}px">${data.error}</li>`; return; 
                }
                containerEl.innerHTML = '';
                if (data.items.length === 0) { containerEl.innerHTML = `<li class="py-1 text-xs italic opacity-50" style="padding-left: ${padLeft + 16}px">Folder kosong</li>`; return; }

                data.items.forEach(item => {
                    const li = document.createElement('li'); li.className = 'tree-item select-none relative z-10';
                    const isChecked = selectedItems.has(item.path) ? 'checked' : '';

                    if (item.type === 'folder') {
                        li.innerHTML = `
                            <div class="flex items-center py-[3px] hover-bg cursor-pointer transition group" style="padding-left: ${padLeft}px"
                                 onclick="toggleFolder('${item.path}', this, event, ${depth + 1})"
                                 oncontextmenu="showContextMenu(event, '${item.path}', 'folder', this)">
                                <input type="checkbox" data-path="${item.path}" class="tree-checkbox mr-1.5 rounded border-theme cursor-pointer flex-shrink-0" ${isChecked} onclick="toggleSelect('${item.path}', event)" title="Centang item ini" />
                                <i class="ti ti-chevron-right text-[14px] text-muted w-[16px] text-center transition-transform duration-200 tree-chevron flex-shrink-0"></i>
                                <span class="text-[16px] text-warning flex mr-1.5 flex-shrink-0"><i class="ti ti-folder folder-icon"></i></span>
                                <span class="truncate">${item.name}</span>
                            </div>
                            <ul class="hidden folder-content" style="--line-x: ${lineX}px;"></ul>
                        `;
                    } else {
                        const info = getFileInfo(item.name);
                        li.innerHTML = `
                            <div class="flex items-center py-[3px] hover-bg cursor-pointer transition border-l border-transparent hover:border-[var(--accent)] group" style="padding-left: ${padLeft}px"
                                 onclick="openFile('${item.path}', event)"
                                 oncontextmenu="showContextMenu(event, '${item.path}', 'file', this)">
                                <input type="checkbox" data-path="${item.path}" class="tree-checkbox mr-1.5 rounded border-theme cursor-pointer flex-shrink-0" ${isChecked} onclick="toggleSelect('${item.path}', event)" title="Centang item ini" />
                                <span class="w-[16px] flex-shrink-0"></span> <span class="text-[16px] flex mr-1.5 flex-shrink-0 ${info.color}">${info.icon}</span>
                                <span class="truncate">${item.name}</span>
                            </div>
                        `;
                    }
                    containerEl.appendChild(li);
                });
            }).catch(() => containerEl.innerHTML = `<li class="py-1 text-xs text-danger" style="padding-left: ${padLeft}px">Gagal koneksi</li>`);
        }

        function toggleFolder(path, el, event, nextDepth) {
            event.stopPropagation(); const subUl = el.parentElement.querySelector('.folder-content'); const chevron = el.querySelector('.tree-chevron'); const folderIcon = el.querySelector('.folder-icon');
            if (subUl.classList.contains('hidden')) {
                subUl.classList.remove('hidden'); chevron.classList.add('rotate-90');
                if (folderIcon) folderIcon.className = 'ti ti-folder-open folder-icon';
                if (subUl.children.length === 0 || subUl.innerText.includes('Memuat...')) loadFolder(path, subUl, nextDepth);
            } else {
                subUl.classList.add('hidden'); chevron.classList.remove('rotate-90');
                if (folderIcon) folderIcon.className = 'ti ti-folder folder-icon';
            }
        }

        function showEmptyState() {
            activeTab = null;
            document.getElementById('editor-wrapper').classList.add('hidden'); document.getElementById('preview-wrapper').classList.add('hidden'); document.getElementById('empty-state').classList.remove('hidden'); document.getElementById('save-action-bar').classList.add('hidden'); document.getElementById('editor-tools').classList.add('hidden'); document.getElementById('editor-top-actions').classList.add('hidden'); 
            document.getElementById('status').innerHTML = '<i class="ti ti-info-circle text-sm"></i> Siap';
            renderTabs();
        }

        function openFile(filePath, event, isBackground = false) {
            if (event) event.stopPropagation();
            if (window.innerWidth <= 768) { document.getElementById('sidebar').classList.add('-translate-x-full'); document.getElementById('mobile-overlay').classList.add('hidden'); }

            if (window.IDEHooks.do('before_openFile', filePath) === false) return;

            const fileName = filePath.split('/').pop(); const info = getFileInfo(fileName);

            if (info.type !== 'code') {
                tabs[filePath] = { type: 'preview', info: info, saved: true };
                if (!isBackground) switchTab(filePath); else renderTabs();
                return;
            }

            if (tabs[filePath]) { if (!isBackground) switchTab(filePath); return; }

            if (!isBackground) document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memuat: ${filePath}...`;

            fetch(getApiUrl('read', 'path=' + encodeURIComponent(filePath))).then(r => r.json()).then(data => {
                if (data.error) { if (!isBackground) { alert(data.error); document.getElementById('status').innerHTML = '<i class="ti ti-alert-circle text-danger"></i> Gagal memuat file'; } } else {
                    let ext = fileName.split('.').pop().toLowerCase();
                    if (ext === 'bak') { const parts = fileName.split('.'); if (parts.length >= 3) { const origPart = parts[parts.length - 2]; ext = origPart.split('_')[0].toLowerCase(); } }
                    const langMap = { 
                        'js': 'javascript', 'jsx': 'javascript', 'ts': 'typescript', 'tsx': 'typescript',
                        'py': 'python', 'html': 'html', 'htm': 'html', 'css': 'css', 'scss': 'scss', 'less': 'less',
                        'json': 'json', 'sql': 'sql', 'php': 'php', 'txt': 'plaintext', 'md': 'markdown',
                        'java': 'java', 'c': 'c', 'cpp': 'cpp', 'h': 'cpp', 'hpp': 'cpp', 'cs': 'csharp',
                        'sh': 'shell', 'yaml': 'yaml', 'yml': 'yaml', 'xml': 'xml', 'rb': 'ruby', 'go': 'go', 'rs': 'rust'
                    };
                    const lang = langMap[ext] || 'plaintext'; let model = null;
                    if (typeof monaco !== 'undefined' && monaco.editor) {
                        model = monaco.editor.createModel(data.content, lang);
                        model.onDidChangeContent(() => { if (tabs[filePath] && tabs[filePath].saved) { tabs[filePath].saved = false; renderTabs(); } });
                    }
                    tabs[filePath] = { type: 'code', model: model, content: data.content, lang: lang, saved: true, info: info };
                    if (!isBackground) switchTab(filePath); else renderTabs(); saveSession(); 
                }
            }).catch(() => { if (!isBackground) alert('Terjadi kesalahan koneksi saat membaca file.'); });
        }

        function switchTab(filePath) {
            if (!tabs[filePath]) return;

            activeTab = filePath; const tabData = tabs[filePath];
            const editorWrap = document.getElementById('editor-wrapper'); 
            const previewWrap = document.getElementById('preview-wrapper');
            const previewContent = document.getElementById('preview-content');
            const emptyState = document.getElementById('empty-state'); 
            const saveBar = document.getElementById('save-action-bar'); 
            const editorTools = document.getElementById('editor-tools');
            const topActions = document.getElementById('editor-top-actions');
            
            emptyState.classList.add('hidden');

            if (tabData.type === 'settings') {
                editorWrap.classList.add('hidden'); saveBar.classList.add('hidden'); 
                editorTools.classList.add('hidden'); topActions.classList.add('hidden');
                previewWrap.classList.remove('hidden');
                
                previewContent.className = "absolute inset-0 w-full h-full overflow-y-auto p-4 md:p-8 bg-[var(--bg-main)]";
                
                let userMgmtSection = ''; 
                let pluginMgmtSection = ''; 
                let identitasAppSection = '';
                
                // Jika user adalah Admin, barulah kita buat elemen HTML untuk form pengaturannya
                if (USER_ROLE === 'admin') {
                    identitasAppSection = `
                        <div class="bg-[var(--bg-tab)] p-5 md:p-6 rounded-xl border border-theme shadow-lg">
                            <h3 class="text-base md:text-lg font-bold mb-4 border-b border-theme pb-3 flex items-center gap-2"><i class="ti ti-color-swatch text-danger"></i> Identitas Aplikasi</h3>
                            <div class="grid gap-4">
                                <div>
                                    <label class="block text-xs font-bold mb-2 text-muted">Nama Aplikasi</label>
                                    <input type="text" id="set-app-name" value="${APP_NAME}" class="w-full border border-theme rounded p-2.5 text-sm transition-colors">
                                </div>
                                <div>
                                    <label class="block text-xs font-bold mb-2 text-muted">Logo URL atau Upload Base64</label>
                                    <div class="flex gap-2">
                                        <input type="text" id="set-app-logo" value="${APP_LOGO}" placeholder="URL Logo..." class="w-full border border-theme rounded p-2.5 text-sm transition-colors">
                                        <label class="border border-theme hover-bg px-3 md:px-4 py-2.5 rounded cursor-pointer transition font-bold flex items-center gap-2 whitespace-nowrap text-xs md:text-sm bg-[var(--bg-sidebar)]">
                                            <i class="ti ti-upload text-accent text-lg"></i> <span class="hidden md:inline">Pilih Gambar</span>
                                            <input type="file" class="hidden" accept="image/*" onchange="handleLogoUpload(this)">
                                        </label>
                                    </div>
                                    <div class="mt-3 flex items-center gap-4 p-3 rounded border border-theme bg-[var(--bg-hover)]" id="logo-preview-box">
                                        ${APP_LOGO ? `<img src="${APP_LOGO}" class="h-12 object-contain rounded p-1 shadow">` : '<span class="text-xs text-muted italic">Belum ada logo khusus...</span>'}
                                    </div>
                                </div>
                                <button onclick="saveAppConfig()" id="btn-save-identitas" class="bg-[var(--color-success)] hover:opacity-80 text-white py-2.5 px-4 rounded font-bold mt-2 shadow-lg transition active:scale-95 w-full md:w-fit flex items-center justify-center gap-2"><i class="ti ti-device-floppy"></i> Simpan Identitas</button>
                            </div>
                        </div>
                    `;

                    userMgmtSection = `
                        <div class="bg-[var(--bg-tab)] p-5 md:p-6 rounded-xl border border-theme shadow-lg mt-6" id="settings-user-mgmt">
                            <h3 class="text-base md:text-lg font-bold mb-4 border-b border-theme pb-3 flex items-center gap-2"><i class="ti ti-users-group text-info"></i> Manajemen User & Guest</h3>
                            <div id="settings-user-content" class="py-4 text-center text-muted text-sm"><i class="ti ti-loader-2 animate-spin text-xl inline-block"></i> Memuat manajemen user...</div>
                        </div>
                    `;
                    
                    pluginMgmtSection = `
                        <div class="bg-[var(--bg-tab)] p-5 md:p-6 rounded-xl border border-theme shadow-lg mt-6 relative overflow-visible" id="settings-plugin-mgmt">
                            <h3 class="text-base md:text-lg font-bold mb-4 border-b border-theme pb-3 flex items-center gap-2"><i class="ti ti-plug text-success"></i> Manajemen Plugin (Ekstensi)</h3>
                            <div id="settings-plugin-content" class="py-4 text-center text-muted text-sm relative overflow-visible"><i class="ti ti-loader-2 animate-spin text-xl inline-block"></i> Memuat daftar plugin...</div>
                        </div>
                    `;
                }

                // Render UI. Grid akan otomatis menyesuaikan jika 'identitasAppSection' kosong
                previewContent.innerHTML = `
                    <div class="max-w-4xl mx-auto pb-20 animate-scale-up">
                        <h2 class="text-xl md:text-2xl font-bold flex items-center gap-3 mb-6 border-b border-theme pb-4">
                            <i class="ti ti-settings text-accent"></i> Pengaturan Sistem
                        </h2>
                        
                        <div class="grid grid-cols-1 ${USER_ROLE === 'admin' ? 'md:grid-cols-2' : 'max-w-md'} gap-6">
                            ${identitasAppSection}
                            
                            <div class="bg-[var(--bg-tab)] p-5 md:p-6 rounded-xl border border-theme shadow-lg">
                                <h3 class="text-base md:text-lg font-bold mb-4 border-b border-theme pb-3 flex items-center gap-2"><i class="ti ti-key text-warning"></i> Ganti Password Akun</h3>
                                <div class="grid gap-4">
                                    <div>
                                        <label class="block text-xs font-bold mb-2 text-muted">Password Lama</label>
                                        <div class="relative"><i class="ti ti-lock absolute left-3 top-3 text-muted"></i><input type="password" id="pw-old" class="w-full border border-theme rounded pl-9 pr-3 py-2.5 text-sm transition-colors"></div>
                                    </div>
                                    <div>
                                        <label class="block text-xs font-bold mb-2 text-muted">Password Baru</label>
                                        <div class="relative"><i class="ti ti-shield-check absolute left-3 top-3 text-muted"></i><input type="password" id="pw-new" class="w-full border border-theme rounded pl-9 pr-3 py-2.5 text-sm transition-colors"></div>
                                    </div>
                                    <button onclick="executeChangePassword()" class="bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] py-2.5 px-4 rounded font-bold mt-2 shadow-lg transition active:scale-95 w-full md:w-fit flex items-center justify-center gap-2"><i class="ti ti-check"></i> Ubah Password</button>
                                </div>
                            </div>
                        </div>
                        
                        ${pluginMgmtSection}
                        ${userMgmtSection}
                    </div>
                `;
                
                if(USER_ROLE === 'admin') { loadUserManagementUI(); loadPluginManagementUI(); }
                document.getElementById('status').innerHTML = `<i class="ti ti-settings"></i> Membuka Konfigurasi Sistem`;
                
            } else if (tabData.type === 'preview') {
                editorWrap.classList.add('hidden'); saveBar.classList.add('hidden'); 
                editorTools.classList.add('hidden'); topActions.classList.add('hidden');
                previewWrap.classList.remove('hidden');

                const url = getApiUrl('raw', 'path=' + encodeURIComponent(filePath));
                previewContent.className = "absolute inset-0 w-full h-full flex items-center justify-center p-4 overflow-auto";

                if (tabData.info.type === 'image') {
                    previewContent.innerHTML = `<img src="${url}" class="max-w-full max-h-full object-contain rounded shadow-2xl bg-[var(--bg-sidebar)] border border-theme animate-scale-up">`;
                } else if (tabData.info.type === 'video') {
                    previewContent.innerHTML = `<video src="${url}" controls class="max-w-full max-h-full rounded shadow-2xl border border-theme animate-scale-up"></video>`;
                } else if (tabData.info.type === 'audio') {
                    previewContent.innerHTML = `<div class="p-10 rounded-2xl shadow-2xl border border-theme text-center animate-scale-up bg-[var(--bg-sidebar)]"><i class="ti ti-music text-[5rem] text-accent mb-6 block animate-bounce"></i><audio src="${url}" controls class="w-[300px]"></audio><div class="mt-4 text-xs font-mono font-bold text-muted break-all">${filePath.split('/').pop()}</div></div>`;
                } else if (tabData.info.type === 'pdf') {
                    previewContent.innerHTML = `<iframe src="${url}" class="w-full h-full bg-white rounded-lg border border-theme shadow-2xl"></iframe>`;
                } else {
                    const fileName = filePath.split('/').pop();
                    const dlUrl = getApiUrl('download', 'path=' + encodeURIComponent(filePath));
                    previewContent.innerHTML = `
                        <div class="p-8 md:p-12 rounded-2xl shadow-2xl border border-theme text-center animate-scale-up bg-[var(--bg-sidebar)] max-w-md w-full mx-4">
                            <div class="w-24 h-24 rounded-full bg-[var(--bg-hover)] flex items-center justify-center mx-auto mb-6 border border-theme shadow-inner">
                                <span class="text-5xl ${tabData.info.color}">${tabData.info.icon}</span>
                            </div>
                            <h3 class="text-lg font-bold text-[var(--text-main)] truncate mb-1" title="${fileName}">${fileName}</h3>
                            <p class="text-xs text-muted font-mono mb-6">${tabData.info.label || 'Archive / Binary File'}</p>
                            <div class="bg-[var(--bg-hover)] p-3.5 rounded-lg border border-theme mb-6 text-xs text-muted leading-relaxed text-left flex items-start gap-2.5">
                                <i class="ti ti-info-circle text-accent text-lg flex-shrink-0 mt-0.5"></i> 
                                <span>File ini tidak dapat ditampilkan secara preview di dalam browser. Klik tombol di bawah jika Anda ingin mengunduh atau menyimpannya.</span>
                            </div>
                            <a href="${dlUrl}" target="_blank" class="w-full py-3 bg-[var(--accent)] hover:opacity-90 text-[var(--btn-text)] font-bold rounded-xl shadow-lg flex items-center justify-center gap-2 transition active:scale-95 inline-flex">
                                <i class="ti ti-download text-lg"></i> Download File Sekarang
                            </a>
                        </div>
                    `;
                }
                document.getElementById('status').innerHTML = `<i class="ti ti-eye"></i> Viewing Media: ${filePath.split('/').pop()}`;
            } else {
                previewWrap.classList.add('hidden');
                editorWrap.classList.remove('hidden'); saveBar.classList.remove('hidden'); editorTools.classList.remove('hidden'); topActions.classList.remove('hidden');
                if (editor) {
                    if (!tabData.model) {
                        tabData.model = monaco.editor.createModel(tabData.content, tabData.lang);
                        tabData.model.onDidChangeContent(() => { if (tabs[filePath] && tabs[filePath].saved) { tabs[filePath].saved = false; renderTabs(); } });
                    }
                    editor.setModel(tabData.model); editor.layout(); editor.focus();
                }
                document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Editing: ${filePath}`;
            }

            window.IDEHooks.do('after_switchTab', activeTab, tabData);
            renderTabs(); saveSession(); 
        }

        async function closeTab(filePath, event, force = false) {
            if (event) event.stopPropagation();
            if (!force && tabs[filePath] && !tabs[filePath].saved && tabs[filePath].type === 'code') {
                const confirmed = await showConfirm('Perubahan Belum Disimpan', `File <span class="font-mono text-warning font-bold">${filePath.split('/').pop()}</span> memiliki perubahan yang belum disimpan.<br>Yakin ingin menutupnya?`, false, 'Tutup Tanpa Simpan');
                if (!confirmed) return;
            }
            if (tabs[filePath] && tabs[filePath].type === 'code' && tabs[filePath].model) tabs[filePath].model.dispose();
            delete tabs[filePath]; saveSession(); 
            if (activeTab === filePath) {
                const remaining = Object.keys(tabs);
                if (remaining.length > 0) switchTab(remaining[remaining.length - 1]);
                else showEmptyState();
            } else { renderTabs(); }
        }

        function renderTabs() {
            const tabBar = document.getElementById('tab-bar'); tabBar.innerHTML = ''; let hasUnsaved = false;
            for (const [filePath, data] of Object.entries(tabs)) {
                const isActive = filePath === activeTab;
                const bgClass = isActive ? 'bg-[var(--bg-main)] text-[var(--text-main)] border-b-2 border-[var(--accent)]' : 'bg-transparent text-[var(--text-main)] opacity-70 hover:opacity-100 hover-bg border-b-2 border-transparent';
                const unsavedDot = data.saved ? '' : '<span class="unsaved-dot" title="Belum disimpan (Ctrl+S)"></span>';
                if (!data.saved) hasUnsaved = true;
                
                const isSettings = filePath === '__SETTINGS__';
                const fileName = isSettings ? data.title : filePath.split('/').pop();
                const info = isSettings ? { icon: '<i class="ti ti-settings"></i>', color: 'text-muted' } : (data.info || getFileInfo(fileName));
                
                const tabEl = document.createElement('div');
                tabEl.className = `flex items-center justify-between gap-2 px-3 py-1.5 text-xs cursor-pointer border-r border-theme min-w-[120px] max-w-[200px] group transition-colors flex-shrink-0 ${bgClass}`;
                tabEl.title = isSettings ? 'Pengaturan' : filePath; tabEl.onclick = () => switchTab(filePath);
                tabEl.innerHTML = `<div class="flex items-center gap-1.5 truncate"><span class="text-base flex ${info.color}">${info.icon}</span><span class="truncate font-medium">${fileName}</span>${unsavedDot}</div><span onclick="closeTab('${filePath}', event)" class="hover-bg hover:text-danger rounded p-0.5 ml-1 transition flex items-center justify-center"><i class="ti ti-x text-[14px]"></i></span>`;
                tabBar.appendChild(tabEl);
            }
            const btnTopSave = document.getElementById('btn-top-save'); const topSaveText = document.getElementById('top-save-text');
            if (btnTopSave && topSaveText) {
                if (hasUnsaved && activeTab && tabs[activeTab] && !tabs[activeTab].saved) {
                    btnTopSave.className = 'bg-[var(--color-warning)] hover:opacity-80 text-black font-bold px-3 py-1 rounded text-xs flex items-center gap-1.5 shadow-lg transition active:scale-95 animate-pulse';
                    topSaveText.innerText = 'Simpan ●';
                } else {
                    btnTopSave.className = 'bg-[var(--accent)] hover:opacity-85 text-[var(--btn-text)] px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition active:scale-95';
                    topSaveText.innerText = 'Simpan';
                }
            }
        }

        function saveCurrentFile() {
            if (USER_MODE === 'read-only') return alert('Mode Demo tidak dapat menyimpan perubahan!');
            if (!activeTab || !tabs[activeTab] || tabs[activeTab].type !== 'code') return;
            const filePath = activeTab; const content = tabs[filePath].model ? tabs[filePath].model.getValue() : tabs[filePath].content;
            document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Menyimpan ${filePath}...`;

            const btnSave = document.getElementById('btn-top-save'); const topSaveText = document.getElementById('top-save-text');
            if(btnSave && topSaveText) { btnSave.disabled = true; btnSave.className = 'bg-gray-500 opacity-50 cursor-not-allowed text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition'; topSaveText.innerText = 'Menyimpan...'; }

            fetch(getApiUrl('save'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ path: filePath, content: content }) 
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    tabs[filePath].saved = true; renderTabs();
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-success"></i> Berhasil disimpan: ${filePath}`;
                    if(btnSave && topSaveText) { btnSave.className = 'bg-[var(--color-success)] text-white font-bold px-3 py-1 rounded text-xs flex items-center gap-1.5 shadow transition'; topSaveText.innerText = 'Tersimpan!'; }
                    setTimeout(() => { 
                        if (activeTab === filePath) document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Editing: ${filePath}`; 
                        if(btnSave) btnSave.disabled = false; renderTabs(); 
                    }, 1500);
                } else { alert(res.error || 'Gagal menyimpan file!'); if(btnSave) btnSave.disabled = false; renderTabs(); }
            }).catch(() => { alert('Terjadi kesalahan koneksi saat menyimpan.'); if(btnSave) btnSave.disabled = false; renderTabs(); });
        }

        window.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveCurrentFile(); } });
    </script>
    
    <?php foreach($active_plugin_js as $js_file): ?>
        <script src="<?php echo htmlspecialchars($js_file); ?>"></script>
    <?php endforeach; ?>

    <?php if (!empty($plugin_errors) && ($current_user['role'] ?? '') === 'admin'): ?>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const errors = <?php echo json_encode($plugin_errors); ?>;
            const errMsg = errors.join('\n\n');
            console.error('SYSTEM PLUGIN WARNING:', errMsg);
            setTimeout(() => {
                alert("⚠ PERINGATAN SISTEM PLUGIN ⚠\n\nSistem menemukan error pada plugin dan telah mematikannya secara otomatis untuk mencegah kerusakan IDE:\n\n" + errMsg);
            }, 1000);
        });
    </script>
    <?php endif; ?>
<?php endif; ?>
</body>
</html>
