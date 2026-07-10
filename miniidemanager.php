<?php
// --- SETUP SESSION & SECURITY ---
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$target_dir = realpath(__DIR__);
$current_script = basename(__FILE__);
$users_file = $target_dir . DIRECTORY_SEPARATOR . '.app_users.php';

// Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- FUNGSI DATABASE USER (FLAT-FILE SECURE) ---
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
                'is_active' => true // Status Embed Aktif/Tidak
            ]
        ];
        save_users_db($file, $default_users);
        return $default_users;
    }
    $content = file_get_contents($file);
    $json = preg_replace('/^<\?php exit\(".*?"\); \?>\s*/', '', $content);
    $db = json_decode($json, true) ?: [];
    
    // Injeksi akun guest jika database lama belum memilikinya
    if (!isset($db['__GUEST__'])) {
        $db['__GUEST__'] = ['role' => 'guest', 'mode' => 'read-only', 'allowed_paths' => ['/'], 'theme' => 'dark', 'is_active' => true];
        save_users_db($file, $db);
    }
    return $db;
}

function save_users_db($file, $data) {
    $header = '<?php exit("Access Denied"); ?>' . "\n";
    file_put_contents($file, $header . json_encode($data, JSON_PRETTY_PRINT));
}

$users_db = get_users_db($users_file);

// --- AUTH HANDLERS ---
if (isset($_GET['auth_action'])) {
    header('Content-Type: application/json');
    $action = $_GET['auth_action'];

    if ($action === 'login') {
        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';
        if (isset($users_db[$user]) && $user !== '__GUEST__' && password_verify($pass, $users_db[$user]['password'])) {
            $_SESSION['user'] = [
                'username' => $user,
                'role' => $users_db[$user]['role'] ?? 'user',
                'mode' => $users_db[$user]['mode'] ?? 'read-write',
                'allowed_paths' => $users_db[$user]['allowed_paths'] ?? ['/'],
                'theme' => $users_db[$user]['theme'] ?? 'dark'
            ];
            echo json_encode(['status' => 'ok', 'theme' => $_SESSION['user']['theme']]);
        } else {
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

// --- VALIDASI LOGIN UNTUK AKSES IDE ATAU MODE EMBED GUEST ---
$is_embed = isset($_GET['embed']) && $_GET['embed'] == '1';
$is_logged_in = isset($_SESSION['user']);
$is_guest = !$is_logged_in && $is_embed;

if ($is_guest) {
    $guest_conf = $users_db['__GUEST__'] ?? ['is_active' => false];
    if (empty($guest_conf['is_active'])) {
        die("<h3>Akses Ditolak</h3><p>Mode Embed (Guest Viewer) telah dinonaktifkan oleh Administrator.</p>");
    }
    $current_user = [
        'username' => 'Guest (Viewer)',
        'role' => 'guest',
        'mode' => 'read-only',
        'allowed_paths' => $guest_conf['allowed_paths'] ?? ['/'],
        'theme' => $guest_conf['theme'] ?? 'dark'
    ];
} else {
    $current_user = $_SESSION['user'] ?? null;
}

// --- BACKEND API HANDLING ---
if (($is_logged_in || $is_guest) && isset($_GET['ajax'])) {
    if (ob_get_length()) ob_clean(); 
    
    $headers = getallheaders();
    $client_csrf = $headers['X-CSRF-Token'] ?? $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    $action = $_GET['action'] ?? '';
    
    $csrf_protected = ['batch_zip', 'batch_action', 'save', 'backup', 'create', 'rename', 'delete', 'upload', 'remote_download', 'change_pw', 'add_user', 'delete_user', 'save_theme', 'update_guest'];
    if (in_array($action, $csrf_protected) && !hash_equals($_SESSION['csrf_token'], $client_csrf)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'CSRF Token tidak valid atau sesi telah habis!']);
        exit;
    }

    $write_actions = ['save', 'backup', 'create', 'rename', 'delete', 'upload', 'remote_download', 'batch_action', 'change_pw', 'add_user', 'delete_user', 'save_theme', 'update_guest'];
    if (in_array($action, $write_actions) && ($current_user['mode'] ?? 'read-write') === 'read-only') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Akses Ditolak! Anda berada dalam MODE READ-ONLY (Viewer).']);
        exit;
    }

    // AUTOCOMPLETE API
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
            $dir = '';
            $term = $query;
        }
        
        $searchDir = $target_dir . ($dir ? DIRECTORY_SEPARATOR . $dir : '');
        $realSearch = realpath($searchDir);
        $results = [];
        
        // Prevent directory traversal
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
        echo json_encode(['status' => 'ok', 'results' => $results]);
        exit;
    }

    if ($action === 'check_theme') {
        header('Content-Type: application/json');
        if ($is_guest) { echo json_encode(['status' => 'ok', 'theme' => $current_user['theme']]); exit; }
        $uname = $current_user['username'];
        $fresh_users = get_users_db($users_file);
        $current_theme = $fresh_users[$uname]['theme'] ?? 'dark';
        $_SESSION['user']['theme'] = $current_theme;
        echo json_encode(['status' => 'ok', 'theme' => $current_theme]);
        exit;
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

    $relPath = $_GET['path'] ?? $_GET['file'] ?? '';
    $relPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relPath), DIRECTORY_SEPARATOR);
    $fullPath = $target_dir . ($relPath ? DIRECTORY_SEPARATOR . $relPath : '');
    $realPath = realpath($fullPath) ?: $fullPath;

    // FUNGSI KEAMANAN PATH DIPERBARUI (MENDUKUNG FILE KHUSUS)
    function isSafePath($path, $base, $allowed_paths) {
        $real = realpath($path);
        if ($real === false && !file_exists($path)) {
            $real = realpath(dirname($path));
        }
        if ($real === false || stripos($real, $base) !== 0) return false;

        if (in_array('/', $allowed_paths) || in_array('*', $allowed_paths)) return true;

        $relativePath = '/' . ltrim(str_replace('\\', '/', substr($real, strlen($base))), '/');
        if ($relativePath === '/') return true; 

        foreach ($allowed_paths as $allowed) {
            $cleanAllowed = '/' . ltrim(str_replace('\\', '/', trim($allowed)), '/');
            
            // 1. Cocok persis (Berlaku untuk File/Folder)
            if ($relativePath === $cleanAllowed) return true;
            
            // 2. Target Path berada DI DALAM Allowed Folder
            if (stripos($relativePath, $cleanAllowed . '/') === 0) return true;
            
            // 3. Target Path adalah PARENT dari Allowed Path (Dibutuhkan agar bisa buka hirarki folder menuju file spesifik)
            if (stripos($cleanAllowed, $relativePath . '/') === 0) return true;
        }
        return false;
    }

    $user_allowed_paths = $current_user['allowed_paths'] ?? ['/'];

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

    if ($action === 'info') {
        header('Content-Type: application/json');
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
            if (!isSafePath($itemFull, $target_dir, $user_allowed_paths) || !file_exists($itemFull) || basename($itemFull) === $current_script || basename($itemFull) === basename($users_file)) continue;
            
            if (is_dir($itemFull)) {
                $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($itemFull, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
                foreach ($files as $name => $file) {
                    if (!$file->isDir()) {
                        $filePath = $file->getRealPath();
                        // Filter file yang ada di dalam ZIP memastikan semuanya memiliki akses isSafePath
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
            if (!isSafePath($srcFull, $target_dir, $user_allowed_paths) || !file_exists($srcFull) || $srcFull === $destFull || basename($srcFull) === $current_script || basename($srcFull) === basename($users_file)) continue;
            
            $itemName = basename($srcFull);
            $targetItemFull = $destFull . DIRECTORY_SEPARATOR . $itemName;
            
            if ($mode === 'move') { rename($srcFull, $targetItemFull); }
            else { customCopyRecursive($srcFull, $targetItemFull); }
        }
        echo json_encode(['status' => 'ok']); exit;
    }

    if ($action === 'list') {
        header('Content-Type: application/json');
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || !is_dir($fullPath)) {
            echo json_encode(['error' => 'Folder tidak valid atau akses ditolak']); exit;
        }

        $items = scandir($fullPath);
        $folders = []; $files = [];

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.htaccess') continue;
            if (realpath($fullPath) === $target_dir && ($item === $current_script || $item === basename($users_file))) continue;

            $itemFullPath = $fullPath . DIRECTORY_SEPARATOR . $item;
            
            // VALIDASI EKSTRA: Jangan tampilkan file/folder jika tidak memiliki safe path.
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

    if ($action === 'read') {
        header('Content-Type: application/json');
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || is_dir($fullPath) || basename($fullPath) === $current_script || basename($fullPath) === basename($users_file)) {
            echo json_encode(['error' => 'Akses tidak diizinkan atau file tidak ditemukan']); exit;
        }
        echo json_encode(['content' => file_get_contents($fullPath)]); exit;
    }

    if ($action === 'raw' || $action === 'download') {
        if (!isSafePath($fullPath, $target_dir, $user_allowed_paths) || is_dir($fullPath) || basename($fullPath) === $current_script || basename($fullPath) === basename($users_file)) {
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

    if ($action === 'save') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $saveRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $saveFullPath = $target_dir . DIRECTORY_SEPARATOR . $saveRelPath;

        if (isSafePath(dirname($saveFullPath), $target_dir, $user_allowed_paths) && basename($saveFullPath) !== $current_script && basename($saveFullPath) !== basename($users_file) && !is_dir($saveFullPath)) {
            file_put_contents($saveFullPath, $data['content']);
            echo json_encode(['status' => 'ok']);
        } else { echo json_encode(['error' => 'Gagal menyimpan. Path tidak valid atau akses ditolak!']); }
        exit;
    }

    if ($action === 'backup') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $backupRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $backupFullPath = $target_dir . DIRECTORY_SEPARATOR . $backupRelPath;

        if (isSafePath($backupFullPath, $target_dir, $user_allowed_paths) && file_exists($backupFullPath) && !is_dir($backupFullPath) && basename($backupFullPath) !== $current_script && basename($backupFullPath) !== basename($users_file)) {
            $backupName = $backupFullPath . '_' . date('Ymd_His') . '.bak';
            if (copy($backupFullPath, $backupName)) {
                echo json_encode(['status' => 'ok', 'backup_file' => basename($backupName)]);
            } else { echo json_encode(['error' => 'Gagal menduplikasi file backup!']); }
        } else { echo json_encode(['error' => 'File tidak valid atau tidak dapat di-backup!']); }
        exit;
    }

    if ($action === 'create') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $newRelPath = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $newFullPath = $target_dir . DIRECTORY_SEPARATOR . $newRelPath;

        if (isSafePath(dirname($newFullPath), $target_dir, $user_allowed_paths)) {
            if (file_exists($newFullPath)) echo json_encode(['error' => 'Nama sudah digunakan!']);
            else {
                if ($data['type'] === 'folder') mkdir($newFullPath, 0777, true);
                else file_put_contents($newFullPath, '');
                echo json_encode(['status' => 'ok']);
            }
        } else { echo json_encode(['error' => 'Lokasi tidak valid atau akses ditolak']); }
        exit;
    }

    if ($action === 'rename') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $oldPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['old_path'] ?? ''), DIRECTORY_SEPARATOR);
        $newPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['new_path'] ?? ''), DIRECTORY_SEPARATOR);

        if (isSafePath($oldPath, $target_dir, $user_allowed_paths) && isSafePath(dirname($newPath), $target_dir, $user_allowed_paths) && basename($oldPath) !== $current_script && basename($oldPath) !== basename($users_file)) {
            if (file_exists($newPath)) echo json_encode(['error' => 'Nama target sudah ada!']);
            else { rename($oldPath, $newPath); echo json_encode(['status' => 'ok']); }
        } else { echo json_encode(['error' => 'Aksi ditolak']); }
        exit;
    }

    if ($action === 'delete') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $delPath = $target_dir . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);

        if (isSafePath($delPath, $target_dir, $user_allowed_paths) && basename($delPath) !== $current_script && basename($delPath) !== basename($users_file)) {
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

    if ($action === 'upload') {
        header('Content-Type: application/json');
        $uploadDirRel = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $_POST['path'] ?? ''), DIRECTORY_SEPARATOR);
        $uploadDirFull = $target_dir . ($uploadDirRel ? DIRECTORY_SEPARATOR . $uploadDirRel : '');

        if (!isSafePath($uploadDirFull, $target_dir, $user_allowed_paths) || !is_dir($uploadDirFull)) { echo json_encode(['error' => 'Direktori upload tidak valid']); exit; }

        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $fileName = basename($_FILES['file']['name']);
            $targetFile = $uploadDirFull . DIRECTORY_SEPARATOR . $fileName;
            if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) echo json_encode(['status' => 'ok']);
            else echo json_encode(['error' => 'Gagal memindahkan file yang diunggah']);
        } else { echo json_encode(['error' => 'Tidak ada file atau terjadi kesalahan upload']); }
        exit;
    }

    if ($action === 'remote_download') {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents('php://input'), true);
        $url = $data['url'] ?? '';
        $targetFolderRel = ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $data['path'] ?? ''), DIRECTORY_SEPARATOR);
        $targetFolderFull = $target_dir . ($targetFolderRel ? DIRECTORY_SEPARATOR . $targetFolderRel : '');

        if (!filter_var($url, FILTER_VALIDATE_URL)) { echo json_encode(['error' => 'URL tidak valid']); exit; }
        if (!isSafePath($targetFolderFull, $target_dir, $user_allowed_paths) || !is_dir($targetFolderFull)) { echo json_encode(['error' => 'Direktori tujuan tidak valid']); exit; }

        $fileName = basename(parse_url($url, PHP_URL_PATH));
        if (!$fileName) $fileName = 'downloaded_file_' . time();
        $targetFile = $targetFolderFull . DIRECTORY_SEPARATOR . $fileName;

        $content = @file_get_contents($url);
        if ($content !== false) {
            file_put_contents($targetFile, $content);
            echo json_encode(['status' => 'ok', 'filename' => $fileName]);
        } else { echo json_encode(['error' => 'Gagal mengambil file dari URL tersebut']); }
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
    <title>Mini File Manager IDE</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs/loader.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/dist/tabler-icons.min.css" />
    <style>
        :root {
            --bg-main: #1e1e1e; --bg-sidebar: #252526; --bg-tab: #2d2d2d; 
            --text-main: #d4d4d4; --border-color: #333333; --accent: #007acc;
        }
        [data-theme="light"] {
            --bg-main: #ffffff; --bg-sidebar: #f3f3f3; --bg-tab: #ececec; 
            --text-main: #333333; --border-color: #cccccc; --accent: #0066b8;
        }
        [data-theme="ocean"] {
            --bg-main: #0f111a; --bg-sidebar: #090b10; --bg-tab: #1a1c23; 
            --text-main: #8f93a2; --border-color: #1e212b; --accent: #82aaff;
        }
        
        body { background-color: var(--bg-main); color: var(--text-main); transition: background-color 0.3s, color 0.3s; }
        aside, #context-menu { background-color: var(--bg-sidebar); border-color: var(--border-color); }
        #tab-bar, .modal-bg > div { background-color: var(--bg-tab); border-color: var(--border-color); }
        .border-theme { border-color: var(--border-color); }
        
        ::-webkit-scrollbar { height: 6px; width: 6px; }
        ::-webkit-scrollbar-thumb { background: #555; border-radius: 3px; }
        #preview-content.hidden, #editor-wrapper.hidden, #empty-state.hidden { display: none !important; }

        .resizer { width: 4px; cursor: col-resize; background-color: transparent; position: absolute; right: 0; top: 0; bottom: 0; z-index: 10; }
        .resizer:hover, .resizer.active { background-color: var(--accent); }

        .folder-content { position: relative; }
        .folder-content::before {
            content: ''; position: absolute; top: 0; bottom: 0; left: var(--line-x); border-left: 1px solid var(--border-color); opacity: 0.7; pointer-events: none; z-index: 0;
        }

        .unsaved-dot {
            width: 8px; height: 8px; border-radius: 50%; background-color: #ffffff; box-shadow: 0 0 8px #ffffff; display: inline-block; margin-left: 6px; animation: pulse-glow 1.5s infinite alternate;
        }
        @keyframes pulse-glow {
            0% { transform: scale(0.9); opacity: 0.8; box-shadow: 0 0 4px #ffffff; }
            100% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 10px #fbbf24, 0 0 4px #ffffff; }
        }

        @keyframes scale-up {
            0% { transform: scale(0.95); opacity: 0; }
            100% { transform: scale(1); opacity: 1; }
        }
        .animate-scale-up { animation: scale-up 0.15s ease-out forwards; }
        
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
        
        .tree-checkbox { display: none; }
        .multi-select-active .tree-checkbox { display: inline-block !important; }
        
        @media (max-width: 768px) {
            .resizer { display: none; }
            #sidebar { width: 85% !important; max-width: 320px; }
        }
    </style>
</head>
<body class="flex flex-col md:flex-row h-screen overflow-hidden font-sans select-none text-sm" data-theme="<?php echo $current_user['theme'] ?? 'dark'; ?>">

<?php if (!$is_logged_in && !$is_guest): ?>
    <div class="fixed inset-0 bg-[var(--bg-main)] flex items-center justify-center z-50 p-4">
        <div class="bg-[var(--bg-tab)] border border-theme rounded-2xl shadow-2xl p-8 max-w-sm w-full animate-scale-up text-center">
            <div class="w-16 h-16 rounded-full bg-[var(--accent)]/20 text-[var(--accent)] flex items-center justify-center mx-auto mb-4 text-3xl border border-[var(--accent)]/30 shadow-inner">
                <i class="ti ti-lock"></i>
            </div>
            <h1 class="text-xl font-bold tracking-widest mb-1">Mini File Manager IDE</h1>
            <p class="text-xs text-gray-400 mb-6">CREATE BY ARF</p>
            
            <form id="login-form" onsubmit="handleLogin(event)" class="space-y-4 text-left">
                <div>
                    <label class="block text-xs font-semibold mb-1 opacity-70">Username</label>
                    <div class="relative">
                        <i class="ti ti-user absolute left-3 top-2.5 text-gray-400"></i>
                        <input type="text" id="login-user" required class="w-full bg-black/20 border border-theme rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-[var(--accent)]" placeholder="Masukkan username...">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold mb-1 opacity-70">Password</label>
                    <div class="relative">
                        <i class="ti ti-key absolute left-3 top-2.5 text-gray-400"></i>
                        <input type="password" id="login-pass" required class="w-full bg-black/20 border border-theme rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-[var(--accent)]" placeholder="Masukkan password...">
                    </div>
                </div>
                <div id="login-error" class="hidden text-xs text-red-400 bg-red-500/10 p-2.5 rounded-lg border border-red-500/20 text-center font-medium"></div>
                <button type="submit" id="login-btn" class="w-full py-2.5 bg-[var(--accent)] hover:opacity-90 text-white font-bold rounded-lg shadow-lg transition active:scale-95 flex items-center justify-center gap-2">
                    <i class="ti ti-login"></i> Masuk IDE
                </button>
            </form>
            <div class="mt-6 pt-4 border-t border-theme text-[10px] text-gray-500 flex flex-col gap-2">
                <div>Default: <b>admin / admin123</b></div>
                <a href="?embed=1" class="text-[var(--accent)] hover:underline inline-flex items-center justify-center gap-1 mt-1"><i class="ti ti-eye"></i> Masuk Mode Guest Viewer</a>
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
                    btn.disabled = false; btn.innerHTML = '<i class="ti ti-login"></i> Masuk IDE';
                }
            }).catch(() => {
                err.innerText = 'Terjadi kesalahan jaringan!';
                err.classList.remove('hidden');
                btn.disabled = false; btn.innerHTML = '<i class="ti ti-login"></i> Masuk IDE';
            });
        }
    </script>
<?php else: ?>
    <div class="md:hidden flex items-center justify-between p-3 border-b border-theme bg-[var(--bg-sidebar)] z-20 flex-shrink-0 shadow-md w-full">
        <div class="font-bold tracking-widest text-[var(--accent)] flex items-center gap-2 text-sm">
            <i class="ti ti-code"></i> MINI MANAGER
        </div>
        <button onclick="toggleSidebar()" class="text-[var(--text-main)] focus:outline-none p-1 rounded hover:bg-black/10">
            <i class="ti ti-menu-2 text-2xl"></i>
        </button>
    </div>

    <div id="mobile-overlay" class="hidden fixed inset-0 bg-black/60 z-30 md:hidden transition-opacity" onclick="toggleSidebar()"></div>

    <aside id="sidebar" class="fixed md:relative inset-y-0 left-0 z-40 transform -translate-x-full md:translate-x-0 transition-transform duration-300 w-64 flex flex-col border-r border-theme flex-shrink-0 h-full shadow-2xl md:shadow-none bg-[var(--bg-sidebar)]" oncontextmenu="showContextMenu(event, currentExplorerRoot, 'root', this)">
        <div class="resizer" id="drag-handle"></div>
        
        <?php if (($current_user['mode'] ?? '') === 'read-only'): ?>
        <div class="bg-amber-500/20 text-amber-300 border-b border-amber-500/30 px-3 py-1.5 text-[11px] font-bold text-center flex items-center justify-center gap-1.5">
            <i class="ti ti-shield-lock"></i> <?php echo $is_guest ? 'GUEST VIEWER (READ-ONLY)' : 'MODE DEMO (READ-ONLY)'; ?>
        </div>
        <?php endif; ?>

        <div id="explorer-header" class="p-3 text-[11px] font-bold uppercase tracking-widest text-[#888] border-b border-theme flex justify-between items-center bg-black/10">
            <span>Explorer</span>
            <div class="flex gap-2 text-base">
                <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-[var(--accent)]" title="Pilih Banyak (Multi-Select Mode)"><i class="ti ti-checkbox"></i></span>
                <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
                <span onclick="openModal('create', currentExplorerRoot, 'file')" class="cursor-pointer hover:text-[var(--accent)]" title="Buat File Baru"><i class="ti ti-file-plus"></i></span>
                <span onclick="openModal('create', currentExplorerRoot, 'folder')" class="cursor-pointer hover:text-[var(--accent)]" title="Buat Folder Baru"><i class="ti ti-folder-plus"></i></span>
                <?php endif; ?>
                <span onclick="loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-[var(--accent)] font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
            </div>
        </div>
        
        <div class="px-2 py-2 border-b border-theme">
            <div class="relative">
                <i class="ti ti-search absolute left-2 top-1.5 text-gray-500"></i>
                <input type="text" id="search-input" placeholder="Cari di explorer..." class="w-full bg-[var(--bg-main)] text-[var(--text-main)] border border-theme rounded px-2 pl-7 py-1 text-xs focus:outline-none focus:border-[var(--accent)]">
            </div>
        </div>

        <ul id="file-tree" class="flex-1 overflow-y-auto py-2">
            <li class="px-4 text-xs italic"><i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memuat folder...</li>
        </ul>

        <div id="batch-action-bar" class="hidden border-t border-theme p-2.5 bg-[var(--bg-tab)] shadow-2xl flex flex-col gap-2 text-xs z-20">
            <div class="flex justify-between items-center font-bold text-yellow-500">
                <span><i class="ti ti-checkbox text-sm"></i> <span id="selected-count">0</span> item terpilih</span>
                <span onclick="disableMultiSelectMode()" class="cursor-pointer text-red-400 hover:underline">Batal</span>
            </div>
            <div class="grid <?php echo ($current_user['mode'] ?? '') === 'read-only' ? 'grid-cols-1' : 'grid-cols-2'; ?> gap-1.5 font-medium">
                <button onclick="batchZipDownload()" class="bg-orange-600 hover:bg-orange-700 text-white py-1 rounded flex items-center justify-center gap-1 shadow transition"><i class="ti ti-file-zip"></i> ZIP Download</button>
                <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
                <button onclick="openModal('batch_copy_move')" class="bg-[var(--accent)] hover:opacity-90 text-white py-1 rounded flex items-center justify-center gap-1 shadow transition"><i class="ti ti-copy"></i> Copy/Move</button>
                <?php endif; ?>
            </div>
        </div>

        <div class="p-2 border-t border-theme flex flex-col gap-2 text-xs text-gray-400 flex-shrink-0 bg-black/10">
            <div class="flex items-center justify-between font-bold text-[var(--text-main)]">
                <span class="flex items-center gap-1.5 truncate">
                    <?php if ($is_guest): ?>
                        <i class="ti ti-user-circle text-gray-400"></i> Guest Mode
                    <?php else: ?>
                        <i class="ti ti-user-check text-green-400"></i> <?php echo htmlspecialchars($current_user['username']); ?>
                    <?php endif; ?>
                </span>
                <span class="bg-[var(--accent)]/20 text-[var(--accent)] px-1.5 py-0.5 rounded text-[10px] uppercase font-mono border border-[var(--accent)]/30"><?php echo $current_user['role']; ?></span>
            </div>
            <div class="flex items-center justify-between">
                <span>Tema UI:</span>
                <select id="theme-selector" class="bg-[var(--bg-main)] text-[var(--text-main)] border border-theme rounded p-1 focus:outline-none w-28 text-[11px]" onchange="changeTheme(this.value)">
                    <option value="dark" <?php echo ($current_user['theme'] ?? '') === 'dark' ? 'selected' : ''; ?>>Dark</option>
                    <option value="light" <?php echo ($current_user['theme'] ?? '') === 'light' ? 'selected' : ''; ?>>Light</option>
                    <option value="ocean" <?php echo ($current_user['theme'] ?? '') === 'ocean' ? 'selected' : ''; ?>>Ocean</option>
                </select>
            </div>
            <div class="flex gap-1 pt-1 border-t border-theme/50">
                <?php if (!$is_guest): ?>
                    <?php if ($current_user['role'] === 'admin'): ?>
                    <button onclick="openUserModal()" class="flex-1 bg-purple-600/30 hover:bg-purple-600 text-purple-300 hover:text-white border border-purple-500/30 py-1 rounded transition flex items-center justify-center gap-1" title="Manajemen User & Guest"><i class="ti ti-users"></i> Users</button>
                    <?php endif; ?>
                    <button onclick="openModal('change_pw')" class="flex-1 bg-black/20 hover:bg-black/30 border border-theme py-1 rounded transition flex items-center justify-center gap-1 text-yellow-400" title="Ganti Password"><i class="ti ti-key"></i> PW</button>
                    <button onclick="logoutApp()" class="flex-1 bg-red-600/30 hover:bg-red-600 text-red-300 hover:text-white border border-red-500/30 py-1 rounded transition flex items-center justify-center gap-1" title="Keluar"><i class="ti ti-logout"></i> Exit</button>
                <?php else: ?>
                    <div class="flex-1 bg-black/20 text-gray-500 font-bold py-1 text-center rounded border border-theme/50 cursor-not-allowed">
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
                <button id="btn-top-backup" onclick="backupCurrentFile()" class="hidden md:flex bg-amber-600 hover:bg-amber-700 text-white px-2.5 py-1 rounded text-xs font-medium items-center gap-1 shadow transition active:scale-95" title="Duplikasi Backup (.bak)">
                    <i class="ti ti-copy text-sm"></i> <span>Backup</span>
                </button>
                <button id="btn-top-save" onclick="saveCurrentFile()" class="bg-[var(--accent)] hover:opacity-85 text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition active:scale-95" title="Simpan Perubahan (Ctrl+S)">
                    <i class="ti ti-device-floppy text-sm"></i> <span id="top-save-text" class="hidden md:inline">Simpan</span>
                </button>
            </div>
            <?php else: ?>
            <div id="editor-top-actions" class="hidden flex items-center gap-1.5 pl-2 border-l border-theme my-1 flex-shrink-0">
                <span class="bg-amber-500/20 text-amber-300 px-2 py-1 rounded text-xs border border-amber-500/30 font-bold"><i class="ti ti-lock"></i> Read-Only</span>
            </div>
            <?php endif; ?>
        </div>

        <div id="empty-state" class="flex-1 flex flex-col items-center justify-center opacity-50 min-h-0 text-center px-4">
            <i class="ti ti-code text-6xl md:text-8xl mb-4"></i>
            <h2 class="text-lg md:text-xl font-bold tracking-wide">Mini File Manager IDE</h2>
            <p class="text-xs md:text-sm mt-2">CREATE BY ARF</p>
        </div>

        <div id="editor-wrapper" class="flex-1 relative hidden min-h-0 w-full">
            <div id="editor" class="absolute inset-0 w-full h-full"></div>
        </div>
        
        <div id="preview-wrapper" class="flex-1 relative hidden bg-black/5 min-h-0 w-full overflow-hidden">
            <div id="preview-content" class="absolute inset-0 overflow-auto w-full h-full"></div>
        </div>

        <div class="h-8 flex-shrink-0 bg-[var(--accent)] text-white flex items-center justify-between px-2 md:px-4 text-[10px] md:text-xs z-10 w-full">
            <div class="flex items-center gap-2 md:gap-4 truncate">
                <span id="status" class="font-mono flex items-center gap-1 truncate"><i class="ti ti-info-circle text-sm"></i> Siap</span>
                <div id="editor-tools" class="hidden border-l border-white/20 pl-2 md:pl-4 flex items-center gap-2 md:gap-3 flex-shrink-0">
                    <span onclick="editor.trigger('', 'actions.find')" class="cursor-pointer hover:underline flex items-center gap-1" title="Cari di file ini"><i class="ti ti-search text-sm"></i> <span class="hidden md:inline">Find (Ctrl+F)</span></span>
                    <span onclick="editor.trigger('', 'editor.action.startFindReplaceAction')" class="cursor-pointer hover:underline flex items-center gap-1" title="Ganti kata"><i class="ti ti-replace text-sm"></i> <span class="hidden md:inline">Replace</span></span>
                </div>
            </div>
            <?php if (($current_user['mode'] ?? '') !== 'read-only'): ?>
            <div class="flex gap-2 md:gap-4 hidden" id="save-action-bar">
                <span onclick="backupCurrentFile()" class="cursor-pointer hover:underline font-bold flex items-center gap-1 text-amber-300" title="Duplikasi jadi .bak"><i class="ti ti-copy text-sm"></i> <span class="hidden md:inline">Backup (.bak)</span></span>
                <span onclick="saveCurrentFile()" class="cursor-pointer hover:underline font-bold flex items-center gap-1"><i class="ti ti-device-floppy text-sm"></i> <span class="hidden md:inline">Save (Ctrl+S)</span></span>
            </div>
            <?php else: ?>
            <div class="flex gap-2 md:gap-4 hidden text-amber-200 font-bold" id="save-action-bar">
                <span><i class="ti ti-ban"></i> Mode Demo: Simpan Dinonaktifkan</span>
            </div>
            <?php endif; ?>
        </div>
    </main>

    <div id="context-menu" class="hidden absolute z-50 border shadow-2xl rounded py-1.5 text-sm min-w-[210px] max-w-[260px]"></div>

    <div id="modal-overlay" class="hidden fixed inset-0 bg-black/60 z-[100] flex items-center justify-center backdrop-blur-sm p-4">
        <div id="modal-container" class="bg-[var(--bg-tab)] border border-theme rounded-xl shadow-2xl w-full max-w-[500px] max-h-[90vh] flex flex-col overflow-hidden text-[var(--text-main)] animate-scale-up">
            <div class="px-4 py-3 border-b border-theme font-bold flex justify-between items-center bg-black/20">
                <span id="modal-title">Judul Modal</span>
                <i class="ti ti-x cursor-pointer hover:text-red-400 text-lg" onclick="closeModal()"></i>
            </div>
            <div class="p-4 overflow-y-auto" id="modal-body"></div>
            <div class="px-4 py-3 border-t border-theme bg-black/10 flex justify-end gap-2 flex-shrink-0" id="modal-footer">
                <button onclick="closeModal()" class="px-4 py-1.5 rounded text-sm hover:bg-black/20 transition border border-theme">Batal</button>
                <button id="modal-btn-submit" class="px-4 py-1.5 bg-[var(--accent)] text-white rounded text-sm font-semibold hover:opacity-80 transition">Simpan</button>
            </div>
        </div>
    </div>

    <div id="confirm-overlay" class="hidden fixed inset-0 bg-black/60 z-[150] flex items-center justify-center backdrop-blur-sm p-4 transition-opacity">
        <div class="bg-[var(--bg-tab)] border border-theme rounded-xl shadow-2xl w-full max-w-[380px] overflow-hidden text-[var(--text-main)] p-6 flex flex-col items-center text-center animate-scale-up">
            <div id="confirm-icon-box" class="w-14 h-14 rounded-full bg-red-500/10 flex items-center justify-center mb-4 text-2xl text-red-500 border border-red-500/20 shadow-inner">
                <i id="confirm-icon" class="ti ti-alert-triangle"></i>
            </div>
            <h3 id="confirm-title" class="font-bold text-lg mb-1 tracking-wide">Konfirmasi</h3>
            <p id="confirm-message" class="text-xs text-gray-400 mb-6 leading-relaxed break-all">Pesan konfirmasi disini...</p>
            <div class="flex gap-3 w-full">
                <button id="confirm-btn-cancel" class="flex-1 py-2.5 rounded-lg text-xs font-medium bg-black/20 hover:bg-black/30 border border-theme transition text-gray-300 active:scale-95">Batal</button>
                <button id="confirm-btn-yes" class="flex-1 py-2.5 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-700 text-white shadow-lg transition active:scale-95">Ya, Lanjutkan</button>
            </div>
        </div>
    </div>

    <script>
        const CSRF_TOKEN = "<?php echo $_SESSION['csrf_token']; ?>";
        const USER_MODE = "<?php echo $current_user['mode'] ?? 'read-write'; ?>";
        const isGuestMode = <?php echo $is_guest ? 'true' : 'false'; ?>;
        
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

        // --- THEME REALTIME SYNC ENGINE ---
        function applyThemeSilently(theme) {
            if (!theme) return;
            const currentTheme = document.body.getAttribute('data-theme');
            if (currentTheme === theme) return;

            document.body.setAttribute('data-theme', theme);
            const selector = document.getElementById('theme-selector');
            if (selector) selector.value = theme;
            if (editor) monaco.editor.setTheme(theme === 'light' ? 'vs' : 'vs-dark');
            localStorage.setItem('ide_theme', theme);
        }

        function changeTheme(theme) {
            applyThemeSilently(theme);
            if(isGuestMode) return;
            fetch(getApiUrl('save_theme'), { 
                method: 'POST', 
                headers: getHeaders({ 'Content-Type': 'application/json' }), 
                body: JSON.stringify({ theme: theme }) 
            });
        }

        setInterval(() => {
            if (!document.hidden && !isGuestMode) { 
                fetch(getApiUrl('check_theme'))
                    .then(r => r.json())
                    .then(res => {
                        if (res.status === 'ok' && res.theme) {
                            applyThemeSilently(res.theme);
                        }
                    }).catch(() => {});
            }
        }, 3000);

        window.addEventListener('storage', (e) => {
            if (e.key === 'ide_theme' && e.newValue) applyThemeSilently(e.newValue);
        });

        // --- MULTI-SELECT ON-DEMAND LOGIC ---
        function toggleMultiSelectMode(autoSelectPath = null) {
            if (isMultiSelectMode) disableMultiSelectMode();
            else enableMultiSelectMode(autoSelectPath);
        }

        function enableMultiSelectMode(autoSelectPath = null) {
            isMultiSelectMode = true;
            document.body.classList.add('multi-select-active');
            updateBatchActionBar();
            if (autoSelectPath) {
                selectedItems.add(autoSelectPath);
                const cb = document.querySelector(`input[data-path="${CSS.escape(autoSelectPath)}"]`);
                if (cb) cb.checked = true;
                updateBatchActionBar();
            }
        }

        function disableMultiSelectMode() {
            isMultiSelectMode = false;
            document.body.classList.remove('multi-select-active');
            selectedItems.clear();
            document.querySelectorAll('.tree-checkbox').forEach(cb => cb.checked = false);
            updateBatchActionBar();
        }

        function toggleSelect(path, event) {
            event.stopPropagation();
            const checkbox = event.target;
            if (checkbox.checked) selectedItems.add(path); else selectedItems.delete(path);
            updateBatchActionBar();
        }

        function updateBatchActionBar() {
            const bar = document.getElementById('batch-action-bar');
            const count = document.getElementById('selected-count');
            if (isMultiSelectMode && selectedItems.size > 0) {
                bar.classList.remove('hidden'); count.innerText = selectedItems.size;
            } else {
                bar.classList.add('hidden');
            }
        }

        // --- PROMISE-BASED CONFIRM ---
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
                    iconBox.className = 'w-14 h-14 rounded-full bg-red-500/10 flex items-center justify-center mb-4 text-2xl text-red-500 border border-red-500/20 shadow-inner';
                    icon.className = 'ti ti-alert-triangle animate-bounce';
                    btnYes.className = 'flex-1 py-2.5 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-700 text-white shadow-lg transition active:scale-95';
                } else {
                    iconBox.className = 'w-14 h-14 rounded-full bg-yellow-500/10 flex items-center justify-center mb-4 text-2xl text-yellow-500 border border-yellow-500/20 shadow-inner';
                    icon.className = 'ti ti-alert-circle';
                    btnYes.className = 'flex-1 py-2.5 rounded-lg text-xs font-bold bg-[var(--accent)] hover:opacity-90 text-white shadow-lg transition active:scale-95';
                }

                overlay.classList.remove('hidden');
                const cleanup = (result) => {
                    overlay.classList.add('hidden'); btnYes.onclick = null; btnCancel.onclick = null; resolve(result);
                };
                btnYes.onclick = () => cleanup(true); btnCancel.onclick = () => cleanup(false);
            });
        }

        const getApiUrl = (action, params = '') => {
            const baseUrl = window.location.href.split('?')[0];
            let url = baseUrl + '?ajax=1&action=' + action + (params ? '&' + params : '');
            if (isGuestMode) url += '&embed=1'; 
            return url;
        };

        const getDirectFileUrl = (filePath) => {
            const baseUrl = window.location.href.split('?')[0];
            const dirUrl = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
            return dirUrl + filePath.split('/').map(encodeURIComponent).join('/');
        };

        // --- RESIZER ---
        const dragHandle = document.getElementById('drag-handle');
        const sidebar = document.getElementById('sidebar');
        let isResizing = false;

        dragHandle.addEventListener('mousedown', () => { isResizing = true; document.body.style.cursor = 'col-resize'; });
        document.addEventListener('mousemove', (e) => {
            if (!isResizing || window.innerWidth <= 768) return;
            let newWidth = e.clientX;
            if (newWidth < 200) newWidth = 200; if (newWidth > 600) newWidth = 600;
            sidebar.style.width = newWidth + 'px';
            if (editor) editor.layout();
        });
        document.addEventListener('mouseup', () => { isResizing = false; document.body.style.cursor = 'default'; });

        document.getElementById('search-input').addEventListener('input', function(e) {
            const term = e.target.value.toLowerCase();
            document.querySelectorAll('#file-tree .tree-item').forEach(li => {
                const name = li.querySelector('.truncate:not(.text-gray-300)').innerText.toLowerCase(); 
                if (name.includes(term)) {
                    li.style.display = 'block';
                    let parentUl = li.closest('ul.folder-content');
                    while(parentUl) { parentUl.classList.remove('hidden'); parentUl = parentUl.parentElement.closest('ul.folder-content'); }
                } else { li.style.display = 'none'; }
            });
        });

        function batchZipDownload() {
            if (selectedItems.size === 0) return;
            document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memproses kompresi ZIP...`;
            
            fetch(getApiUrl('batch_zip'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ items: Array.from(selectedItems) })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check"></i> ZIP Berhasil Dibuat! Mengunduh...`;
                    window.open(res.zip_url, '_blank');
                    disableMultiSelectMode();
                } else {
                    alert(res.error || 'Gagal membuat file ZIP');
                    document.getElementById('status').innerHTML = `<i class="ti ti-alert-circle"></i> Gagal membuat ZIP`;
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
            const createBtns = USER_MODE === 'read-only' ? '' : `
                <span onclick="openModal('create', currentExplorerRoot, 'file')" class="cursor-pointer hover:text-[var(--accent)]" title="Buat File"><i class="ti ti-file-plus"></i></span>
                <span onclick="openModal('create', currentExplorerRoot, 'folder')" class="cursor-pointer hover:text-[var(--accent)]" title="Buat Folder"><i class="ti ti-folder-plus"></i></span>
            `;

            if (currentExplorerRoot !== '') {
                header.innerHTML = `
                    <div class="flex items-center gap-1.5 text-yellow-500 font-bold truncate cursor-pointer hover:underline" onclick="drillUpFolder()" title="Kembali ke folder atas">
                        <i class="ti ti-arrow-left text-base"></i> <span class="truncate">${currentExplorerRoot.split('/').pop() || 'Root'}</span>
                    </div>
                    <div class="flex gap-2 text-base flex-shrink-0">
                        <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-[var(--accent)]" title="Pilih Banyak (Multi-Select)"><i class="ti ti-checkbox"></i></span>
                        <span onclick="drillDownFolder('')" class="cursor-pointer hover:text-[var(--accent)]" title="Ke Root Utama"><i class="ti ti-home"></i></span>
                        ${createBtns}
                        <span onclick="loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-[var(--accent)] font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
                    </div>
                `;
            } else {
                header.innerHTML = `
                    <span>Explorer</span>
                    <div class="flex gap-2 text-base">
                        <span onclick="toggleMultiSelectMode()" class="cursor-pointer hover:text-[var(--accent)]" title="Pilih Banyak (Multi-Select)"><i class="ti ti-checkbox"></i></span>
                        ${createBtns}
                        <span onclick="loadFolder('', document.getElementById('file-tree'), 0)" class="cursor-pointer hover:text-[var(--accent)] font-bold" title="Refresh"><i class="ti ti-refresh"></i></span>
                    </div>
                `;
            }
        }

        // --- CUSTOM MODALS & AUTOCOMPLETE ---
        let currentModalAction = null; let modalTargetPath = '';
        
        function setupAutocomplete(inputId) {
            const input = document.getElementById(inputId);
            if (!input) return;
            
            let wrapper = input.parentNode;
            wrapper.style.position = 'relative'; 
            
            let listContainer = document.getElementById(inputId + '-ac-list');
            if (!listContainer) {
                listContainer = document.createElement('div');
                listContainer.id = inputId + '-ac-list';
                listContainer.className = 'absolute z-[200] bg-[var(--bg-sidebar)] border border-theme w-full rounded-md mt-1 shadow-2xl max-h-48 overflow-y-auto hidden';
                wrapper.appendChild(listContainer);
            }

            input.addEventListener('input', function() {
                const val = this.value;
                const parts = val.split(',');
                const currentPart = parts[parts.length - 1].trim();
                
                if (currentPart.length >= 1) { 
                    fetch(getApiUrl('autocomplete', 'query=' + encodeURIComponent(currentPart)))
                    .then(r => r.json())
                    .then(res => {
                        if (res.status === 'ok' && res.results.length > 0) {
                            listContainer.innerHTML = '';
                            res.results.forEach(item => {
                                let div = document.createElement('div');
                                const icon = item.type === 'folder' ? '<i class="ti ti-folder text-yellow-500"></i>' : '<i class="ti ti-file text-blue-400"></i>';
                                div.innerHTML = `<div class="px-3 py-2 hover:bg-[var(--accent)] hover:text-white cursor-pointer text-[11px] font-mono flex items-center gap-2 border-b border-theme transition-colors">${icon} <span class="truncate">${item.path}</span></div>`;
                                div.onclick = function() {
                                    parts[parts.length - 1] = ' ' + item.path;
                                    input.value = parts.join(',').trim();
                                    listContainer.classList.add('hidden');
                                    input.focus();
                                };
                                listContainer.appendChild(div);
                            });
                            listContainer.classList.remove('hidden');
                        } else {
                            listContainer.classList.add('hidden');
                        }
                    });
                } else {
                    listContainer.classList.add('hidden');
                }
            });

            document.addEventListener('click', function (e) {
                if (e.target !== input && !listContainer.contains(e.target)) {
                    listContainer.classList.add('hidden');
                }
            });
        }

        function openModal(action, path = '', type = '') {
            if (USER_MODE === 'read-only' && ['create', 'rename', 'upload', 'remote', 'batch_copy_move', 'copy_move_single'].includes(action)) {
                return alert('Akses Ditolak! Akun Anda berada dalam Mode Read-Only / Demo.');
            }

            const overlay = document.getElementById('modal-overlay');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            const btn = document.getElementById('modal-btn-submit');
            const footer = document.getElementById('modal-footer');
            
            modalTargetPath = path || currentExplorerRoot; currentModalAction = { action, type };
            footer.classList.remove('hidden');

            if (action === 'create') {
                title.innerText = type === 'folder' ? 'Buat Folder Baru' : 'Buat File Baru';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Lokasi: ${modalTargetPath || '/'}</label><input type="text" id="modal-input-name" class="w-full bg-black/20 border border-theme rounded p-2 text-sm focus:outline-[var(--accent)]" placeholder="Nama ${type}...">`;
                btn.innerText = 'Buat'; btn.onclick = executeCreate;
            } else if (action === 'rename') {
                title.innerText = 'Ganti Nama'; const oldName = path.split('/').pop();
                body.innerHTML = `<input type="text" id="modal-input-name" class="w-full bg-black/20 border border-theme rounded p-2 text-sm focus:outline-[var(--accent)]" value="${oldName}">`;
                btn.innerText = 'Simpan'; btn.onclick = executeRename;
            } else if (action === 'upload') {
                title.innerText = 'Upload File';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Ke Lokasi: ${modalTargetPath || '/'}</label><input type="file" id="modal-input-file" class="w-full bg-black/20 border border-theme rounded p-2 text-sm cursor-pointer">`;
                btn.innerText = 'Upload'; btn.onclick = executeUpload;
            } else if (action === 'remote') {
                title.innerText = 'Download dari URL';
                body.innerHTML = `<label class="block text-xs mb-1 opacity-70">Simpan ke: ${modalTargetPath || '/'}</label><input type="url" id="modal-input-url" class="w-full bg-black/20 border border-theme rounded p-2 text-sm focus:outline-[var(--accent)]" placeholder="https://contoh.com/gambar.jpg">`;
                btn.innerText = 'Download'; btn.onclick = executeRemoteDownload;
            } else if (action === 'batch_copy_move') {
                title.innerText = `Copy / Move (${selectedItems.size} Item Terpilih)`;
                body.innerHTML = `
                    <label class="block text-xs mb-1 opacity-70">Folder Tujuan (Kosongkan jika ke Root):</label>
                    <input type="text" id="modal-input-dest" class="w-full bg-black/20 border border-theme rounded p-2 text-sm focus:outline-[var(--accent)] mb-4" placeholder="contoh: folder/backup" value="${currentExplorerRoot}">
                    <label class="block text-xs mb-1 opacity-70">Pilih Mode Tindakan:</label>
                    <div class="flex gap-3">
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs bg-black/20 border border-theme px-3 py-2 rounded flex-1 hover:border-blue-400 transition"><input type="radio" name="batch-mode" value="copy" checked> <i class="ti ti-copy text-blue-400"></i> Copy</label>
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs bg-black/20 border border-theme px-3 py-2 rounded flex-1 hover:border-red-400 transition"><input type="radio" name="batch-mode" value="move"> <i class="ti ti-cut text-red-400"></i> Move</label>
                    </div>
                `;
                btn.innerText = 'Proses'; btn.onclick = executeBatchCopyMove;
            } else if (action === 'copy_move_single') {
                title.innerText = `Copy / Move: ${path.split('/').pop()}`;
                body.innerHTML = `
                    <div class="bg-black/20 p-2.5 rounded border border-theme text-xs mb-4 font-mono truncate text-yellow-500"><i class="ti ti-file text-sm"></i> Item: ${path}</div>
                    <label class="block text-xs mb-1 opacity-70">Folder Tujuan:</label>
                    <input type="text" id="modal-input-dest" class="w-full bg-black/20 border border-theme rounded p-2 text-sm focus:outline-[var(--accent)] mb-4" placeholder="contoh: folder_backup" value="${currentExplorerRoot}">
                    <div class="flex gap-3">
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs bg-black/20 border border-theme px-3 py-2 rounded flex-1 hover:border-blue-400 transition"><input type="radio" name="single-mode" value="copy" checked> <i class="ti ti-copy text-blue-400"></i> Copy</label>
                        <label class="flex items-center justify-center gap-1.5 cursor-pointer font-medium text-xs bg-black/20 border border-theme px-3 py-2 rounded flex-1 hover:border-red-400 transition"><input type="radio" name="single-mode" value="move"> <i class="ti ti-cut text-red-400"></i> Move</label>
                    </div>
                `;
                btn.innerText = 'Eksekusi'; btn.onclick = () => executeSingleCopyMove(path);
            } else if (action === 'change_pw') {
                title.innerText = 'Ganti Password Akun';
                body.innerHTML = `
                    <div class="space-y-3">
                        <div><label class="block text-xs mb-1 opacity-70">Password Lama</label><input type="password" id="pw-old" class="w-full bg-black/20 border border-theme rounded p-2 text-sm"></div>
                        <div><label class="block text-xs mb-1 opacity-70">Password Baru</label><input type="password" id="pw-new" class="w-full bg-black/20 border border-theme rounded p-2 text-sm"></div>
                    </div>
                `;
                btn.innerText = 'Ubah Password'; btn.onclick = executeChangePassword;
            }

            overlay.classList.remove('hidden');
            setTimeout(() => { if(document.getElementById('modal-input-name')) document.getElementById('modal-input-name').focus(); }, 100);
        }

        function closeModal() { document.getElementById('modal-overlay').classList.add('hidden'); }

        function executeChangePassword() {
            const old_pw = document.getElementById('pw-old').value;
            const new_pw = document.getElementById('pw-new').value;
            if(!old_pw || !new_pw) return alert('Semua kolom wajib diisi!');
            
            fetch(getApiUrl('change_pw'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ old_password: old_pw, new_password: new_pw })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { alert('Password berhasil diubah!'); closeModal(); }
                else alert(res.error || 'Gagal mengubah password');
            });
        }

        // --- MANAJEMEN USER & GUEST DENGAN AUTOCOMPLETE ---
        function openUserModal() {
            const overlay = document.getElementById('modal-overlay');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            const footer = document.getElementById('modal-footer');

            title.innerText = 'Manajemen Akses & Embed Guest';
            body.innerHTML = '<div class="text-center py-4 text-xs opacity-70"><i class="ti ti-loader-2 animate-spin text-xl inline-block"></i> Memuat konfigurasi...</div>';
            footer.classList.add('hidden'); // Sembunyikan footer standar, simpan dilakukan per-section
            overlay.classList.remove('hidden');

            fetch(getApiUrl('list_users')).then(r => r.json()).then(res => {
                if (res.error) { body.innerHTML = `<div class="p-4 text-red-400 text-xs text-center">${res.error}</div>`; return; }
                
                let html = `
                    <div class="space-y-4">
                        <div class="bg-blue-500/10 p-3.5 rounded-lg border border-blue-500/30 shadow-inner">
                            <h4 class="font-bold text-[11px] uppercase text-blue-400 mb-3 flex items-center gap-1.5"><i class="ti ti-world text-sm"></i> Konfigurasi Link Embed / Guest</h4>
                            <div class="flex items-center gap-2 mb-3">
                                <label class="text-xs font-bold text-gray-300">Izinkan Akses Publik (?embed=1)</label>
                                <input type="checkbox" id="guest-active" ${res.guest.is_active ? 'checked' : ''} class="cursor-pointer w-4 h-4 rounded accent-[var(--accent)]">
                            </div>
                            <div class="relative w-full">
                                <label class="block text-[10px] text-gray-400 mb-1 font-bold">Daftar Akses File & Folder Guest:</label>
                                <input type="text" id="guest-paths" value="${res.guest.allowed_paths.join(', ')}" class="w-full bg-[var(--bg-main)] border border-theme rounded p-2 text-xs font-mono focus:border-blue-400 focus:outline-none transition-colors" placeholder="/, /css/style.css" autocomplete="off">
                                <span class="text-[9px] text-gray-400 mt-1 block">Ketik 1-2 huruf akan otomatis memunculkan sugesti file/folder.</span>
                            </div>
                            <button onclick="executeUpdateGuest()" class="mt-3 w-full py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-bold transition shadow-lg active:scale-95 flex items-center justify-center gap-1"><i class="ti ti-device-floppy"></i> Simpan Konfigurasi Guest</button>
                        </div>

                        <div class="bg-black/20 p-3.5 rounded-lg border border-theme shadow-inner">
                            <h4 class="font-bold text-[11px] uppercase text-[var(--accent)] mb-3 flex items-center gap-1.5"><i class="ti ti-user-plus text-sm"></i> Tambah User Baru</h4>
                            <div class="grid grid-cols-2 gap-3 mb-3">
                                <div><label class="block text-[10px] text-gray-400 mb-1 font-bold">Username</label><input type="text" id="new-u-name" placeholder="Username" class="w-full bg-[var(--bg-main)] border border-theme rounded p-2 text-xs focus:outline-none focus:border-[var(--accent)]"></div>
                                <div><label class="block text-[10px] text-gray-400 mb-1 font-bold">Password</label><input type="password" id="new-u-pass" placeholder="Password" class="w-full bg-[var(--bg-main)] border border-theme rounded p-2 text-xs focus:outline-none focus:border-[var(--accent)]"></div>
                            </div>
                            <div class="grid grid-cols-1 gap-3">
                                <div>
                                    <label class="block text-[10px] text-gray-400 mb-1 font-bold">Mode Akses (RBAC):</label>
                                    <select id="new-u-mode" class="w-full bg-[var(--bg-main)] border border-theme rounded p-2 text-xs focus:outline-none focus:border-[var(--accent)]">
                                        <option value="read-write">Normal (Bisa Edit, Simpan, Hapus)</option>
                                        <option value="read-only">Demo (Hanya Bisa Buka / Read-Only)</option>
                                    </select>
                                </div>
                                <div class="relative w-full">
                                    <label class="block text-[10px] text-gray-400 mb-1 font-bold">Daftar Akses File & Folder:</label>
                                    <input type="text" id="new-u-paths" placeholder="/, /js/main.js, /folder/rahasia" class="w-full bg-[var(--bg-main)] border border-theme rounded p-2 text-xs font-mono focus:outline-none focus:border-[var(--accent)]" autocomplete="off">
                                </div>
                            </div>
                            <button onclick="executeAddUser()" class="mt-4 w-full py-2 bg-[var(--accent)] hover:opacity-90 text-white rounded text-xs font-bold transition shadow-lg active:scale-95 flex items-center justify-center gap-1"><i class="ti ti-plus"></i> Tambahkan User</button>
                        </div>
                        
                        <div class="space-y-2 max-h-48 overflow-y-auto pr-1">
                `;
                
                res.users.forEach(u => {
                    const delBtn = u.role === 'admin' ? '' : `<button onclick="executeDeleteUser('${u.username}')" class="text-red-400 hover:bg-red-500/10 p-1.5 rounded transition" title="Hapus User"><i class="ti ti-trash"></i></button>`;
                    const modeBadge = u.mode === 'read-only' ? '<span class="bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[9px] px-1.5 py-0.5 rounded font-mono">DEMO</span>' : '<span class="bg-green-500/20 text-green-400 border border-green-500/30 text-[9px] px-1.5 py-0.5 rounded font-mono">NORMAL</span>';
                    html += `
                        <div class="flex items-center justify-between p-2.5 bg-black/10 rounded-lg border border-theme text-xs shadow-sm">
                            <div class="min-w-0 flex-1 mr-2">
                                <div class="font-bold truncate flex items-center gap-1.5">
                                    <i class="ti ti-user text-gray-400"></i> ${u.username} 
                                    <span class="bg-white/10 text-[9px] px-1.5 rounded uppercase font-mono">${u.role}</span>
                                    ${modeBadge}
                                </div>
                                <div class="text-[10px] text-gray-400 font-mono truncate mt-1.5" title="Akses: ${u.allowed_paths}">Akses: <span class="text-yellow-400">${u.allowed_paths}</span></div>
                            </div>
                            ${delBtn}
                        </div>
                    `;
                });
                html += '</div></div>';
                body.innerHTML = html;
                
                // Init Autocomplete
                setupAutocomplete('guest-paths');
                setupAutocomplete('new-u-paths');
            });
        }

        function executeUpdateGuest() {
            const isActive = document.getElementById('guest-active').checked;
            const paths = document.getElementById('guest-paths').value.trim();
            
            fetch(getApiUrl('update_guest'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ is_active: isActive, allowed_paths: paths })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') { alert('Konfigurasi Embed Guest berhasil disimpan!'); openUserModal(); }
                else alert(res.error || 'Gagal menyimpan konfigurasi');
            });
        }

        function executeAddUser() {
            const uname = document.getElementById('new-u-name').value.trim();
            const pass = document.getElementById('new-u-pass').value;
            const mode = document.getElementById('new-u-mode').value;
            const paths = document.getElementById('new-u-paths').value.trim();
            if(!uname || !pass) return alert('Username & Password wajib diisi!');

            fetch(getApiUrl('add_user'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ username: uname, password: pass, mode: mode, allowed_paths: paths })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') openUserModal();
                else alert(res.error || 'Gagal menambah user');
            });
        }

        function executeDeleteUser(uname) {
            if(!confirm(`Hapus user "${uname}" permanen?`)) return;
            fetch(getApiUrl('delete_user'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ username: uname })
            }).then(r => r.json()).then(res => {
                if(res.status === 'ok') openUserModal();
                else alert(res.error || 'Gagal menghapus user');
            });
        }

        function showMetadataModal(path, type) {
            const overlay = document.getElementById('modal-overlay');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            const footer = document.getElementById('modal-footer');
            
            title.innerText = `Detail Metadata ${type === 'folder' ? 'Folder' : 'File'}`;
            body.innerHTML = `<div class="py-8 text-center text-xs opacity-70"><i class="ti ti-loader-2 animate-spin text-2xl mb-2 inline-block"></i><br>Mengambil data metadata dari server...</div>`;
            footer.classList.remove('hidden'); footer.innerHTML = '<button onclick="closeModal()" class="px-4 py-1.5 rounded text-sm hover:bg-black/20 transition border border-theme w-full text-center block">Tutup</button>'; 
            overlay.classList.remove('hidden');

            fetch(getApiUrl('info', 'path=' + encodeURIComponent(path))).then(r => r.json()).then(data => {
                if (data.error) { body.innerHTML = `<div class="p-4 text-red-400 text-center text-xs">${data.error}</div>`; return; }
                const icon = type === 'folder' ? '<i class="ti ti-folder text-yellow-500 text-3xl"></i>' : getFileInfo(data.name).icon;
                
                let extraRow = type === 'folder' ? `<div class="flex justify-between py-1.5 border-b border-theme"><span class="text-gray-400 font-medium">Isi Kandungan:</span><span class="font-bold text-yellow-400">${data.contents || 'Kosong'}</span></div>` : (data.dimensions && data.dimensions !== 'N/A' ? `<div class="flex justify-between py-1.5 border-b border-theme"><span class="text-gray-400 font-medium">Resolusi Gambar:</span><span class="font-bold text-purple-400">${data.dimensions}</span></div>` : '');

                body.innerHTML = `
                    <div class="flex items-center gap-3 p-3 bg-black/20 rounded-lg border border-theme mb-4">
                        <div class="text-3xl flex-shrink-0">${icon}</div>
                        <div class="min-w-0 flex-1"><h4 class="font-bold text-sm truncate" title="${data.name}">${data.name}</h4><span class="text-[11px] text-gray-400 font-mono">${data.mime || type}</span></div>
                    </div>
                    <div class="text-xs space-y-1 font-mono">
                        <div class="py-1.5 border-b border-theme"><span class="text-gray-400 block text-[10px] uppercase font-bold mb-0.5">Full Path Lokasi:</span><span class="font-bold text-yellow-500 block truncate select-all bg-black/30 p-1.5 rounded border border-theme" title="${data.full_path}">${data.full_path}</span></div>
                        <div class="flex justify-between py-1.5 border-b border-theme"><span class="text-gray-400 font-medium">Ukuran (Size):</span><span class="font-bold text-green-400">${data.size}</span></div>
                        ${extraRow}
                        <div class="flex justify-between py-1.5 border-b border-theme"><span class="text-gray-400 font-medium">Terakhir Diubah:</span><span class="font-bold text-sky-400">${data.modified || 'N/A'}</span></div>
                        <div class="flex justify-between py-1.5"><span class="text-gray-400 font-medium">Hak Akses (Chmod):</span><span class="font-bold text-orange-400 bg-black/30 px-2 py-0.5 rounded border border-theme">${data.permissions || '0755'}</span></div>
                    </div>
                `;
            }).catch(() => { body.innerHTML = `<div class="p-4 text-red-400 text-center text-xs">Gagal mengambil data dari server.</div>`; });
        }

        function executeCreate() {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat membuat item baru!');
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
            const dest = document.getElementById('modal-input-dest').value.trim();
            const mode = document.querySelector('input[name="batch-mode"]:checked').value;
            document.getElementById('modal-btn-submit').innerText = 'Memproses...';
            fetch(getApiUrl('batch_action'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ items: Array.from(selectedItems), dest: dest, mode: mode })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    disableMultiSelectMode(); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal();
                } else alert(res.error || 'Gagal memproses aksi');
            });
        }

        function executeSingleCopyMove(itemPath) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat memproses Copy/Move!');
            const dest = document.getElementById('modal-input-dest').value.trim();
            const mode = document.querySelector('input[name="single-mode"]:checked').value;
            document.getElementById('modal-btn-submit').innerText = 'Memproses...';
            fetch(getApiUrl('batch_action'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ items: [itemPath], dest: dest, mode: mode })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-green-400"></i> Berhasil di-${mode === 'copy' ? 'copy' : 'move'}: ${itemPath}`;
                    loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0); closeModal();
                } else alert(res.error || 'Gagal memproses aksi copy/move');
            });
        }

        function backupItem(filePath) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat membuat file backup (.bak)!');
            document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Membuat backup: ${filePath}...`;
            fetch(getApiUrl('backup'), {
                method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ path: filePath })
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-green-400"></i> Backup sukses: ${res.backup_file}`;
                    loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0);
                    setTimeout(() => { if (activeTab === filePath) document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Editing: ${filePath}`; }, 3000);
                } else {
                    alert(res.error || 'Gagal membuat file backup (.bak)!');
                    document.getElementById('status').innerHTML = `<i class="ti ti-alert-circle text-red-400"></i> Gagal backup file`;
                }
            }).catch(() => { alert('Terjadi kesalahan koneksi saat proses backup.'); });
        }

        function backupCurrentFile() { if (!activeTab) return; backupItem(activeTab); }

        // --- CONTEXT MENU DINAMIS SESUAI ROLE/MODE ---
        const contextMenu = document.getElementById('context-menu');
        function clearContextMenuHighlight() {
            if (activeContextElement) { activeContextElement.classList.remove('bg-[var(--accent)]', 'text-white'); activeContextElement = null; }
        }

        window.addEventListener('click', () => { contextMenu.classList.add('hidden'); clearContextMenuHighlight(); }, true);
        window.addEventListener('contextmenu', (e) => {
            if (!e.target.closest('aside') && !e.target.closest('#context-menu')) { contextMenu.classList.add('hidden'); clearContextMenuHighlight(); }
        }, true);

        function showContextMenu(e, path, type, element) {
            e.preventDefault(); e.stopPropagation(); clearContextMenuHighlight(); 
            if (element && type !== 'root') { activeContextElement = element; activeContextElement.classList.add('bg-[var(--accent)]', 'text-white'); }

            contextMenu.innerHTML = ''; let menuHTML = '';
            const createItem = (icon, text, onClickFunc, extraClass='') => {
                return `<div class="px-4 py-2 hover:bg-black/20 cursor-pointer flex items-center gap-2.5 transition-colors ${extraClass}" onclick="document.getElementById('context-menu').classList.add('hidden'); clearContextMenuHighlight(); ${onClickFunc}"><i class="${icon} text-[16px]"></i> <span>${text}</span></div>`;
            };
            const createDivider = () => `<div class="border-t border-theme my-1 mx-1"></div>`;

            if (type !== 'root') {
                menuHTML += createItem('ti ti-checkbox text-[var(--accent)] font-bold', 'Pilih Banyak (Multi-Select)', `enableMultiSelectMode('${path}');`);
                menuHTML += createDivider();
            }

            if (type === 'folder' || type === 'root') {
                if (type === 'folder') {
                    menuHTML += createItem('ti ti-folder-open text-yellow-400 font-bold', 'Buka Full di Sidebar', `drillDownFolder('${path}');`);
                    if (USER_MODE !== 'read-only') {
                        menuHTML += createItem('ti ti-copy text-blue-400 font-bold', 'Copy / Move ke Folder Lain', `openModal('copy_move_single', '${path}', 'folder');`);
                    }
                    menuHTML += createItem('ti ti-info-circle text-purple-400 font-bold', 'Detail & Metadata Folder', `showMetadataModal('${path}', 'folder');`);
                    menuHTML += createDivider();
                }
                if (USER_MODE !== 'read-only') {
                    menuHTML += createItem('ti ti-file-plus', 'Buat File Baru', `openModal('create', '${path}', 'file');`);
                    menuHTML += createItem('ti ti-folder-plus', 'Buat Folder Baru', `openModal('create', '${path}', 'folder');`);
                    menuHTML += createItem('ti ti-upload', 'Upload File Kesini', `openModal('upload', '${path}');`);
                    menuHTML += createItem('ti ti-cloud-download', 'Download URL Kesini', `openModal('remote', '${path}');`);
                }
            }
            if (type !== 'root') {
                if (type === 'folder' && USER_MODE !== 'read-only') menuHTML += createDivider();
                if (type === 'file') {
                    menuHTML += createItem('ti ti-external-link text-[var(--accent)] font-bold', 'Buka File Langsung', `window.open(getDirectFileUrl('${path}'), '_blank')`);
                    if (USER_MODE !== 'read-only') {
                        menuHTML += createItem('ti ti-copy text-amber-400 font-bold', 'Buat Backup (.bak)', `backupItem('${path}')`);
                        menuHTML += createItem('ti ti-copy text-blue-400 font-bold', 'Copy / Move ke Folder Lain', `openModal('copy_move_single', '${path}', 'file');`);
                    }
                    menuHTML += createItem('ti ti-info-circle text-purple-400 font-bold', 'Detail & Metadata File', `showMetadataModal('${path}', 'file');`);
                    menuHTML += createItem('ti ti-download', 'Download File', `window.open(getApiUrl('download', 'path=' + encodeURIComponent('${path}')), '_blank')`);
                    if (USER_MODE !== 'read-only') menuHTML += createDivider();
                }
                if (USER_MODE !== 'read-only') {
                    menuHTML += createItem('ti ti-pencil', 'Ganti Nama (Rename)', `openModal('rename', '${path}');`);
                    menuHTML += createDivider();
                    menuHTML += createItem('ti ti-trash text-red-500', '<span class="text-red-500">Hapus Permanen</span>', `deleteItem('${path}');`);
                }
            }

            contextMenu.innerHTML = menuHTML;
            let x = e.clientX; let y = e.clientY; contextMenu.classList.remove('hidden');
            const menuRect = contextMenu.getBoundingClientRect();
            if (x + menuRect.width > window.innerWidth) x -= menuRect.width;
            if (y + menuRect.height > window.innerHeight) y -= menuRect.height;
            contextMenu.style.left = `${x}px`; contextMenu.style.top = `${y}px`;
        }

        // --- SESSION PERSISTENCE ---
        function saveSession() {
            const sessionData = { files: Object.keys(tabs), active: activeTab };
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
            const savedRoot = localStorage.getItem('ide_explorer_root');
            if (savedRoot !== null) currentExplorerRoot = savedRoot;
            renderSidebarHeader(); loadFolder(currentExplorerRoot, document.getElementById('file-tree'), 0);
            restoreSession();
        });

        // --- MONACO EDITOR ---
        require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' }});
        require(['vs/editor/editor.main'], () => {
            const isLight = document.body.getAttribute('data-theme') === 'light';
            editor = monaco.editor.create(document.getElementById('editor'), { 
                theme: isLight ? 'vs' : 'vs-dark', automaticLayout: true, fontSize: 14, model: null,
                readOnly: USER_MODE === 'read-only',
                find: { addExtraClassToFindWidget: true, seedSearchStringFromSelection: 'always', autoSelectWithPaste: true }
            });
            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => { saveCurrentFile(); });
            if (activeTab && tabs[activeTab] && tabs[activeTab].type === 'code') switchTab(activeTab);
        });

        function getFileInfo(fileName) {
            const ext = fileName.split('.').pop().toLowerCase();
            if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp', 'tiff'].includes(ext)) return { type: 'image', icon: '<i class="ti ti-photo"></i>', color: 'text-purple-400', label: 'File Gambar (Image)' };
            if (['mp4', 'webm', 'ogg', 'mkv', 'avi', 'mov', 'flv'].includes(ext)) return { type: 'video', icon: '<i class="ti ti-video"></i>', color: 'text-pink-400', label: 'File Video / Multimedia' };
            if (['mp3', 'wav', 'flac', 'aac', 'm4a', 'wma'].includes(ext)) return { type: 'audio', icon: '<i class="ti ti-music"></i>', color: 'text-yellow-400', label: 'File Audio / Musik' };
            if (['pdf'].includes(ext)) return { type: 'pdf', icon: '<i class="ti ti-file-type-pdf"></i>', color: 'text-red-400', label: 'Dokumen PDF' };
            if (['ppt', 'pptx', 'odp', 'key'].includes(ext)) return { type: 'ppt', icon: '<i class="ti ti-file-presentation"></i>', color: 'text-orange-500', label: 'Dokumen Presentasi PowerPoint' };
            if (['doc', 'docx', 'rtf', 'odt', 'pages', 'epub'].includes(ext)) return { type: 'word', icon: '<i class="ti ti-file-word"></i>', color: 'text-blue-500', label: 'Dokumen Microsoft Word' };
            if (['xls', 'xlsx', 'ods', 'numbers'].includes(ext)) return { type: 'excel', icon: '<i class="ti ti-file-spreadsheet"></i>', color: 'text-green-500', label: 'Dokumen Spreadsheet Excel' };
            if (['zip', 'rar', 'tar', 'gz', '7z', 'bz2', 'xz', 'iso', 'tgz', 'cab', 'lz', 'zst'].includes(ext)) return { type: 'archive', icon: '<i class="ti ti-file-zip"></i>', color: 'text-orange-400', label: 'File Arsip / Terkompresi' };
            if (['exe', 'msi', 'com', 'dll', 'sys', 'ini_bin', 'ocx', 'drv', 'lib', 'a', 'o', 'obj', 'pdb', 'bin', 'dat', 'rom', 'firmware', 'hex', 'apk', 'xapk', 'aab', 'ipa', 'dmg', 'pkg', 'app', 'deb', 'rpm', 'so', 'appimage', 'flatpak', 'snap', 'db', 'sqlite', 'sqlite3', 'mdb', 'accdb', 'sqlitedb', 'frm', 'ibd', 'myd', 'myi', 'ttf', 'otf', 'woff', 'woff2', 'eot'].includes(ext)) return { type: 'binary', icon: '<i class="ti ti-cpu"></i>', color: 'text-slate-400', label: 'File Binary / System / App' };
            if (['bak'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-history"></i>', color: 'text-amber-400', label: 'File Backup Code/Text' };
            if (['csv', 'tsv'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-table"></i>', color: 'text-emerald-400', label: 'CSV / Tabular Data Text' };
            if (['php', 'phtml'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-php"></i>', color: 'text-indigo-400', label: 'PHP Script' };
            if (['js', 'jsx', 'mjs', 'ts', 'tsx'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-javascript"></i>', color: 'text-yellow-400', label: 'JavaScript / TypeScript' };
            if (['html', 'htm', 'xhtml'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-html5"></i>', color: 'text-orange-500', label: 'HTML Document' };
            if (['css', 'scss', 'less', 'sass'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-css3"></i>', color: 'text-blue-400', label: 'Stylesheet CSS' };
            if (['json', 'json5'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-braces"></i>', color: 'text-green-400', label: 'JSON Data' };
            if (['py', 'pyw', 'ipynb'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-python"></i>', color: 'text-blue-300', label: 'Python Script' };
            if (['java', 'class', 'jar'].includes(ext)) {
                if (ext === 'jar' || ext === 'class') return { type: 'binary', icon: '<i class="ti ti-cup"></i>', color: 'text-red-500', label: 'Java Compiled Binary/Archive' };
                return { type: 'code', icon: '<i class="ti ti-cup"></i>', color: 'text-red-500', label: 'Java Source Code' };
            }
            if (['c', 'cpp', 'h', 'hpp', 'cs'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-brand-cpp"></i>', color: 'text-blue-500', label: 'C / C++ / C# Source Code' };
            if (['sql'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-database-export"></i>', color: 'text-cyan-400', label: 'SQL Query Script' };
            if (['md', 'markdown'].includes(ext)) return { type: 'code', icon: '<i class="ti ti-markdown"></i>', color: 'text-sky-300', label: 'Markdown Text' };
            return { type: 'code', icon: '<i class="ti ti-file-code"></i>', color: 'text-gray-400', label: 'Text / Code File' };
        }

        async function deleteItem(path) {
            if(USER_MODE === 'read-only') return alert('Mode Demo tidak dapat menghapus file!');
            const confirmed = await showConfirm('Hapus File Permanen?', `Yakin ingin menghapus:<br><span class="font-mono text-yellow-500 font-bold mt-1 inline-block select-all bg-black/20 px-2 py-0.5 rounded border border-theme">${path}</span><br><span class="text-red-400 block mt-2">Tindakan ini tidak dapat dibatalkan!</span>`, true, 'Ya, Hapus Permanen');
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
                    containerEl.innerHTML = `<li class="py-1 text-xs text-red-400" style="padding-left: ${padLeft}px">${data.error}</li>`; return; 
                }
                containerEl.innerHTML = '';
                if (data.items.length === 0) { containerEl.innerHTML = `<li class="py-1 text-xs italic opacity-50" style="padding-left: ${padLeft + 16}px">Folder kosong</li>`; return; }
                
                data.items.forEach(item => {
                    const li = document.createElement('li'); li.className = 'tree-item select-none relative z-10';
                    const isChecked = selectedItems.has(item.path) ? 'checked' : '';
                    
                    if (item.type === 'folder') {
                        li.innerHTML = `
                            <div class="flex items-center py-[3px] hover:bg-black/10 cursor-pointer transition group" style="padding-left: ${padLeft}px"
                                 onclick="toggleFolder('${item.path}', this, event, ${depth + 1})"
                                 oncontextmenu="showContextMenu(event, '${item.path}', 'folder', this)">
                                <input type="checkbox" data-path="${item.path}" class="tree-checkbox mr-1.5 rounded bg-black/20 border-theme cursor-pointer flex-shrink-0" ${isChecked} onclick="toggleSelect('${item.path}', event)" title="Centang item ini" />
                                <i class="ti ti-chevron-right text-[14px] text-gray-400 w-[16px] text-center transition-transform duration-200 tree-chevron flex-shrink-0"></i>
                                <span class="text-[16px] text-yellow-600 flex mr-1.5 flex-shrink-0"><i class="ti ti-folder folder-icon"></i></span>
                                <span class="truncate text-[13.5px]">${item.name}</span>
                            </div>
                            <ul class="hidden folder-content" style="--line-x: ${lineX}px;"></ul>
                        `;
                    } else {
                        const info = getFileInfo(item.name);
                        li.innerHTML = `
                            <div class="flex items-center py-[3px] hover:bg-black/10 cursor-pointer transition border-l border-transparent hover:border-[var(--accent)] group" style="padding-left: ${padLeft}px"
                                 onclick="openFile('${item.path}', event)"
                                 oncontextmenu="showContextMenu(event, '${item.path}', 'file', this)">
                                <input type="checkbox" data-path="${item.path}" class="tree-checkbox mr-1.5 rounded bg-black/20 border-theme cursor-pointer flex-shrink-0" ${isChecked} onclick="toggleSelect('${item.path}', event)" title="Centang item ini" />
                                <span class="w-[16px] flex-shrink-0"></span> <span class="text-[16px] flex mr-1.5 flex-shrink-0 ${info.color}">${info.icon}</span>
                                <span class="truncate text-[13.5px]">${item.name}</span>
                            </div>
                        `;
                    }
                    containerEl.appendChild(li);
                });
            }).catch(() => containerEl.innerHTML = `<li class="py-1 text-xs text-red-400" style="padding-left: ${padLeft}px">Gagal koneksi</li>`);
        }

        function toggleFolder(path, el, event, nextDepth) {
            event.stopPropagation();
            const subUl = el.parentElement.querySelector('.folder-content');
            const chevron = el.querySelector('.tree-chevron');
            const folderIcon = el.querySelector('.folder-icon');

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
            if (tabs[filePath]) { if (!isBackground) switchTab(filePath); return; }

            const fileName = filePath.split('/').pop(); const info = getFileInfo(fileName);
            if (!isBackground) document.getElementById('status').innerHTML = `<i class="ti ti-loader-2 animate-spin inline-block mr-1"></i> Memuat: ${filePath}...`;

            if (info.type !== 'code') {
                tabs[filePath] = { type: info.type, url: getApiUrl('raw', 'path=' + encodeURIComponent(filePath)), saved: true, info: info };
                if (!isBackground) switchTab(filePath); else renderTabs(); saveSession(); return;
            }

            fetch(getApiUrl('read', 'path=' + encodeURIComponent(filePath))).then(r => r.json()).then(data => {
                if (data.error) { if (!isBackground) { alert(data.error); document.getElementById('status').innerHTML = '<i class="ti ti-alert-circle"></i> Gagal memuat file'; } } else {
                    let ext = fileName.split('.').pop().toLowerCase();
                    if (ext === 'bak') { const parts = fileName.split('.'); if (parts.length >= 3) { const origPart = parts[parts.length - 2]; ext = origPart.split('_')[0].toLowerCase(); } }
                    const langMap = { 'js': 'javascript', 'py': 'python', 'html': 'html', 'css': 'css', 'json': 'json', 'sql': 'sql', 'php': 'php', 'txt': 'plaintext', 'md': 'markdown' };
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
            if (activeTab && tabs[activeTab] && (tabs[activeTab].type === 'video' || tabs[activeTab].type === 'audio')) {
                if (tabs[activeTab].previewElement) { const activeMedia = tabs[activeTab].previewElement.querySelector('video, audio'); if (activeMedia) activeMedia.pause(); }
            }

            activeTab = filePath; const tabData = tabs[filePath];
            const editorWrap = document.getElementById('editor-wrapper'); const previewWrap = document.getElementById('preview-wrapper'); const emptyState = document.getElementById('empty-state'); const previewBox = document.getElementById('preview-content'); const saveBar = document.getElementById('save-action-bar'); const editorTools = document.getElementById('editor-tools');
            emptyState.classList.add('hidden');

            if (tabData.type === 'code') {
                previewWrap.classList.add('hidden'); editorWrap.classList.remove('hidden'); saveBar.classList.remove('hidden'); editorTools.classList.remove('hidden'); document.getElementById('editor-top-actions').classList.remove('hidden');
                if (editor) {
                    if (!tabData.model) {
                        tabData.model = monaco.editor.createModel(tabData.content, tabData.lang);
                        tabData.model.onDidChangeContent(() => { if (tabs[filePath] && tabs[filePath].saved) { tabs[filePath].saved = false; renderTabs(); } });
                    }
                    editor.setModel(tabData.model); editor.layout(); editor.focus();
                }
                document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Viewing: ${filePath}`;
            } else {
                editorWrap.classList.add('hidden'); previewWrap.classList.remove('hidden'); saveBar.classList.add('hidden'); editorTools.classList.add('hidden'); document.getElementById('editor-top-actions').classList.add('hidden');
                Array.from(previewBox.children).forEach(child => child.classList.add('hidden'));

                if (!tabData.previewElement) {
                    const container = document.createElement('div'); container.className = 'w-full h-full flex flex-col min-h-0 bg-[var(--bg-main)]'; 
                    const fileName = filePath.split('/').pop(); const fileInfo = tabData.info || getFileInfo(fileName); const directUrl = getDirectFileUrl(filePath);

                    fetch(getApiUrl('info', 'path=' + encodeURIComponent(filePath))).then(r => r.json()).then(infoData => {
                        const metadataPanel = `<div class="bg-black/30 border-b border-theme px-4 py-2.5 text-[10px] md:text-xs font-mono grid grid-cols-2 md:grid-cols-4 gap-3 text-gray-300 shadow-inner"><div class="truncate"><span class="text-gray-500 block text-[9px] md:text-[10px] uppercase font-bold">Full Path</span><span class="truncate block select-all font-bold text-yellow-500" title="${infoData.full_path}">${infoData.full_path}</span></div><div><span class="text-gray-500 block text-[9px] md:text-[10px] uppercase font-bold">File Size</span><span class="font-bold text-green-400">${infoData.size}</span></div><div class="truncate"><span class="text-gray-500 block text-[9px] md:text-[10px] uppercase font-bold">MIME-Type</span><span class="font-bold text-blue-400 truncate block" title="${infoData.mime}">${infoData.mime}</span></div><div><span class="text-gray-500 block text-[9px] md:text-[10px] uppercase font-bold">Image Size / Resolusi</span><span class="font-bold text-purple-400">${infoData.dimensions}</span></div></div>`;
                        const mediaTopBar = `<div class="w-full bg-[var(--bg-sidebar)] border-b border-theme px-2 md:px-4 py-2 flex flex-wrap items-center justify-between gap-3 text-xs flex-shrink-0 z-10"><div class="flex items-center gap-2 truncate max-w-sm"><span class="text-base flex ${fileInfo.color}">${fileInfo.icon}</span><span class="font-bold text-[var(--text-main)] truncate">${fileName}</span><span class="bg-black/20 text-gray-400 px-2 py-0.5 rounded text-[9px] md:text-[10px] uppercase font-mono border border-theme">${tabData.type}</span></div><div class="flex items-center gap-2 flex-1 justify-end min-w-[200px]"><div class="relative flex-1 max-w-md flex items-center hidden md:flex"><i class="ti ti-link absolute left-2 text-gray-500"></i><input type="text" readonly value="${directUrl}" class="w-full bg-black/20 border border-theme rounded pl-7 pr-2 py-1 text-[11px] text-gray-300 font-mono select-all focus:outline-none focus:border-[var(--accent)]" onclick="this.select()" title="Alamat URL File Langsung" /></div><button onclick="navigator.clipboard.writeText('${directUrl}'); alert('Alamat URL berhasil disalin!');" class="bg-black/20 hover:bg-black/30 text-gray-300 border border-theme px-2.5 py-1 rounded transition flex items-center gap-1 flex-shrink-0" title="Salin Alamat URL"><i class="ti ti-copy text-sm"></i> <span class="hidden md:inline">Salin</span></button><a href="${directUrl}" target="_blank" class="bg-[var(--accent)] hover:opacity-90 text-white px-3 py-1 rounded transition flex items-center gap-1.5 font-medium shadow flex-shrink-0" title="Buka File Langsung di Tab Baru"><i class="ti ti-external-link text-sm"></i> <span class="hidden md:inline">Buka</span></a></div></div>`;

                        if (tabData.type === 'image') {
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full flex items-center justify-center p-4 md:p-6 overflow-auto bg-black/10"><img src="${directUrl}" class="max-w-full max-h-full object-contain drop-shadow-2xl rounded p-2 bg-[var(--bg-sidebar)] border border-theme" /></div>`;
                        } else if (tabData.type === 'video') {
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full flex items-center justify-center p-4 md:p-6 overflow-auto bg-black/20"><video src="${directUrl}" controls autoplay class="max-w-full max-h-full drop-shadow-2xl rounded bg-black outline-none border border-theme"></video></div>`;
                        } else if (tabData.type === 'audio') {
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full flex items-center justify-center p-4 md:p-6 overflow-auto bg-black/10"><div class="bg-[var(--bg-sidebar)] p-6 md:p-10 rounded-xl shadow-2xl flex flex-col items-center gap-6 border border-theme text-[var(--accent)] max-w-md w-full"><i class="ti ti-music text-7xl animate-bounce"></i><div class="text-center"><div class="font-bold text-[var(--text-main)] mb-1">${fileName}</div><div class="text-xs text-gray-500">Audio Player</div></div><audio src="${directUrl}" controls autoplay class="w-full outline-none"></audio></div></div>`;
                        } else if (tabData.type === 'pdf') {
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full h-full min-h-0"><iframe src="${directUrl}" class="w-full h-full border-0 bg-white"></iframe></div>`;
                        } else if (['ppt', 'word', 'excel'].includes(tabData.type)) {
                            const fullDownloadUrl = window.location.origin + window.location.pathname + '?ajax=1&action=download&path=' + encodeURIComponent(filePath);
                            const msViewerUrl = `https://view.officeapps.live.com/op/embed.aspx?src=${encodeURIComponent(fullDownloadUrl)}`;
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full flex items-center justify-center p-4 md:p-6 overflow-auto bg-black/5"><div class="text-center bg-[var(--bg-sidebar)] p-6 md:p-8 rounded-xl border border-theme max-w-md shadow-2xl"><div class="text-6xl md:text-8xl mb-4 flex justify-center ${fileInfo.color}">${fileInfo.icon}</div><h3 class="text-base md:text-lg font-bold text-[var(--text-main)] mb-1 truncate px-4" title="${fileName}">${fileName}</h3><p class="text-[10px] md:text-xs text-gray-400 mb-6 font-medium">${fileInfo.label}</p><div class="bg-black/20 p-3.5 rounded-lg text-xs mb-6 border border-theme text-gray-400 leading-relaxed text-left"><span class="flex items-center gap-1.5 font-bold ${fileInfo.color} mb-1"><i class="ti ti-file-check text-base"></i> Dokumen Microsoft Office</span>Untuk menjamin tata letak, presentasi, dan pemformatan dokumen tetap utuh, silakan download atau buka menggunakan aplikasi Office.</div><div class="flex flex-col gap-2.5"><a href="${directUrl}" target="_blank" class="bg-[var(--accent)] text-white px-6 py-2.5 rounded-lg text-sm font-medium hover:opacity-90 transition inline-flex items-center justify-center gap-2 shadow-lg"><i class="ti ti-external-link text-lg"></i> Buka Langsung</a><button onclick="window.open('${msViewerUrl}', '_blank')" class="bg-black/20 hover:bg-black/30 text-gray-300 border border-theme px-6 py-2 rounded-lg text-xs transition inline-flex items-center justify-center gap-2"><i class="ti ti-cloud-share"></i> Coba Buka di Online Office Viewer</button></div></div></div>`;
                        } else {
                            container.innerHTML = mediaTopBar + metadataPanel + `<div class="flex-1 w-full flex items-center justify-center p-4 md:p-6 overflow-auto bg-black/5"><div class="text-center bg-[var(--bg-sidebar)] p-6 md:p-8 rounded-xl border border-theme max-w-md shadow-2xl"><div class="text-6xl md:text-7xl mb-4 flex justify-center ${fileInfo.color}">${fileInfo.icon}</div><h3 class="text-base md:text-lg font-bold text-[var(--text-main)] mb-1 truncate px-4" title="${fileName}">${fileName}</h3><p class="text-[10px] md:text-xs text-gray-400 mb-6 font-medium">${fileInfo.label || 'Format File Biner / Non-Programming'}</p><div class="bg-black/20 p-3.5 rounded-lg text-xs mb-6 border border-theme text-gray-400 leading-relaxed text-left"><span class="flex items-center gap-1.5 font-bold text-yellow-500 mb-1"><i class="ti ti-alert-triangle text-base"></i> File Biner / Non-Kode</span>File dengan format ini tidak dapat dibaca atau diedit secara langsung di dalam teks editor Monaco karena berisi karakter biner atau format khusus sistem.</div><a href="${directUrl}" target="_blank" class="bg-[var(--accent)] text-white px-6 py-2.5 rounded-lg text-sm font-medium hover:opacity-90 transition inline-flex items-center gap-2 shadow-lg justify-center"><i class="ti ti-external-link text-lg"></i> Buka & Akses Langsung</a></div></div>`;
                        }
                    });
                    tabData.previewElement = container; previewBox.appendChild(container);
                } else { tabData.previewElement.classList.remove('hidden'); }
                document.getElementById('status').innerHTML = `<i class="ti ti-eye"></i> Previewing: ${filePath}`;
            }
            renderTabs(); saveSession(); 
        }

        async function closeTab(filePath, event, force = false) {
            if (event) event.stopPropagation();
            if (!force && !tabs[filePath].saved && tabs[filePath].type === 'code') {
                const confirmed = await showConfirm('Perubahan Belum Disimpan', `File <span class="font-mono text-yellow-500 font-bold">${filePath.split('/').pop()}</span> memiliki perubahan yang belum disimpan.<br>Yakin ingin menutupnya?`, false, 'Tutup Tanpa Simpan');
                if (!confirmed) return;
            }
            if (tabs[filePath].type === 'code' && tabs[filePath].model) tabs[filePath].model.dispose();
            if (tabs[filePath].previewElement) tabs[filePath].previewElement.remove();
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
                const bgClass = isActive ? 'bg-[var(--bg-main)] text-[var(--text-main)] border-b-2 border-[var(--accent)]' : 'bg-transparent text-[var(--text-main)] opacity-70 hover:opacity-100 hover:bg-black/5 border-b-2 border-transparent';
                const unsavedDot = data.saved ? '' : '<span class="unsaved-dot" title="Belum disimpan (Ctrl+S)"></span>';
                if (!data.saved) hasUnsaved = true;
                const fileName = filePath.split('/').pop(); const info = getFileInfo(fileName);
                const tabEl = document.createElement('div');
                tabEl.className = `flex items-center justify-between gap-2 px-3 py-1.5 text-xs cursor-pointer border-r border-theme min-w-[120px] max-w-[200px] group transition-colors flex-shrink-0 ${bgClass}`;
                tabEl.title = filePath; tabEl.onclick = () => switchTab(filePath);
                tabEl.innerHTML = `<div class="flex items-center gap-1.5 truncate"><span class="text-base flex ${info.color}">${info.icon}</span><span class="truncate font-medium">${fileName}</span>${unsavedDot}</div><span onclick="closeTab('${filePath}', event)" class="hover:bg-black/20 hover:text-red-400 rounded p-0.5 ml-1 transition flex items-center justify-center"><i class="ti ti-x text-[14px]"></i></span>`;
                tabBar.appendChild(tabEl);
            }
            const btnTopSave = document.getElementById('btn-top-save'); const topSaveText = document.getElementById('top-save-text');
            if (btnTopSave && topSaveText) {
                if (hasUnsaved && activeTab && !tabs[activeTab].saved) {
                    btnTopSave.className = 'bg-amber-500 hover:bg-amber-600 text-black font-bold px-3 py-1 rounded text-xs flex items-center gap-1.5 shadow-lg transition active:scale-95 animate-pulse';
                    topSaveText.innerText = 'Simpan ●';
                } else {
                    btnTopSave.className = 'bg-[var(--accent)] hover:opacity-85 text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition active:scale-95';
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
            if(btnSave && topSaveText) { btnSave.disabled = true; btnSave.className = 'bg-gray-600 opacity-50 cursor-not-allowed text-white px-3 py-1 rounded text-xs font-medium flex items-center gap-1.5 shadow transition'; topSaveText.innerText = 'Menyimpan...'; }

            fetch(getApiUrl('save'), { method: 'POST', headers: getHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ path: filePath, content: content }) 
            }).then(r => r.json()).then(res => {
                if (res.status === 'ok') {
                    tabs[filePath].saved = true; renderTabs();
                    document.getElementById('status').innerHTML = `<i class="ti ti-check text-green-400"></i> Berhasil disimpan: ${filePath}`;
                    if(btnSave && topSaveText) { btnSave.className = 'bg-green-600 text-white font-bold px-3 py-1 rounded text-xs flex items-center gap-1.5 shadow transition'; topSaveText.innerText = 'Tersimpan!'; }
                    setTimeout(() => { 
                        if (activeTab === filePath) document.getElementById('status').innerHTML = `<i class="ti ti-edit"></i> Editing: ${filePath}`; 
                        if(btnSave) btnSave.disabled = false; renderTabs(); 
                    }, 1500);
                } else { alert(res.error || 'Gagal menyimpan file!'); if(btnSave) btnSave.disabled = false; renderTabs(); }
            }).catch(() => { alert('Terjadi kesalahan koneksi saat menyimpan.'); if(btnSave) btnSave.disabled = false; renderTabs(); });
        }

        window.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveCurrentFile(); } });
    </script>
<?php endif; ?>
</body>
</html>
