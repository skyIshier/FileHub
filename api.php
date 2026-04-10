<?php
// 禁用错误输出，保证 JSON 纯净
error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

define('ROOT_DIR', __DIR__);

// 加载管理员配置
function loadAdmins() {
    $configFile = ROOT_DIR . '/admins.json';
    if (!file_exists($configFile)) {
        return ['admins' => []];
    }
    $content = file_get_contents($configFile);
    return json_decode($content, true) ?: ['admins' => []];
}

// 验证管理员并返回权限
function authenticateAdmin() {
    $user = $_POST['username'] ?? $_GET['username'] ?? $_SERVER['HTTP_X_AUTH_USER'] ?? null;
    if (!$user) return false;
    
    $config = loadAdmins();
    foreach ($config['admins'] as $admin) {
        if ($admin['username'] === $user) {
            // 验证密码（仅登录接口会传密码）
            $pwd = $_POST['password'] ?? $_GET['password'] ?? null;
            if ($pwd && $admin['password'] !== $pwd) {
                return false;
            }
            return [
                'username' => $admin['username'],
                'permissions' => $admin['permissions']
            ];
        }
    }
    return false;
}

// 检查权限
function hasPermission($action) {
    $auth = authenticateAdmin();
    if (!$auth) return false;
    $perms = $auth['permissions'];
    
    $actionToPerm = [
        'upload' => 'upload',
        'delete' => 'delete',
        'mkdir' => 'mkdir'
    ];
    
    $permName = $actionToPerm[$action] ?? null;
    if ($permName && isset($perms[$permName])) {
        return $perms[$permName] === true;
    }
    return false;
}

function error($msg, $code = 403) {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $msg]);
    exit;
}

// 递归扫描目录
function scanRecursive($basePath, $relativePath = '') {
    $fullPath = $basePath . ($relativePath ? '/' . $relativePath : '');
    if (!is_dir($fullPath)) return [];
    
    $items = [];
    $entries = scandir($fullPath);
    $exclude = ['.', '..', 'api.php', 'index.html', 'admins.json'];
    
    foreach ($entries as $entry) {
        if (in_array($entry, $exclude)) continue;
        $rel = $relativePath ? $relativePath . '/' . $entry : $entry;
        $full = $fullPath . '/' . $entry;
        
        if (is_dir($full)) {
            $items[] = [
                'name' => $entry,
                'type' => 'dir',
                'path' => $rel,
                'children' => scanRecursive($basePath, $rel)
            ];
        } else {
            $items[] = [
                'name' => $entry,
                'type' => 'file',
                'path' => $rel,
                'size' => filesize($full),
                'modified' => date('Y-m-d H:i:s', filemtime($full))
            ];
        }
    }
    
    usort($items, function($a, $b) {
        if ($a['type'] === $b['type']) return strcasecmp($a['name'], $b['name']);
        return ($a['type'] === 'dir') ? -1 : 1;
    });
    return $items;
}

$action = $_GET['action'] ?? '';

// 登录接口
if ($action === 'login') {
    $input = json_decode(file_get_contents('php://input'), true);
    $user = $input['username'] ?? '';
    $pwd = $input['password'] ?? '';
    
    $config = loadAdmins();
    $authenticated = false;
    $userData = null;
    foreach ($config['admins'] as $admin) {
        if ($admin['username'] === $user && $admin['password'] === $pwd) {
            $authenticated = true;
            $userData = $admin;
            break;
        }
    }
    
    if ($authenticated) {
        echo json_encode([
            'success' => true,
            'token' => md5($pwd),
            'permissions' => $userData['permissions']
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => '用户名或密码错误']);
    }
    exit;
}

// 获取文件列表（无需登录）
if ($action === 'list') {
    $tree = scanRecursive(ROOT_DIR, '');
    echo json_encode(['success' => true, 'tree' => ['name' => 'root', 'type' => 'dir', 'path' => '', 'children' => $tree]]);
    exit;
}

// 下载文件（无需登录）
if ($action === 'download') {
    $path = $_GET['path'] ?? '';
    if (empty($path)) error('缺少文件路径');
    $full = ROOT_DIR . '/' . ltrim($path, '/');
    if (!is_file($full)) error('文件不存在', 404);
    $fileName = basename($full);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $fileName . '"');
    header('Content-Length: ' . filesize($full));
    readfile($full);
    exit;
}

// 以下操作需要管理员登录
$auth = authenticateAdmin();
if (!$auth) {
    error('请先登录管理员账号');
}

// 上传文件
if ($action === 'upload') {
    if (!hasPermission('upload')) {
        error('您的账号没有上传文件的权限');
    }
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        error('上传失败');
    }
    $targetDir = $_POST['target_dir'] ?? '';
    $targetDir = trim($targetDir, '/');
    $uploadPath = ROOT_DIR . ($targetDir ? '/' . $targetDir : '');
    if (!is_dir($uploadPath)) {
        mkdir($uploadPath, 0777, true);
    }
    $fileName = basename($_FILES['file']['name']);
    $dest = $uploadPath . '/' . $fileName;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo json_encode(['success' => true]);
    } else {
        error('移动文件失败');
    }
    exit;
}

// 删除
if ($action === 'delete') {
    if (!hasPermission('delete')) {
        error('您的账号没有删除文件的权限');
    }
    $path = $_POST['path'] ?? '';
    if (empty($path)) error('路径无效');
    $full = ROOT_DIR . '/' . ltrim($path, '/');
    if (!file_exists($full)) error('文件不存在');
    
    function delTree($dir) {
        if (!is_dir($dir)) return unlink($dir);
        foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
            delTree($dir . '/' . $f);
        }
        return rmdir($dir);
    }
    
    if (delTree($full)) {
        echo json_encode(['success' => true]);
    } else {
        error('删除失败');
    }
    exit;
}

// 新建文件夹
if ($action === 'mkdir') {
    if (!hasPermission('mkdir')) {
        error('您的账号没有创建文件夹的权限');
    }
    $parent = $_POST['parent'] ?? '';
    $name = $_POST['name'] ?? '';
    if (empty($name)) error('文件夹名不能为空');
    $parentPath = ROOT_DIR . ($parent ? '/' . ltrim($parent, '/') : '');
    $newDir = $parentPath . '/' . $name;
    if (file_exists($newDir)) error('已存在同名文件或文件夹');
    if (mkdir($newDir, 0777, true)) {
        echo json_encode(['success' => true]);
    } else {
        error('创建失败');
    }
    exit;
}

error('未知操作');
?>