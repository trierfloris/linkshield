/**
 * Add v8.7.0 i18n keys for Emergency Mode and Universal Non-ASCII Flag
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

const newKeys = {
    "universalNonAsciiDetected": {
        "en": { "message": "Non-standard characters detected in URL", "description": "Warning for URLs containing non-ASCII characters" },
        "nl": { "message": "Niet-standaard tekens gedetecteerd in URL", "description": "" },
        "de": { "message": "Nicht-Standard-Zeichen in URL erkannt", "description": "" },
        "fr": { "message": "Caractères non standard détectés dans l'URL", "description": "" },
        "es": { "message": "Caracteres no estándar detectados en la URL", "description": "" },
        "it": { "message": "Caratteri non standard rilevati nell'URL", "description": "" },
        "pt": { "message": "Caracteres não padrão detectados na URL", "description": "" },
        "pt_BR": { "message": "Caracteres não padrão detectados na URL", "description": "" },
        "ru": { "message": "Обнаружены нестандартные символы в URL", "description": "" },
        "ja": { "message": "URLに非標準文字が検出されました", "description": "" },
        "ko": { "message": "URL에서 비표준 문자가 감지되었습니다", "description": "" },
        "zh": { "message": "URL中检测到非标准字符", "description": "" },
        "ar": { "message": "تم اكتشاف أحرف غير قياسية في الرابط", "description": "" },
        "hi": { "message": "URL में गैर-मानक वर्ण पाए गए", "description": "" },
        "tr": { "message": "URL'de standart dışı karakterler algılandı", "description": "" },
        "pl": { "message": "Wykryto niestandardowe znaki w URL", "description": "" },
        "uk": { "message": "Виявлено нестандартні символи в URL", "description": "" },
        "cs": { "message": "V URL byly zjištěny nestandardní znaky", "description": "" },
        "ro": { "message": "Caractere non-standard detectate în URL", "description": "" },
        "hu": { "message": "Nem szabványos karakterek észlelve az URL-ben", "description": "" },
        "el": { "message": "Εντοπίστηκαν μη τυπικοί χαρακτήρες στο URL", "description": "" },
        "th": { "message": "ตรวจพบอักขระที่ไม่เป็นมาตรฐานใน URL", "description": "" },
        "vi": { "message": "Phát hiện ký tự không chuẩn trong URL", "description": "" },
        "id": { "message": "Karakter non-standar terdeteksi di URL", "description": "" }
    },
    "emergencyModeTitle": {
        "en": { "message": "Emergency Protection Mode", "description": "Title for emergency mode notification" },
        "nl": { "message": "Noodmodus Bescherming", "description": "" },
        "de": { "message": "Notfall-Schutzmodus", "description": "" },
        "fr": { "message": "Mode de protection d'urgence", "description": "" },
        "es": { "message": "Modo de protección de emergencia", "description": "" },
        "it": { "message": "Modalità protezione di emergenza", "description": "" },
        "pt": { "message": "Modo de proteção de emergência", "description": "" },
        "pt_BR": { "message": "Modo de proteção de emergência", "description": "" },
        "ru": { "message": "Аварийный режим защиты", "description": "" },
        "ja": { "message": "緊急保護モード", "description": "" },
        "ko": { "message": "긴급 보호 모드", "description": "" },
        "zh": { "message": "紧急保护模式", "description": "" },
        "ar": { "message": "وضع الحماية الطارئة", "description": "" },
        "hi": { "message": "आपातकालीन सुरक्षा मोड", "description": "" },
        "tr": { "message": "Acil koruma modu", "description": "" },
        "pl": { "message": "Tryb ochrony awaryjnej", "description": "" },
        "uk": { "message": "Аварійний режим захисту", "description": "" },
        "cs": { "message": "Nouzový režim ochrany", "description": "" },
        "ro": { "message": "Mod de protecție de urgență", "description": "" },
        "hu": { "message": "Vészhelyzeti védelmi mód", "description": "" },
        "el": { "message": "Λειτουργία έκτακτης προστασίας", "description": "" },
        "th": { "message": "โหมดการป้องกันฉุกเฉิน", "description": "" },
        "vi": { "message": "Chế độ bảo vệ khẩn cấp", "description": "" },
        "id": { "message": "Mode perlindungan darurat", "description": "" }
    },
    "emergencyModeMessage": {
        "en": { "message": "LinkShield is running in Emergency Mode. Protection remains fully active. Please check your internet connection.", "description": "Message for emergency mode notification" },
        "nl": { "message": "LinkShield draait in noodmodus. Bescherming blijft volledig actief. Controleer uw internetverbinding.", "description": "" },
        "de": { "message": "LinkShield läuft im Notfallmodus. Der Schutz bleibt vollständig aktiv. Bitte überprüfen Sie Ihre Internetverbindung.", "description": "" },
        "fr": { "message": "LinkShield fonctionne en mode d'urgence. La protection reste entièrement active. Veuillez vérifier votre connexion internet.", "description": "" },
        "es": { "message": "LinkShield está funcionando en modo de emergencia. La protección permanece completamente activa. Verifique su conexión a internet.", "description": "" },
        "it": { "message": "LinkShield è in modalità di emergenza. La protezione rimane completamente attiva. Controlla la tua connessione internet.", "description": "" },
        "pt": { "message": "LinkShield está em modo de emergência. A proteção permanece totalmente ativa. Verifique sua conexão com a internet.", "description": "" },
        "pt_BR": { "message": "LinkShield está em modo de emergência. A proteção permanece totalmente ativa. Verifique sua conexão com a internet.", "description": "" },
        "ru": { "message": "LinkShield работает в аварийном режиме. Защита полностью активна. Пожалуйста, проверьте подключение к интернету.", "description": "" },
        "ja": { "message": "LinkShieldは緊急モードで動作しています。保護は完全に有効です。インターネット接続を確認してください。", "description": "" },
        "ko": { "message": "LinkShield가 긴급 모드로 실행 중입니다. 보호 기능은 완전히 활성화되어 있습니다. 인터넷 연결을 확인하세요.", "description": "" },
        "zh": { "message": "LinkShield正在紧急模式下运行。保护功能完全激活。请检查您的网络连接。", "description": "" },
        "ar": { "message": "يعمل LinkShield في وضع الطوارئ. تظل الحماية نشطة بالكامل. يرجى التحقق من اتصالك بالإنترنت.", "description": "" },
        "hi": { "message": "LinkShield आपातकालीन मोड में चल रहा है। सुरक्षा पूरी तरह सक्रिय है। कृपया अपना इंटरनेट कनेक्शन जांचें।", "description": "" },
        "tr": { "message": "LinkShield acil modda çalışıyor. Koruma tamamen aktif kalıyor. Lütfen internet bağlantınızı kontrol edin.", "description": "" },
        "pl": { "message": "LinkShield działa w trybie awaryjnym. Ochrona pozostaje w pełni aktywna. Sprawdź połączenie internetowe.", "description": "" },
        "uk": { "message": "LinkShield працює в аварійному режимі. Захист залишається повністю активним. Перевірте підключення до інтернету.", "description": "" },
        "cs": { "message": "LinkShield běží v nouzovém režimu. Ochrana zůstává plně aktivní. Zkontrolujte připojení k internetu.", "description": "" },
        "ro": { "message": "LinkShield rulează în modul de urgență. Protecția rămâne complet activă. Verificați conexiunea la internet.", "description": "" },
        "hu": { "message": "A LinkShield vészhelyzeti módban fut. A védelem teljesen aktív marad. Ellenőrizze az internetkapcsolatot.", "description": "" },
        "el": { "message": "Το LinkShield λειτουργεί σε λειτουργία έκτακτης ανάγκης. Η προστασία παραμένει πλήρως ενεργή. Ελέγξτε τη σύνδεσή σας στο διαδίκτυο.", "description": "" },
        "th": { "message": "LinkShield ทำงานในโหมดฉุกเฉิน การป้องกันยังคงใช้งานได้เต็มที่ กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ต", "description": "" },
        "vi": { "message": "LinkShield đang chạy ở chế độ khẩn cấp. Bảo vệ vẫn hoàn toàn hoạt động. Vui lòng kiểm tra kết nối internet.", "description": "" },
        "id": { "message": "LinkShield berjalan dalam mode darurat. Perlindungan tetap aktif sepenuhnya. Silakan periksa koneksi internet Anda.", "description": "" }
    }
};

// Process each locale
const locales = fs.readdirSync(localesDir).filter(f =>
    fs.statSync(path.join(localesDir, f)).isDirectory()
);

let updated = 0;
let errors = 0;

locales.forEach(locale => {
    const messagesPath = path.join(localesDir, locale, 'messages.json');

    if (!fs.existsSync(messagesPath)) {
        console.log(`SKIP: ${locale} - no messages.json`);
        return;
    }

    try {
        let content = fs.readFileSync(messagesPath, 'utf8');
        let messages = JSON.parse(content);
        let changed = false;

        // Add each new key
        for (const [key, translations] of Object.entries(newKeys)) {
            if (!messages[key]) {
                const translation = translations[locale] || translations['en'];
                messages[key] = translation;
                changed = true;
            }
        }

        if (changed) {
            // Write back with proper formatting
            const output = JSON.stringify(messages, null, 2);
            fs.writeFileSync(messagesPath, output, 'utf8');
            updated++;
            console.log(`OK: ${locale}`);
        } else {
            console.log(`SKIP: ${locale} - keys already exist`);
        }
    } catch (e) {
        console.error(`ERROR: ${locale} - ${e.message}`);
        errors++;
    }
});

console.log(`\nDONE: Updated ${updated} locales, ${errors} errors`);
