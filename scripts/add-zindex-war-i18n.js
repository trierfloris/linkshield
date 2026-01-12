/**
 * Add Z-Index War 2.0 i18n keys to all locales
 */

const fs = require('fs');
const path = require('path');

const LOCALES_DIR = path.join(__dirname, '..', '_locales');

const translations = {
  pointerEventsNoneHighZIndex: {
    ar: "تم اكتشاف طبقة غير مرئية بأقصى مؤشر z (خطر حرج). هذه الصفحة تحاول اعتراض نقراتك.",
    cs: "Detekována neviditelná vrstva s maximálním z-indexem (kritické riziko). Tato stránka se pokouší zachytit vaše kliknutí.",
    de: "Unsichtbare Überlagerung mit maximalem Z-Index erkannt (kritisches Risiko). Diese Seite versucht, Ihre Klicks abzufangen.",
    el: "Εντοπίστηκε αόρατη επικάλυψη με μέγιστο z-index (κρίσιμος κίνδυνος). Αυτή η σελίδα προσπαθεί να υποκλέψει τα κλικ σας.",
    en: "Invisible overlay with maximum z-index detected (critical risk). This page is attempting to intercept your clicks.",
    es: "Superposición invisible con z-index máximo detectada (riesgo crítico). Esta página está intentando interceptar sus clics.",
    fr: "Superposition invisible avec z-index maximum détectée (risque critique). Cette page tente d'intercepter vos clics.",
    hi: "अधिकतम z-इंडेक्स वाली अदृश्य परत का पता चला (गंभीर जोखिम)। यह पृष्ठ आपके क्लिक को रोकने का प्रयास कर रहा है।",
    hu: "Láthatatlan réteg maximális z-indexszel észlelve (kritikus kockázat). Ez az oldal megpróbálja elfogni a kattintásait.",
    id: "Lapisan tak terlihat dengan z-index maksimum terdeteksi (risiko kritis). Halaman ini mencoba mencegat klik Anda.",
    it: "Rilevata sovrapposizione invisibile con z-index massimo (rischio critico). Questa pagina sta tentando di intercettare i tuoi clic.",
    ja: "最大z-indexの不可視オーバーレイが検出されました（重大なリスク）。このページはクリックを傍受しようとしています。",
    ko: "최대 z-index를 가진 보이지 않는 오버레이 감지 (심각한 위험). 이 페이지가 클릭을 가로채려고 합니다.",
    nl: "Onzichtbare overlay met maximale z-index gedetecteerd (kritiek risico). Deze pagina probeert uw klikken te onderscheppen.",
    pl: "Wykryto niewidoczną nakładkę z maksymalnym z-index (krytyczne ryzyko). Ta strona próbuje przechwycić Twoje kliknięcia.",
    pt: "Sobreposição invisível com z-index máximo detectada (risco crítico). Esta página está tentando interceptar seus cliques.",
    pt_BR: "Sobreposição invisível com z-index máximo detectada (risco crítico). Esta página está tentando interceptar seus cliques.",
    ro: "Suprapunere invizibilă cu z-index maxim detectată (risc critic). Această pagină încearcă să vă intercepteze clicurile.",
    ru: "Обнаружен невидимый слой с максимальным z-index (критический риск). Эта страница пытается перехватить ваши клики.",
    th: "ตรวจพบเลเยอร์ที่มองไม่เห็นที่มี z-index สูงสุด (ความเสี่ยงร้ายแรง) หน้านี้กำลังพยายามดักจับการคลิกของคุณ",
    tr: "Maksimum z-index ile görünmez kaplama algılandı (kritik risk). Bu sayfa tıklamalarınızı yakalamaya çalışıyor.",
    uk: "Виявлено невидимий шар з максимальним z-index (критичний ризик). Ця сторінка намагається перехопити ваші кліки.",
    vi: "Phát hiện lớp phủ vô hình với z-index tối đa (rủi ro nghiêm trọng). Trang này đang cố gắng chặn các nhấp chuột của bạn.",
    zh: "检测到具有最大z-index的不可见覆盖层（严重风险）。此页面正在尝试拦截您的点击。"
  },
  intMaxZIndexOverlay: {
    ar: "تم اكتشاف طبقة مشبوهة تستخدم أقصى مؤشر z (خطر حرج). هذه تقنية شائعة لاختطاف النقرات.",
    cs: "Detekována podezřelá vrstva používající maximální z-index (kritické riziko). Jedná se o běžnou techniku únosu kliknutí.",
    de: "Verdächtige Überlagerung mit maximalem Z-Index erkannt (kritisches Risiko). Dies ist eine häufige Click-Hijacking-Technik.",
    el: "Εντοπίστηκε ύποπτη επικάλυψη με μέγιστο z-index (κρίσιμος κίνδυνος). Αυτή είναι μια κοινή τεχνική υποκλοπής κλικ.",
    en: "Suspicious overlay using maximum z-index detected (critical risk). This is a common click hijacking technique.",
    es: "Superposición sospechosa usando z-index máximo detectada (riesgo crítico). Esta es una técnica común de secuestro de clics.",
    fr: "Superposition suspecte utilisant z-index maximum détectée (risque critique). C'est une technique courante de détournement de clic.",
    hi: "अधिकतम z-इंडेक्स का उपयोग करने वाली संदिग्ध परत का पता चला (गंभीर जोखिम)। यह क्लिक अपहरण की एक सामान्य तकनीक है।",
    hu: "Gyanús réteg maximális z-indexszel észlelve (kritikus kockázat). Ez egy gyakori kattintás-eltérítési technika.",
    id: "Lapisan mencurigakan menggunakan z-index maksimum terdeteksi (risiko kritis). Ini adalah teknik pembajakan klik yang umum.",
    it: "Rilevata sovrapposizione sospetta con z-index massimo (rischio critico). Questa è una tecnica comune di click hijacking.",
    ja: "最大z-indexを使用した不審なオーバーレイが検出されました（重大なリスク）。これは一般的なクリックハイジャック手法です。",
    ko: "최대 z-index를 사용하는 의심스러운 오버레이 감지 (심각한 위험). 이것은 일반적인 클릭 하이재킹 기술입니다.",
    nl: "Verdachte overlay met maximale z-index gedetecteerd (kritiek risico). Dit is een veelgebruikte click hijacking techniek.",
    pl: "Wykryto podejrzaną nakładkę z maksymalnym z-index (krytyczne ryzyko). Jest to powszechna technika przechwytywania kliknięć.",
    pt: "Sobreposição suspeita usando z-index máximo detectada (risco crítico). Esta é uma técnica comum de sequestro de clique.",
    pt_BR: "Sobreposição suspeita usando z-index máximo detectada (risco crítico). Esta é uma técnica comum de sequestro de clique.",
    ro: "Suprapunere suspectă folosind z-index maxim detectată (risc critic). Aceasta este o tehnică comună de deturnare a clicurilor.",
    ru: "Обнаружен подозрительный слой с максимальным z-index (критический риск). Это распространённая техника перехвата кликов.",
    th: "ตรวจพบเลเยอร์ที่น่าสงสัยใช้ z-index สูงสุด (ความเสี่ยงร้ายแรง) นี่เป็นเทคนิคการจี้คลิกที่พบบ่อย",
    tr: "Maksimum z-index kullanan şüpheli kaplama algılandı (kritik risk). Bu yaygın bir tıklama kaçırma tekniğidir.",
    uk: "Виявлено підозрілий шар з максимальним z-index (критичний ризик). Це поширена техніка перехоплення кліків.",
    vi: "Phát hiện lớp phủ đáng ngờ sử dụng z-index tối đa (rủi ro nghiêm trọng). Đây là kỹ thuật chiếm đoạt nhấp chuột phổ biến.",
    zh: "检测到使用最大z-index的可疑覆盖层（严重风险）。这是一种常见的点击劫持技术。"
  },
  fullscreenPointerEventsNone: {
    ar: "تم اكتشاف طبقة غير مرئية بملء الشاشة (خطر حرج). قد تحاول هذه الصفحة التقاط تفاعلاتك.",
    cs: "Detekována celoobrazovková neviditelná vrstva (kritické riziko). Tato stránka se možná pokouší zachytit vaše interakce.",
    de: "Bildschirmfüllende unsichtbare Überlagerung erkannt (kritisches Risiko). Diese Seite versucht möglicherweise, Ihre Interaktionen abzufangen.",
    el: "Εντοπίστηκε αόρατη επικάλυψη πλήρους οθόνης (κρίσιμος κίνδυνος). Αυτή η σελίδα ενδέχεται να προσπαθεί να καταγράψει τις αλληλεπιδράσεις σας.",
    en: "Full-screen invisible overlay detected (critical risk). This page may be attempting to capture your interactions.",
    es: "Superposición invisible de pantalla completa detectada (riesgo crítico). Esta página puede estar intentando capturar sus interacciones.",
    fr: "Superposition invisible plein écran détectée (risque critique). Cette page pourrait tenter de capturer vos interactions.",
    hi: "पूर्ण स्क्रीन अदृश्य परत का पता चला (गंभीर जोखिम)। यह पृष्ठ आपकी बातचीत को कैप्चर करने का प्रयास कर सकता है।",
    hu: "Teljes képernyős láthatatlan réteg észlelve (kritikus kockázat). Ez az oldal megpróbálhatja rögzíteni az interakcióit.",
    id: "Lapisan tak terlihat layar penuh terdeteksi (risiko kritis). Halaman ini mungkin mencoba menangkap interaksi Anda.",
    it: "Rilevata sovrapposizione invisibile a schermo intero (rischio critico). Questa pagina potrebbe tentare di catturare le tue interazioni.",
    ja: "フルスクリーンの不可視オーバーレイが検出されました（重大なリスク）。このページはあなたの操作をキャプチャしようとしている可能性があります。",
    ko: "전체 화면 보이지 않는 오버레이 감지 (심각한 위험). 이 페이지가 상호 작용을 캡처하려고 할 수 있습니다.",
    nl: "Volledig scherm onzichtbare overlay gedetecteerd (kritiek risico). Deze pagina probeert mogelijk uw interacties vast te leggen.",
    pl: "Wykryto niewidoczną nakładkę pełnoekranową (krytyczne ryzyko). Ta strona może próbować przechwycić Twoje interakcje.",
    pt: "Sobreposição invisível em tela cheia detectada (risco crítico). Esta página pode estar tentando capturar suas interações.",
    pt_BR: "Sobreposição invisível em tela cheia detectada (risco crítico). Esta página pode estar tentando capturar suas interações.",
    ro: "Suprapunere invizibilă pe tot ecranul detectată (risc critic). Această pagină ar putea încerca să vă captureze interacțiunile.",
    ru: "Обнаружен полноэкранный невидимый слой (критический риск). Эта страница может пытаться перехватить ваши действия.",
    th: "ตรวจพบเลเยอร์ที่มองไม่เห็นเต็มหน้าจอ (ความเสี่ยงร้ายแรง) หน้านี้อาจพยายามจับภาพการโต้ตอบของคุณ",
    tr: "Tam ekran görünmez kaplama algılandı (kritik risk). Bu sayfa etkileşimlerinizi yakalamaya çalışıyor olabilir.",
    uk: "Виявлено повноекранний невидимий шар (критичний ризик). Ця сторінка може намагатися захопити ваші дії.",
    vi: "Phát hiện lớp phủ vô hình toàn màn hình (rủi ro nghiêm trọng). Trang này có thể đang cố gắng ghi lại tương tác của bạn.",
    zh: "检测到全屏不可见覆盖层（严重风险）。此页面可能正在尝试捕获您的交互。"
  }
};

let updated = 0;

const locales = fs.readdirSync(LOCALES_DIR).filter(dir => {
  const messagesPath = path.join(LOCALES_DIR, dir, 'messages.json');
  return fs.existsSync(messagesPath);
});

console.log(`Found ${locales.length} locales\n`);

locales.forEach(locale => {
  const messagesPath = path.join(LOCALES_DIR, locale, 'messages.json');

  try {
    const content = fs.readFileSync(messagesPath, 'utf8');
    const messages = JSON.parse(content);
    let changed = false;

    for (const [key, trans] of Object.entries(translations)) {
      if (!messages[key] && trans[locale]) {
        messages[key] = { message: trans[locale] };
        changed = true;
      }
    }

    if (changed) {
      fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');
      console.log(`✓ ${locale}: Added Z-Index War keys`);
      updated++;
    } else {
      console.log(`- ${locale}: Already has all keys`);
    }
  } catch (error) {
    console.log(`✗ ${locale}: Error - ${error.message}`);
  }
});

console.log(`\nUpdated: ${updated}/${locales.length} locales`);
