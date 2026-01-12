/**
 * Add suspicious z-index i18n keys to all locales
 */

const fs = require('fs');
const path = require('path');

const LOCALES_DIR = path.join(__dirname, '..', '_locales');

const translations = {
  suspiciousLinkZIndex: {
    ar: "هذا الرابط يستخدم موضع z-index مرتفع للغاية (خطر حرج). هذه تقنية هجوم اختطاف النقرات حيث يتم وضع الروابط الضارة فوق المحتوى الشرعي.",
    cs: "Tento odkaz používá extrémně vysoké z-index umístění (kritické riziko). Jedná se o techniku útoku click hijacking, kde jsou škodlivé odkazy umístěny nad legitimním obsahem.",
    de: "Dieser Link verwendet eine extrem hohe Z-Index-Positionierung (kritisches Risiko). Dies ist eine Click-Hijacking-Angriffstechnik, bei der bösartige Links über legitimen Inhalten platziert werden.",
    el: "Αυτός ο σύνδεσμος χρησιμοποιεί εξαιρετικά υψηλή τοποθέτηση z-index (κρίσιμος κίνδυνος). Αυτή είναι μια τεχνική επίθεσης click hijacking όπου κακόβουλοι σύνδεσμοι τοποθετούνται πάνω από νόμιμο περιεχόμενο.",
    en: "This link uses an extremely high z-index positioning (critical risk). This is a click hijacking attack technique where malicious links are layered above legitimate content.",
    es: "Este enlace utiliza un posicionamiento z-index extremadamente alto (riesgo crítico). Esta es una técnica de ataque de secuestro de clics donde los enlaces maliciosos se colocan sobre contenido legítimo.",
    fr: "Ce lien utilise un positionnement z-index extrêmement élevé (risque critique). C'est une technique d'attaque de détournement de clic où des liens malveillants sont superposés au contenu légitime.",
    hi: "यह लिंक अत्यधिक उच्च z-index पोजिशनिंग का उपयोग करता है (गंभीर जोखिम)। यह एक क्लिक हाइजैकिंग अटैक तकनीक है जहां दुर्भावनापूर्ण लिंक वैध सामग्री के ऊपर रखे जाते हैं।",
    hu: "Ez a link rendkívül magas z-index pozicionálást használ (kritikus kockázat). Ez egy kattintás-eltérítési támadási technika, ahol a rosszindulatú linkeket a legitim tartalom fölé helyezik.",
    id: "Tautan ini menggunakan posisi z-index yang sangat tinggi (risiko kritis). Ini adalah teknik serangan pembajakan klik di mana tautan berbahaya ditempatkan di atas konten yang sah.",
    it: "Questo link utilizza un posizionamento z-index estremamente alto (rischio critico). Questa è una tecnica di attacco click hijacking in cui i link dannosi vengono sovrapposti al contenuto legittimo.",
    ja: "このリンクは非常に高いz-indexポジショニングを使用しています（重大なリスク）。これは悪意のあるリンクが正規のコンテンツの上に重ねられるクリックハイジャック攻撃手法です。",
    ko: "이 링크는 매우 높은 z-index 위치 지정을 사용합니다 (심각한 위험). 이것은 악성 링크가 합법적인 콘텐츠 위에 배치되는 클릭 하이재킹 공격 기술입니다.",
    nl: "Deze link gebruikt een extreem hoge z-index positionering (kritiek risico). Dit is een click hijacking aanvalstechniek waarbij kwaadaardige links boven legitieme content worden geplaatst.",
    pl: "Ten link używa ekstremalnie wysokiego pozycjonowania z-index (krytyczne ryzyko). Jest to technika ataku click hijacking, w której złośliwe linki są umieszczane nad legalną treścią.",
    pt: "Este link usa posicionamento z-index extremamente alto (risco crítico). Esta é uma técnica de ataque de sequestro de clique onde links maliciosos são colocados acima do conteúdo legítimo.",
    pt_BR: "Este link usa posicionamento z-index extremamente alto (risco crítico). Esta é uma técnica de ataque de sequestro de clique onde links maliciosos são colocados acima do conteúdo legítimo.",
    ro: "Acest link utilizează o poziționare z-index extrem de înaltă (risc critic). Aceasta este o tehnică de atac click hijacking în care linkurile malițioase sunt plasate deasupra conținutului legitim.",
    ru: "Эта ссылка использует чрезвычайно высокое позиционирование z-index (критический риск). Это техника атаки перехвата кликов, при которой вредоносные ссылки размещаются поверх легитимного контента.",
    th: "ลิงก์นี้ใช้การจัดตำแหน่ง z-index ที่สูงมาก (ความเสี่ยงร้ายแรง) นี่คือเทคนิคการโจมตีแบบ click hijacking ที่ลิงก์ที่เป็นอันตรายถูกวางซ้อนบนเนื้อหาที่ถูกต้อง",
    tr: "Bu bağlantı aşırı yüksek z-index konumlandırması kullanıyor (kritik risk). Bu, kötü amaçlı bağlantıların meşru içeriğin üzerine yerleştirildiği bir tıklama kaçırma saldırı tekniğidir.",
    uk: "Це посилання використовує надзвичайно високе позиціонування z-index (критичний ризик). Це техніка атаки перехоплення кліків, де шкідливі посилання розміщуються над легітимним контентом.",
    vi: "Liên kết này sử dụng định vị z-index cực cao (rủi ro nghiêm trọng). Đây là kỹ thuật tấn công chiếm đoạt nhấp chuột trong đó các liên kết độc hại được đặt phía trên nội dung hợp pháp.",
    zh: "此链接使用极高的z-index定位（严重风险）。这是一种点击劫持攻击技术，恶意链接被放置在合法内容之上。"
  },
  suspiciousContainerZIndex: {
    ar: "هذا الرابط موجود داخل حاوية ذات موضع z-index مشبوه (خطر حرج). قد تحاول الصفحة خداعك للنقر على محتوى ضار.",
    cs: "Tento odkaz je uvnitř kontejneru s podezřelým z-index umístěním (kritické riziko). Stránka se vás možná pokouší přimět kliknout na škodlivý obsah.",
    de: "Dieser Link befindet sich in einem Container mit verdächtiger Z-Index-Positionierung (kritisches Risiko). Die Seite versucht möglicherweise, Sie zum Klicken auf bösartige Inhalte zu verleiten.",
    el: "Αυτός ο σύνδεσμος βρίσκεται μέσα σε ένα container με ύποπτη τοποθέτηση z-index (κρίσιμος κίνδυνος). Η σελίδα μπορεί να προσπαθεί να σας εξαπατήσει ώστε να κάνετε κλικ σε κακόβουλο περιεχόμενο.",
    en: "This link is inside a container with suspicious z-index positioning (critical risk). The page may be attempting to trick you into clicking malicious content.",
    es: "Este enlace está dentro de un contenedor con posicionamiento z-index sospechoso (riesgo crítico). La página puede estar intentando engañarte para que hagas clic en contenido malicioso.",
    fr: "Ce lien se trouve dans un conteneur avec un positionnement z-index suspect (risque critique). La page pourrait tenter de vous inciter à cliquer sur du contenu malveillant.",
    hi: "यह लिंक संदिग्ध z-index पोजिशनिंग वाले कंटेनर के अंदर है (गंभीर जोखिम)। पृष्ठ आपको दुर्भावनापूर्ण सामग्री पर क्लिक करने के लिए धोखा देने का प्रयास कर सकता है।",
    hu: "Ez a link egy gyanús z-index pozicionálású tárolóban van (kritikus kockázat). Az oldal megpróbálhatja rávenni, hogy rosszindulatú tartalomra kattintson.",
    id: "Tautan ini berada di dalam wadah dengan posisi z-index yang mencurigakan (risiko kritis). Halaman ini mungkin mencoba menipu Anda untuk mengklik konten berbahaya.",
    it: "Questo link è all'interno di un contenitore con posizionamento z-index sospetto (rischio critico). La pagina potrebbe tentare di indurti a cliccare su contenuti dannosi.",
    ja: "このリンクは疑わしいz-indexポジショニングを持つコンテナ内にあります（重大なリスク）。ページは悪意のあるコンテンツをクリックさせようとしている可能性があります。",
    ko: "이 링크는 의심스러운 z-index 위치 지정을 가진 컨테이너 안에 있습니다 (심각한 위험). 페이지가 악성 콘텐츠를 클릭하도록 속이려고 할 수 있습니다.",
    nl: "Deze link bevindt zich in een container met verdachte z-index positionering (kritiek risico). De pagina probeert u mogelijk te misleiden om op kwaadaardige content te klikken.",
    pl: "Ten link znajduje się w kontenerze z podejrzanym pozycjonowaniem z-index (krytyczne ryzyko). Strona może próbować nakłonić cię do kliknięcia złośliwej treści.",
    pt: "Este link está dentro de um contêiner com posicionamento z-index suspeito (risco crítico). A página pode estar tentando enganá-lo para clicar em conteúdo malicioso.",
    pt_BR: "Este link está dentro de um contêiner com posicionamento z-index suspeito (risco crítico). A página pode estar tentando enganá-lo para clicar em conteúdo malicioso.",
    ro: "Acest link este într-un container cu poziționare z-index suspectă (risc critic). Pagina ar putea încerca să vă păcălească să faceți clic pe conținut malițios.",
    ru: "Эта ссылка находится внутри контейнера с подозрительным позиционированием z-index (критический риск). Страница может пытаться обманом заставить вас нажать на вредоносный контент.",
    th: "ลิงก์นี้อยู่ภายในคอนเทนเนอร์ที่มีการจัดตำแหน่ง z-index ที่น่าสงสัย (ความเสี่ยงร้ายแรง) หน้านี้อาจพยายามหลอกให้คุณคลิกเนื้อหาที่เป็นอันตราย",
    tr: "Bu bağlantı şüpheli z-index konumlandırmasına sahip bir kapsayıcının içinde (kritik risk). Sayfa sizi kötü amaçlı içeriğe tıklamaya kandırmaya çalışıyor olabilir.",
    uk: "Це посилання знаходиться всередині контейнера з підозрілим позиціонуванням z-index (критичний ризик). Сторінка може намагатися обманом змусити вас натиснути на шкідливий контент.",
    vi: "Liên kết này nằm trong một container với vị trí z-index đáng ngờ (rủi ro nghiêm trọng). Trang có thể đang cố gắng lừa bạn nhấp vào nội dung độc hại.",
    zh: "此链接位于具有可疑z-index定位的容器内（严重风险）。该页面可能试图诱骗您点击恶意内容。"
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
      console.log(`✓ ${locale}: Added suspicious z-index keys`);
      updated++;
    } else {
      console.log(`- ${locale}: Already has all keys`);
    }
  } catch (error) {
    console.log(`✗ ${locale}: Error - ${error.message}`);
  }
});

console.log(`\nUpdated: ${updated}/${locales.length} locales`);
