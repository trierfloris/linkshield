/**
 * Script to add visualHijackingRisk i18n key to all locale files
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

const translations = {
  en: "CRITICAL: Visual hijacking attack detected (critical risk). A transparent overlay is attempting to intercept your clicks and redirect you to a malicious destination. This link has been blocked for your protection.",
  nl: "KRITIEK: Visuele kaping-aanval gedetecteerd (kritiek risico). Een transparante overlay probeert uw klikken te onderscheppen en u naar een kwaadaardige bestemming om te leiden. Deze link is geblokkeerd voor uw bescherming.",
  de: "KRITISCH: Visueller Hijacking-Angriff erkannt (kritisches Risiko). Ein transparentes Overlay versucht, Ihre Klicks abzufangen und Sie zu einem bösartigen Ziel umzuleiten. Dieser Link wurde zu Ihrem Schutz blockiert.",
  fr: "CRITIQUE: Attaque de détournement visuel détectée (risque critique). Une superposition transparente tente d'intercepter vos clics et de vous rediriger vers une destination malveillante. Ce lien a été bloqué pour votre protection.",
  es: "CRÍTICO: Ataque de secuestro visual detectado (riesgo crítico). Una superposición transparente está intentando interceptar sus clics y redirigirlo a un destino malicioso. Este enlace ha sido bloqueado para su protección.",
  it: "CRITICO: Attacco di dirottamento visivo rilevato (rischio critico). Una sovrapposizione trasparente sta tentando di intercettare i tuoi clic e reindirizzarti verso una destinazione dannosa. Questo link è stato bloccato per la tua protezione.",
  pt: "CRÍTICO: Ataque de sequestro visual detectado (risco crítico). Uma sobreposição transparente está tentando interceptar seus cliques e redirecioná-lo para um destino malicioso. Este link foi bloqueado para sua proteção.",
  pt_BR: "CRÍTICO: Ataque de sequestro visual detectado (risco crítico). Uma sobreposição transparente está tentando interceptar seus cliques e redirecioná-lo para um destino malicioso. Este link foi bloqueado para sua proteção.",
  ru: "КРИТИЧНО: Обнаружена атака визуального перехвата (критический риск). Прозрачный оверлей пытается перехватить ваши клики и перенаправить вас на вредоносный ресурс. Эта ссылка заблокирована для вашей защиты.",
  uk: "КРИТИЧНО: Виявлено атаку візуального перехоплення (критичний ризик). Прозорий оверлей намагається перехопити ваші кліки та перенаправити вас на шкідливий ресурс. Це посилання заблоковано для вашого захисту.",
  pl: "KRYTYCZNE: Wykryto atak wizualnego przechwytywania (krytyczne ryzyko). Przezroczysta nakładka próbuje przechwycić Twoje kliknięcia i przekierować Cię do złośliwego miejsca docelowego. Ten link został zablokowany dla Twojej ochrony.",
  cs: "KRITICKÉ: Detekován vizuální únos (kritické riziko). Průhledná vrstva se pokouší zachytit vaše kliknutí a přesměrovat vás na škodlivý cíl. Tento odkaz byl zablokován pro vaši ochranu.",
  ro: "CRITIC: Atac de deturnare vizuală detectat (risc critic). O suprapunere transparentă încearcă să vă intercepteze clicurile și să vă redirecționeze către o destinație malițioasă. Acest link a fost blocat pentru protecția dvs.",
  hu: "KRITIKUS: Vizuális eltérítési támadás észlelve (kritikus kockázat). Egy átlátszó réteg próbálja elfogni kattintásait és átirányítani egy rosszindulatú célra. Ez a link blokkolva lett az Ön védelme érdekében.",
  tr: "KRİTİK: Görsel kaçırma saldırısı tespit edildi (kritik risk). Şeffaf bir katman tıklamalarınızı yakalamaya ve sizi kötü amaçlı bir hedefe yönlendirmeye çalışıyor. Bu bağlantı korumanız için engellendi.",
  el: "ΚΡΙΣΙΜΟ: Ανιχνεύθηκε επίθεση οπτικής υποκλοπής (κρίσιμος κίνδυνος). Ένα διαφανές επίπεδο προσπαθεί να υποκλέψει τα κλικ σας και να σας ανακατευθύνει σε κακόβουλο προορισμό. Αυτός ο σύνδεσμος έχει αποκλειστεί για την προστασία σας.",
  ar: "حرج: تم اكتشاف هجوم اختطاف بصري (خطر حرج). طبقة شفافة تحاول اعتراض نقراتك وإعادة توجيهك إلى وجهة ضارة. تم حظر هذا الرابط لحمايتك.",
  hi: "गंभीर: दृश्य अपहरण हमला पाया गया (गंभीर जोखिम)। एक पारदर्शी ओवरले आपके क्लिक को रोकने और आपको एक दुर्भावनापूर्ण गंतव्य पर पुनर्निर्देशित करने का प्रयास कर रहा है। यह लिंक आपकी सुरक्षा के लिए अवरुद्ध कर दिया गया है।",
  th: "วิกฤต: ตรวจพบการโจมตี Visual Hijacking (ความเสี่ยงวิกฤต) เลเยอร์โปร่งใสกำลังพยายามดักจับคลิกของคุณและเปลี่ยนเส้นทางไปยังปลายทางที่เป็นอันตราย ลิงก์นี้ถูกบล็อกเพื่อการป้องกันของคุณ",
  vi: "NGHIÊM TRỌNG: Phát hiện tấn công Visual Hijacking (rủi ro nghiêm trọng). Một lớp phủ trong suốt đang cố gắng chặn nhấp chuột của bạn và chuyển hướng bạn đến đích độc hại. Liên kết này đã bị chặn để bảo vệ bạn.",
  id: "KRITIS: Serangan visual hijacking terdeteksi (risiko kritis). Overlay transparan mencoba mencegat klik Anda dan mengarahkan Anda ke tujuan berbahaya. Tautan ini telah diblokir untuk perlindungan Anda.",
  ja: "重大: ビジュアルハイジャック攻撃が検出されました（重大リスク）。透明なオーバーレイがあなたのクリックを傍受し、悪意のある宛先にリダイレクトしようとしています。このリンクはあなたの保護のためにブロックされました。",
  ko: "심각: 시각적 하이재킹 공격이 감지되었습니다 (심각한 위험). 투명한 오버레이가 클릭을 가로채고 악성 목적지로 리디렉션하려고 합니다. 이 링크는 귀하의 보호를 위해 차단되었습니다.",
  zh: "严重：检测到视觉劫持攻击（严重风险）。透明覆盖层正试图拦截您的点击并将您重定向到恶意目的地。此链接已被阻止以保护您。"
};

const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && f !== 'en';
});

console.log(`Found ${locales.length} non-English locales to update`);

let updated = 0;

locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');

  if (!fs.existsSync(messagesPath)) {
    console.log(`Warning: Skipping ${locale}: messages.json not found`);
    return;
  }

  try {
    const content = fs.readFileSync(messagesPath, 'utf8');
    const messages = JSON.parse(content);

    if (messages.visualHijackingRisk) {
      console.log(`OK ${locale}: Key already present`);
      return;
    }

    messages.visualHijackingRisk = {
      message: translations[locale] || translations['en']
    };

    fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n');
    console.log(`UPDATED ${locale}: Added visualHijackingRisk`);
    updated++;

  } catch (err) {
    console.error(`ERROR ${locale}: ${err.message}`);
  }
});

console.log(`\nSummary: ${updated} locales updated`);
