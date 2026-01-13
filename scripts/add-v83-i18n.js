/**
 * Script to add v8.3.0 security i18n keys to all locale files
 * Adds: dangerousBlobUri, digitHomoglyph
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

// Translations for all 24 locales
const translations = {
  en: {
    dangerousBlobUri: "CRITICAL: This link contains a Blob URL (critical risk). Blob URLs can be used to execute malicious code or deliver malware.",
    digitHomoglyph: "This domain uses digits that look like letters to imitate a known brand (high risk). For example: g00gle uses zeros instead of 'o'."
  },
  nl: {
    dangerousBlobUri: "KRITIEK: Deze link bevat een Blob-URL (kritiek risico). Blob-URL's kunnen worden gebruikt om schadelijke code uit te voeren of malware af te leveren.",
    digitHomoglyph: "Dit domein gebruikt cijfers die op letters lijken om een bekend merk na te bootsen (hoog risico). Bijvoorbeeld: g00gle gebruikt nullen in plaats van 'o'."
  },
  de: {
    dangerousBlobUri: "KRITISCH: Dieser Link enthält eine Blob-URL (kritisches Risiko). Blob-URLs können verwendet werden, um schädlichen Code auszuführen oder Malware zu verbreiten.",
    digitHomoglyph: "Diese Domain verwendet Ziffern, die wie Buchstaben aussehen, um eine bekannte Marke zu imitieren (hohes Risiko). Beispiel: g00gle verwendet Nullen statt 'o'."
  },
  fr: {
    dangerousBlobUri: "CRITIQUE: Ce lien contient une URL Blob (risque critique). Les URL Blob peuvent être utilisées pour exécuter du code malveillant ou distribuer des malwares.",
    digitHomoglyph: "Ce domaine utilise des chiffres qui ressemblent à des lettres pour imiter une marque connue (risque élevé). Par exemple: g00gle utilise des zéros au lieu de 'o'."
  },
  es: {
    dangerousBlobUri: "CRÍTICO: Este enlace contiene una URL Blob (riesgo crítico). Las URL Blob pueden usarse para ejecutar código malicioso o distribuir malware.",
    digitHomoglyph: "Este dominio usa dígitos que parecen letras para imitar una marca conocida (alto riesgo). Por ejemplo: g00gle usa ceros en lugar de 'o'."
  },
  it: {
    dangerousBlobUri: "CRITICO: Questo link contiene un URL Blob (rischio critico). Gli URL Blob possono essere utilizzati per eseguire codice dannoso o distribuire malware.",
    digitHomoglyph: "Questo dominio usa cifre che sembrano lettere per imitare un marchio noto (alto rischio). Esempio: g00gle usa zeri invece di 'o'."
  },
  pt: {
    dangerousBlobUri: "CRÍTICO: Este link contém uma URL Blob (risco crítico). URLs Blob podem ser usadas para executar código malicioso ou distribuir malware.",
    digitHomoglyph: "Este domínio usa dígitos que parecem letras para imitar uma marca conhecida (alto risco). Exemplo: g00gle usa zeros em vez de 'o'."
  },
  pt_BR: {
    dangerousBlobUri: "CRÍTICO: Este link contém uma URL Blob (risco crítico). URLs Blob podem ser usadas para executar código malicioso ou distribuir malware.",
    digitHomoglyph: "Este domínio usa dígitos que parecem letras para imitar uma marca conhecida (alto risco). Exemplo: g00gle usa zeros em vez de 'o'."
  },
  ru: {
    dangerousBlobUri: "КРИТИЧНО: Эта ссылка содержит Blob URL (критический риск). Blob URL могут использоваться для выполнения вредоносного кода или распространения вредоносного ПО.",
    digitHomoglyph: "Этот домен использует цифры, похожие на буквы, для имитации известного бренда (высокий риск). Например: g00gle использует нули вместо 'o'."
  },
  uk: {
    dangerousBlobUri: "КРИТИЧНО: Це посилання містить Blob URL (критичний ризик). Blob URL можуть використовуватися для виконання шкідливого коду або розповсюдження шкідливого ПЗ.",
    digitHomoglyph: "Цей домен використовує цифри, схожі на букви, для імітації відомого бренду (високий ризик). Наприклад: g00gle використовує нулі замість 'o'."
  },
  pl: {
    dangerousBlobUri: "KRYTYCZNE: Ten link zawiera URL Blob (krytyczne ryzyko). URL Blob mogą być używane do wykonywania złośliwego kodu lub dystrybucji malware.",
    digitHomoglyph: "Ta domena używa cyfr wyglądających jak litery, aby imitować znaną markę (wysokie ryzyko). Przykład: g00gle używa zer zamiast 'o'."
  },
  cs: {
    dangerousBlobUri: "KRITICKÉ: Tento odkaz obsahuje Blob URL (kritické riziko). Blob URL mohou být použity ke spuštění škodlivého kódu nebo šíření malwaru.",
    digitHomoglyph: "Tato doména používá číslice vypadající jako písmena k napodobení známé značky (vysoké riziko). Příklad: g00gle používá nuly místo 'o'."
  },
  ro: {
    dangerousBlobUri: "CRITIC: Acest link conține un URL Blob (risc critic). URL-urile Blob pot fi folosite pentru a executa cod malițios sau a distribui malware.",
    digitHomoglyph: "Acest domeniu folosește cifre care arată ca litere pentru a imita o marcă cunoscută (risc ridicat). Exemplu: g00gle folosește zerouri în loc de 'o'."
  },
  hu: {
    dangerousBlobUri: "KRITIKUS: Ez a link Blob URL-t tartalmaz (kritikus kockázat). A Blob URL-ek használhatók rosszindulatú kód futtatására vagy malware terjesztésére.",
    digitHomoglyph: "Ez a domain számjegyeket használ, amelyek betűknek tűnnek, egy ismert márka utánzására (magas kockázat). Példa: g00gle nullákat használ 'o' helyett."
  },
  tr: {
    dangerousBlobUri: "KRİTİK: Bu bağlantı Blob URL içeriyor (kritik risk). Blob URL'ler kötü amaçlı kod çalıştırmak veya kötü amaçlı yazılım dağıtmak için kullanılabilir.",
    digitHomoglyph: "Bu alan adı, bilinen bir markayı taklit etmek için harflere benzeyen rakamlar kullanıyor (yüksek risk). Örnek: g00gle 'o' yerine sıfır kullanıyor."
  },
  el: {
    dangerousBlobUri: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει Blob URL (κρίσιμος κίνδυνος). Τα Blob URL μπορούν να χρησιμοποιηθούν για εκτέλεση κακόβουλου κώδικα ή διανομή κακόβουλου λογισμικού.",
    digitHomoglyph: "Αυτός ο τομέας χρησιμοποιεί ψηφία που μοιάζουν με γράμματα για να μιμηθεί μια γνωστή μάρκα (υψηλός κίνδυνος). Παράδειγμα: g00gle χρησιμοποιεί μηδενικά αντί για 'o'."
  },
  ar: {
    dangerousBlobUri: "حرج: يحتوي هذا الرابط على Blob URL (خطر حرج). يمكن استخدام Blob URLs لتنفيذ كود ضار أو توزيع برمجيات خبيثة.",
    digitHomoglyph: "يستخدم هذا النطاق أرقاماً تشبه الحروف لتقليد علامة تجارية معروفة (خطر عالي). مثال: g00gle يستخدم أصفار بدلاً من 'o'."
  },
  hi: {
    dangerousBlobUri: "गंभीर: इस लिंक में Blob URL है (गंभीर जोखिम)। Blob URLs का उपयोग दुर्भावनापूर्ण कोड चलाने या मैलवेयर वितरित करने के लिए किया जा सकता है।",
    digitHomoglyph: "यह डोमेन एक ज्ञात ब्रांड की नकल करने के लिए अक्षरों जैसे दिखने वाले अंकों का उपयोग करता है (उच्च जोखिम)। उदाहरण: g00gle 'o' के बजाय शून्य का उपयोग करता है।"
  },
  th: {
    dangerousBlobUri: "วิกฤต: ลิงก์นี้มี Blob URL (ความเสี่ยงวิกฤต) Blob URLs สามารถใช้เพื่อรันโค้ดที่เป็นอันตรายหรือแพร่กระจายมัลแวร์",
    digitHomoglyph: "โดเมนนี้ใช้ตัวเลขที่ดูเหมือนตัวอักษรเพื่อเลียนแบบแบรนด์ที่รู้จัก (ความเสี่ยงสูง) ตัวอย่าง: g00gle ใช้เลขศูนย์แทน 'o'"
  },
  vi: {
    dangerousBlobUri: "NGHIÊM TRỌNG: Liên kết này chứa Blob URL (rủi ro nghiêm trọng). Blob URL có thể được sử dụng để thực thi mã độc hại hoặc phân phối phần mềm độc hại.",
    digitHomoglyph: "Tên miền này sử dụng chữ số trông giống chữ cái để bắt chước một thương hiệu nổi tiếng (rủi ro cao). Ví dụ: g00gle sử dụng số không thay vì 'o'."
  },
  id: {
    dangerousBlobUri: "KRITIS: Tautan ini berisi Blob URL (risiko kritis). Blob URL dapat digunakan untuk mengeksekusi kode berbahaya atau mendistribusikan malware.",
    digitHomoglyph: "Domain ini menggunakan angka yang terlihat seperti huruf untuk meniru merek terkenal (risiko tinggi). Contoh: g00gle menggunakan nol sebagai ganti 'o'."
  },
  ja: {
    dangerousBlobUri: "重大: このリンクにはBlob URLが含まれています（重大リスク）。Blob URLは悪意のあるコードの実行やマルウェアの配布に使用される可能性があります。",
    digitHomoglyph: "このドメインは、有名ブランドを模倣するために文字に似た数字を使用しています（高リスク）。例：g00gleは'o'の代わりにゼロを使用。"
  },
  ko: {
    dangerousBlobUri: "심각: 이 링크에는 Blob URL이 포함되어 있습니다 (심각한 위험). Blob URL은 악성 코드를 실행하거나 악성 소프트웨어를 배포하는 데 사용될 수 있습니다.",
    digitHomoglyph: "이 도메인은 알려진 브랜드를 모방하기 위해 문자처럼 보이는 숫자를 사용합니다 (높은 위험). 예: g00gle은 'o' 대신 0을 사용합니다."
  },
  zh: {
    dangerousBlobUri: "严重：此链接包含Blob URL（严重风险）。Blob URL可用于执行恶意代码或分发恶意软件。",
    digitHomoglyph: "此域名使用看起来像字母的数字来模仿知名品牌（高风险）。例如：g00gle使用零代替'o'。"
  }
};

// Keys to add
const keysToAdd = ['dangerousBlobUri', 'digitHomoglyph'];

// Process each locale (except English which is already updated)
const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && f !== 'en';
});

console.log(`Found ${locales.length} non-English locales to update`);

let updated = 0;

locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');

  if (!fs.existsSync(messagesPath)) {
    console.log(`⚠️ Skipping ${locale}: messages.json not found`);
    return;
  }

  try {
    const content = fs.readFileSync(messagesPath, 'utf8');
    const messages = JSON.parse(content);

    // Get translations for this locale (fallback to English)
    const localeTrans = translations[locale] || translations['en'];

    // Check which keys are missing
    const missingKeys = keysToAdd.filter(key => !messages[key]);

    if (missingKeys.length === 0) {
      console.log(`✓ ${locale}: All keys already present`);
      return;
    }

    // Add missing keys
    missingKeys.forEach(key => {
      messages[key] = {
        message: localeTrans[key] || translations['en'][key]
      };
    });

    // Write back
    fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n');
    console.log(`✅ ${locale}: Added ${missingKeys.length} keys (${missingKeys.join(', ')})`);
    updated++;

  } catch (err) {
    console.error(`❌ ${locale}: Error - ${err.message}`);
  }
});

console.log(`\n📊 Summary: ${updated} locales updated`);
