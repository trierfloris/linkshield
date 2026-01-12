/**
 * Script to add v8.5.0 security i18n keys to all locale files
 * New keys: fullwidthCharsDetected, cherokeeCharsDetected, nonAsciiInBrandDomain,
 *           pointerEventsNoneHighZIndex, intMaxZIndexOverlay, maliciousDomainKeyword
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

const translations = {
  // fullwidthCharsDetected
  fullwidthCharsDetected: {
    en: "This domain contains Fullwidth Unicode characters (high risk). Fullwidth letters (like ａｐｐｌｅ) look identical to regular letters but are different characters, commonly used for phishing attacks.",
    nl: "Dit domein bevat Fullwidth Unicode-tekens (hoog risico). Fullwidth letters (zoals ａｐｐｌｅ) zien er identiek uit als gewone letters maar zijn andere tekens, vaak gebruikt voor phishing-aanvallen.",
    de: "Diese Domain enthält Vollbreite-Unicode-Zeichen (hohes Risiko). Vollbreite-Buchstaben (wie ａｐｐｌｅ) sehen identisch mit normalen Buchstaben aus, sind aber andere Zeichen, die häufig für Phishing-Angriffe verwendet werden.",
    fr: "Ce domaine contient des caractères Unicode pleine largeur (risque élevé). Les lettres pleine largeur (comme ａｐｐｌｅ) ressemblent aux lettres normales mais sont des caractères différents, couramment utilisés pour les attaques de phishing.",
    es: "Este dominio contiene caracteres Unicode de ancho completo (alto riesgo). Las letras de ancho completo (como ａｐｐｌｅ) parecen idénticas a las letras normales pero son caracteres diferentes, comúnmente usados para ataques de phishing.",
    it: "Questo dominio contiene caratteri Unicode a larghezza piena (alto rischio). Le lettere a larghezza piena (come ａｐｐｌｅ) sembrano identiche alle lettere normali ma sono caratteri diversi, comunemente usati per attacchi di phishing.",
    pt: "Este domínio contém caracteres Unicode de largura total (alto risco). Letras de largura total (como ａｐｐｌｅ) parecem idênticas às letras normais mas são caracteres diferentes, comumente usados para ataques de phishing.",
    pt_BR: "Este domínio contém caracteres Unicode de largura total (alto risco). Letras de largura total (como ａｐｐｌｅ) parecem idênticas às letras normais mas são caracteres diferentes, comumente usados para ataques de phishing.",
    ru: "Этот домен содержит полноширинные Unicode-символы (высокий риск). Полноширинные буквы (например, ａｐｐｌｅ) выглядят идентично обычным буквам, но являются другими символами, часто используемыми для фишинговых атак.",
    uk: "Цей домен містить повноширинні Unicode-символи (високий ризик). Повноширинні літери (наприклад, ａｐｐｌｅ) виглядають ідентично звичайним літерам, але є іншими символами, які часто використовуються для фішингових атак.",
    pl: "Ta domena zawiera znaki Unicode o pełnej szerokości (wysokie ryzyko). Litery o pełnej szerokości (jak ａｐｐｌｅ) wyglądają identycznie jak zwykłe litery, ale są różnymi znakami, powszechnie używanymi do ataków phishingowych.",
    cs: "Tato doména obsahuje Unicode znaky plné šířky (vysoké riziko). Znaky plné šířky (jako ａｐｐｌｅ) vypadají stejně jako běžné znaky, ale jsou to jiné znaky, běžně používané pro phishingové útoky.",
    ro: "Acest domeniu conține caractere Unicode de lățime completă (risc ridicat). Literele de lățime completă (precum ａｐｐｌｅ) arată identic cu literele normale dar sunt caractere diferite, utilizate frecvent pentru atacuri de phishing.",
    hu: "Ez a domain teljes szélességű Unicode karaktereket tartalmaz (magas kockázat). A teljes szélességű betűk (mint ａｐｐｌｅ) azonosnak tűnnek a normál betűkkel, de különböző karakterek, amelyeket gyakran használnak adathalász támadásokhoz.",
    tr: "Bu alan adı tam genişlikli Unicode karakterler içeriyor (yüksek risk). Tam genişlikli harfler (ａｐｐｌｅ gibi) normal harflerle aynı görünür ancak farklı karakterlerdir, yaygın olarak kimlik avı saldırılarında kullanılır.",
    el: "Αυτός ο τομέας περιέχει χαρακτήρες Unicode πλήρους πλάτους (υψηλός κίνδυνος). Τα γράμματα πλήρους πλάτους (όπως ａｐｐｌｅ) φαίνονται πανομοιότυπα με τα κανονικά γράμματα αλλά είναι διαφορετικοί χαρακτήρες, που χρησιμοποιούνται συχνά για επιθέσεις phishing.",
    ar: "يحتوي هذا النطاق على أحرف Unicode كاملة العرض (خطر عالي). الأحرف كاملة العرض (مثل ａｐｐｌｅ) تبدو متطابقة مع الأحرف العادية لكنها أحرف مختلفة، تستخدم عادة في هجمات التصيد.",
    hi: "इस डोमेन में फुलविड्थ यूनिकोड अक्षर हैं (उच्च जोखिम)। फुलविड्थ अक्षर (जैसे ａｐｐｌｅ) सामान्य अक्षरों की तरह दिखते हैं लेकिन अलग अक्षर हैं, जो आमतौर पर फ़िशिंग हमलों के लिए उपयोग किए जाते हैं।",
    th: "โดเมนนี้มีอักขระ Unicode แบบเต็มความกว้าง (ความเสี่ยงสูง) ตัวอักษรแบบเต็มความกว้าง (เช่น ａｐｐｌｅ) ดูเหมือนกับตัวอักษรปกติแต่เป็นอักขระที่แตกต่างกัน ซึ่งมักใช้สำหรับการโจมตีแบบฟิชชิง",
    vi: "Tên miền này chứa các ký tự Unicode toàn chiều rộng (rủi ro cao). Các chữ cái toàn chiều rộng (như ａｐｐｌｅ) trông giống hệt các chữ cái thông thường nhưng là các ký tự khác nhau, thường được sử dụng cho các cuộc tấn công lừa đảo.",
    id: "Domain ini mengandung karakter Unicode lebar penuh (risiko tinggi). Huruf lebar penuh (seperti ａｐｐｌｅ) terlihat identik dengan huruf biasa tetapi merupakan karakter yang berbeda, umumnya digunakan untuk serangan phishing.",
    ja: "このドメインには全角Unicode文字が含まれています（高リスク）。全角文字（ａｐｐｌｅなど）は通常の文字と同じに見えますが、異なる文字であり、フィッシング攻撃によく使用されます。",
    ko: "이 도메인에는 전각 유니코드 문자가 포함되어 있습니다(높은 위험). 전각 문자(ａｐｐｌｅ 등)는 일반 문자와 동일하게 보이지만 다른 문자이며, 피싱 공격에 일반적으로 사용됩니다.",
    zh: "此域名包含全角Unicode字符（高风险）。全角字母（如ａｐｐｌｅ）看起来与普通字母相同，但实际上是不同的字符，常用于钓鱼攻击。"
  },

  // cherokeeCharsDetected
  cherokeeCharsDetected: {
    en: "This domain contains Cherokee script characters (high risk). Cherokee letters resemble Latin letters (like ꮓ looks like 'z') and are used to create convincing fake domains.",
    nl: "Dit domein bevat Cherokee-schrifttekens (hoog risico). Cherokee-letters lijken op Latijnse letters (zoals ꮓ lijkt op 'z') en worden gebruikt om overtuigende nepdomeinen te maken.",
    de: "Diese Domain enthält Cherokee-Schriftzeichen (hohes Risiko). Cherokee-Buchstaben ähneln lateinischen Buchstaben (z.B. ꮓ sieht aus wie 'z') und werden verwendet, um überzeugende gefälschte Domains zu erstellen.",
    fr: "Ce domaine contient des caractères Cherokee (risque élevé). Les lettres Cherokee ressemblent aux lettres latines (comme ꮓ ressemble à 'z') et sont utilisées pour créer des domaines factices convaincants.",
    es: "Este dominio contiene caracteres Cherokee (alto riesgo). Las letras Cherokee se parecen a las letras latinas (como ꮓ parece 'z') y se usan para crear dominios falsos convincentes.",
    it: "Questo dominio contiene caratteri Cherokee (alto rischio). Le lettere Cherokee assomigliano alle lettere latine (come ꮓ sembra 'z') e vengono usate per creare domini falsi convincenti.",
    pt: "Este domínio contém caracteres Cherokee (alto risco). As letras Cherokee se parecem com letras latinas (como ꮓ parece 'z') e são usadas para criar domínios falsos convincentes.",
    pt_BR: "Este domínio contém caracteres Cherokee (alto risco). As letras Cherokee se parecem com letras latinas (como ꮓ parece 'z') e são usadas para criar domínios falsos convincentes.",
    ru: "Этот домен содержит символы Cherokee (высокий риск). Буквы Cherokee похожи на латинские буквы (например, ꮓ похож на 'z') и используются для создания убедительных поддельных доменов.",
    uk: "Цей домен містить символи Cherokee (високий ризик). Літери Cherokee схожі на латинські літери (наприклад, ꮓ схожий на 'z') і використовуються для створення переконливих підроблених доменів.",
    pl: "Ta domena zawiera znaki pisma Cherokee (wysokie ryzyko). Litery Cherokee przypominają litery łacińskie (jak ꮓ wygląda jak 'z') i są używane do tworzenia przekonujących fałszywych domen.",
    cs: "Tato doména obsahuje znaky písma Cherokee (vysoké riziko). Písmena Cherokee připomínají latinská písmena (např. ꮓ vypadá jako 'z') a používají se k vytváření přesvědčivých falešných domén.",
    ro: "Acest domeniu conține caractere Cherokee (risc ridicat). Literele Cherokee seamănă cu literele latine (precum ꮓ arată ca 'z') și sunt folosite pentru a crea domenii false convingătoare.",
    hu: "Ez a domain Cherokee írásjeleket tartalmaz (magas kockázat). A Cherokee betűk hasonlítanak a latin betűkre (például ꮓ úgy néz ki, mint 'z') és meggyőző hamis domainek létrehozására használják.",
    tr: "Bu alan adı Cherokee yazı karakterleri içeriyor (yüksek risk). Cherokee harfleri Latin harflerine benzer (ꮓ 'z' gibi görünür) ve ikna edici sahte alan adları oluşturmak için kullanılır.",
    el: "Αυτός ο τομέας περιέχει χαρακτήρες Cherokee (υψηλός κίνδυνος). Τα γράμματα Cherokee μοιάζουν με λατινικά γράμματα (όπως το ꮓ μοιάζει με 'z') και χρησιμοποιούνται για τη δημιουργία πειστικών ψεύτικων τομέων.",
    ar: "يحتوي هذا النطاق على أحرف شيروكي (خطر عالي). أحرف شيروكي تشبه الأحرف اللاتينية (مثل ꮓ تبدو مثل 'z') وتستخدم لإنشاء نطاقات مزيفة مقنعة.",
    hi: "इस डोमेन में चेरोकी लिपि के अक्षर हैं (उच्च जोखिम)। चेरोकी अक्षर लैटिन अक्षरों की तरह दिखते हैं (जैसे ꮓ 'z' जैसा दिखता है) और विश्वसनीय नकली डोमेन बनाने के लिए उपयोग किए जाते हैं।",
    th: "โดเมนนี้มีอักขระเชอโรกี (ความเสี่ยงสูง) ตัวอักษรเชอโรกีคล้ายกับตัวอักษรละติน (เช่น ꮓ ดูเหมือน 'z') และใช้สร้างโดเมนปลอมที่น่าเชื่อถือ",
    vi: "Tên miền này chứa các ký tự Cherokee (rủi ro cao). Các chữ cái Cherokee giống với các chữ cái Latin (như ꮓ trông giống 'z') và được sử dụng để tạo các tên miền giả mạo thuyết phục.",
    id: "Domain ini mengandung karakter skrip Cherokee (risiko tinggi). Huruf Cherokee menyerupai huruf Latin (seperti ꮓ terlihat seperti 'z') dan digunakan untuk membuat domain palsu yang meyakinkan.",
    ja: "このドメインにはチェロキー文字が含まれています（高リスク）。チェロキー文字はラテン文字に似ています（ꮓは'z'のように見えます）。説得力のある偽のドメインを作成するために使用されます。",
    ko: "이 도메인에는 체로키 문자가 포함되어 있습니다(높은 위험). 체로키 문자는 라틴 문자와 비슷합니다(ꮓ는 'z'처럼 보임). 설득력 있는 가짜 도메인을 만드는 데 사용됩니다.",
    zh: "此域名包含切罗基文字字符（高风险）。切罗基字母与拉丁字母相似（如ꮓ看起来像'z'），用于创建令人信服的假域名。"
  },

  // nonAsciiInBrandDomain
  nonAsciiInBrandDomain: {
    en: "This domain contains non-ASCII characters in a brand-like context (high risk). Special characters are being used to impersonate a legitimate website.",
    nl: "Dit domein bevat niet-ASCII-tekens in een merkachtige context (hoog risico). Speciale tekens worden gebruikt om een legitieme website na te bootsen.",
    de: "Diese Domain enthält Nicht-ASCII-Zeichen in einem markenähnlichen Kontext (hohes Risiko). Sonderzeichen werden verwendet, um eine legitime Website zu imitieren.",
    fr: "Ce domaine contient des caractères non-ASCII dans un contexte de marque (risque élevé). Des caractères spéciaux sont utilisés pour usurper l'identité d'un site Web légitime.",
    es: "Este dominio contiene caracteres no ASCII en un contexto de marca (alto riesgo). Se están usando caracteres especiales para suplantar un sitio web legítimo.",
    it: "Questo dominio contiene caratteri non ASCII in un contesto di marca (alto rischio). Caratteri speciali vengono utilizzati per impersonare un sito web legittimo.",
    pt: "Este domínio contém caracteres não-ASCII em um contexto de marca (alto risco). Caracteres especiais estão sendo usados para se passar por um site legítimo.",
    pt_BR: "Este domínio contém caracteres não-ASCII em um contexto de marca (alto risco). Caracteres especiais estão sendo usados para se passar por um site legítimo.",
    ru: "Этот домен содержит не-ASCII символы в контексте бренда (высокий риск). Специальные символы используются для имитации легитимного веб-сайта.",
    uk: "Цей домен містить не-ASCII символи в контексті бренду (високий ризик). Спеціальні символи використовуються для імітації легітимного веб-сайту.",
    pl: "Ta domena zawiera znaki spoza ASCII w kontekście marki (wysokie ryzyko). Znaki specjalne są używane do podszywania się pod legalną stronę internetową.",
    cs: "Tato doména obsahuje znaky mimo ASCII v kontextu značky (vysoké riziko). Speciální znaky se používají k napodobování legitimních webových stránek.",
    ro: "Acest domeniu conține caractere non-ASCII într-un context de marcă (risc ridicat). Caractere speciale sunt folosite pentru a imita un site web legitim.",
    hu: "Ez a domain nem-ASCII karaktereket tartalmaz márkaszerű kontextusban (magas kockázat). Speciális karaktereket használnak egy legitim weboldal megszemélyesítésére.",
    tr: "Bu alan adı marka benzeri bir bağlamda ASCII olmayan karakterler içeriyor (yüksek risk). Özel karakterler meşru bir web sitesini taklit etmek için kullanılıyor.",
    el: "Αυτός ο τομέας περιέχει χαρακτήρες μη-ASCII σε περιβάλλον μάρκας (υψηλός κίνδυνος). Χρησιμοποιούνται ειδικοί χαρακτήρες για την απομίμηση νόμιμου ιστότοπου.",
    ar: "يحتوي هذا النطاق على أحرف غير ASCII في سياق علامة تجارية (خطر عالي). يتم استخدام أحرف خاصة لانتحال هوية موقع ويب شرعي.",
    hi: "इस डोमेन में ब्रांड जैसे संदर्भ में गैर-ASCII अक्षर हैं (उच्च जोखिम)। एक वैध वेबसाइट का प्रतिरूपण करने के लिए विशेष अक्षरों का उपयोग किया जा रहा है।",
    th: "โดเมนนี้มีอักขระที่ไม่ใช่ ASCII ในบริบทของแบรนด์ (ความเสี่ยงสูง) อักขระพิเศษถูกใช้เพื่อปลอมเป็นเว็บไซต์ที่ถูกต้อง",
    vi: "Tên miền này chứa các ký tự không phải ASCII trong ngữ cảnh thương hiệu (rủi ro cao). Các ký tự đặc biệt đang được sử dụng để mạo danh một trang web hợp pháp.",
    id: "Domain ini mengandung karakter non-ASCII dalam konteks merek (risiko tinggi). Karakter khusus digunakan untuk meniru situs web yang sah.",
    ja: "このドメインには、ブランドのようなコンテキストで非ASCII文字が含まれています（高リスク）。特殊文字が正規のウェブサイトを偽装するために使用されています。",
    ko: "이 도메인에는 브랜드와 유사한 컨텍스트에서 비ASCII 문자가 포함되어 있습니다(높은 위험). 합법적인 웹사이트를 사칭하기 위해 특수 문자가 사용되고 있습니다.",
    zh: "此域名在品牌相关的上下文中包含非ASCII字符（高风险）。正在使用特殊字符来冒充合法网站。"
  },

  // pointerEventsNoneHighZIndex
  pointerEventsNoneHighZIndex: {
    en: "CRITICAL: A transparent clickjacking overlay was detected (critical risk). An invisible element with maximum z-index is trying to intercept your interactions.",
    nl: "KRITIEK: Een transparante clickjacking-overlay gedetecteerd (kritiek risico). Een onzichtbaar element met maximale z-index probeert uw interacties te onderscheppen.",
    de: "KRITISCH: Ein transparentes Clickjacking-Overlay wurde erkannt (kritisches Risiko). Ein unsichtbares Element mit maximalem z-index versucht, Ihre Interaktionen abzufangen.",
    fr: "CRITIQUE: Une superposition de clickjacking transparente a été détectée (risque critique). Un élément invisible avec un z-index maximum tente d'intercepter vos interactions.",
    es: "CRÍTICO: Se detectó una superposición de clickjacking transparente (riesgo crítico). Un elemento invisible con z-index máximo está intentando interceptar sus interacciones.",
    it: "CRITICO: Rilevato overlay di clickjacking trasparente (rischio critico). Un elemento invisibile con z-index massimo sta cercando di intercettare le tue interazioni.",
    pt: "CRÍTICO: Foi detectada uma sobreposição de clickjacking transparente (risco crítico). Um elemento invisível com z-index máximo está tentando interceptar suas interações.",
    pt_BR: "CRÍTICO: Foi detectada uma sobreposição de clickjacking transparente (risco crítico). Um elemento invisível com z-index máximo está tentando interceptar suas interações.",
    ru: "КРИТИЧНО: Обнаружен прозрачный оверлей для кликджекинга (критический риск). Невидимый элемент с максимальным z-index пытается перехватить ваши взаимодействия.",
    uk: "КРИТИЧНО: Виявлено прозорий оверлей для клікджекінгу (критичний ризик). Невидимий елемент з максимальним z-index намагається перехопити ваші взаємодії.",
    pl: "KRYTYCZNE: Wykryto przezroczystą nakładkę clickjacking (krytyczne ryzyko). Niewidoczny element z maksymalnym z-index próbuje przechwycić Twoje interakcje.",
    cs: "KRITICKÉ: Detekován průhledný clickjacking overlay (kritické riziko). Neviditelný prvek s maximálním z-index se pokouší zachytit vaše interakce.",
    ro: "CRITIC: A fost detectată o suprapunere de clickjacking transparentă (risc critic). Un element invizibil cu z-index maxim încearcă să vă intercepteze interacțiunile.",
    hu: "KRITIKUS: Átlátszó clickjacking overlay észlelve (kritikus kockázat). Egy láthatatlan elem maximális z-index-szel próbálja elfogni az interakcióit.",
    tr: "KRİTİK: Şeffaf bir clickjacking katmanı tespit edildi (kritik risk). Maksimum z-index'e sahip görünmez bir öğe etkileşimlerinizi yakalamaya çalışıyor.",
    el: "ΚΡΙΣΙΜΟ: Ανιχνεύθηκε διαφανές clickjacking overlay (κρίσιμος κίνδυνος). Ένα αόρατο στοιχείο με μέγιστο z-index προσπαθεί να υποκλέψει τις αλληλεπιδράσεις σας.",
    ar: "حرج: تم اكتشاف طبقة clickjacking شفافة (خطر حرج). عنصر غير مرئي بأقصى z-index يحاول اعتراض تفاعلاتك.",
    hi: "गंभीर: एक पारदर्शी क्लिकजैकिंग ओवरले का पता चला (गंभीर जोखिम)। अधिकतम z-index वाला एक अदृश्य तत्व आपकी इंटरैक्शन को इंटरसेप्ट करने की कोशिश कर रहा है।",
    th: "วิกฤต: ตรวจพบ overlay clickjacking โปร่งใส (ความเสี่ยงวิกฤต) องค์ประกอบที่มองไม่เห็นที่มี z-index สูงสุดกำลังพยายามดักจับการโต้ตอบของคุณ",
    vi: "NGHIÊM TRỌNG: Phát hiện lớp phủ clickjacking trong suốt (rủi ro nghiêm trọng). Một phần tử vô hình với z-index tối đa đang cố gắng chặn các tương tác của bạn.",
    id: "KRITIS: Overlay clickjacking transparan terdeteksi (risiko kritis). Elemen tak terlihat dengan z-index maksimum mencoba mencegat interaksi Anda.",
    ja: "重大: 透明なクリックジャッキングオーバーレイが検出されました（重大リスク）。最大z-indexを持つ不可視の要素があなたの操作を傍受しようとしています。",
    ko: "심각: 투명한 클릭재킹 오버레이가 감지되었습니다(심각한 위험). 최대 z-index를 가진 보이지 않는 요소가 상호작용을 가로채려고 합니다.",
    zh: "严重：检测到透明的点击劫持覆盖层（严重风险）。具有最大z-index的不可见元素正试图拦截您的交互。"
  },

  // intMaxZIndexOverlay
  intMaxZIndexOverlay: {
    en: "CRITICAL: A suspicious overlay with maximum z-index was detected (critical risk). This may be an attempt to hijack your clicks.",
    nl: "KRITIEK: Een verdachte overlay met maximale z-index gedetecteerd (kritiek risico). Dit kan een poging zijn om uw klikken te kapen.",
    de: "KRITISCH: Ein verdächtiges Overlay mit maximalem z-index wurde erkannt (kritisches Risiko). Dies könnte ein Versuch sein, Ihre Klicks zu kapern.",
    fr: "CRITIQUE: Une superposition suspecte avec z-index maximum a été détectée (risque critique). Ceci pourrait être une tentative de détourner vos clics.",
    es: "CRÍTICO: Se detectó una superposición sospechosa con z-index máximo (riesgo crítico). Esto puede ser un intento de secuestrar sus clics.",
    it: "CRITICO: Rilevato overlay sospetto con z-index massimo (rischio critico). Questo potrebbe essere un tentativo di dirottare i tuoi clic.",
    pt: "CRÍTICO: Foi detectada uma sobreposição suspeita com z-index máximo (risco crítico). Isso pode ser uma tentativa de sequestrar seus cliques.",
    pt_BR: "CRÍTICO: Foi detectada uma sobreposição suspeita com z-index máximo (risco crítico). Isso pode ser uma tentativa de sequestrar seus cliques.",
    ru: "КРИТИЧНО: Обнаружен подозрительный оверлей с максимальным z-index (критический риск). Это может быть попыткой перехватить ваши клики.",
    uk: "КРИТИЧНО: Виявлено підозрілий оверлей з максимальним z-index (критичний ризик). Це може бути спробою перехопити ваші кліки.",
    pl: "KRYTYCZNE: Wykryto podejrzaną nakładkę z maksymalnym z-index (krytyczne ryzyko). To może być próba przejęcia Twoich kliknięć.",
    cs: "KRITICKÉ: Detekována podezřelá vrstva s maximálním z-index (kritické riziko). Může se jednat o pokus o únos vašich kliknutí.",
    ro: "CRITIC: A fost detectată o suprapunere suspectă cu z-index maxim (risc critic). Aceasta poate fi o încercare de a vă deturna clicurile.",
    hu: "KRITIKUS: Gyanús overlay észlelve maximális z-index-szel (kritikus kockázat). Ez egy kísérlet lehet a kattintások eltérítésére.",
    tr: "KRİTİK: Maksimum z-index'e sahip şüpheli bir katman tespit edildi (kritik risk). Bu, tıklamalarınızı ele geçirme girişimi olabilir.",
    el: "ΚΡΙΣΙΜΟ: Ανιχνεύθηκε ύποπτο overlay με μέγιστο z-index (κρίσιμος κίνδυνος). Αυτό μπορεί να είναι απόπειρα υποκλοπής των κλικ σας.",
    ar: "حرج: تم اكتشاف طبقة مشبوهة بأقصى z-index (خطر حرج). قد تكون هذه محاولة لاختطاف نقراتك.",
    hi: "गंभीर: अधिकतम z-index वाला एक संदिग्ध ओवरले का पता चला (गंभीर जोखिम)। यह आपके क्लिक को हाईजैक करने का प्रयास हो सकता है।",
    th: "วิกฤต: ตรวจพบ overlay ที่น่าสงสัยที่มี z-index สูงสุด (ความเสี่ยงวิกฤต) นี่อาจเป็นความพยายามในการดักจับคลิกของคุณ",
    vi: "NGHIÊM TRỌNG: Phát hiện lớp phủ đáng ngờ với z-index tối đa (rủi ro nghiêm trọng). Đây có thể là nỗ lực chiếm quyền điều khiển các nhấp chuột của bạn.",
    id: "KRITIS: Overlay mencurigakan dengan z-index maksimum terdeteksi (risiko kritis). Ini mungkin upaya untuk membajak klik Anda.",
    ja: "重大: 最大z-indexを持つ不審なオーバーレイが検出されました（重大リスク）。これはクリックをハイジャックしようとする試みである可能性があります。",
    ko: "심각: 최대 z-index를 가진 의심스러운 오버레이가 감지되었습니다(심각한 위험). 이것은 클릭을 가로채려는 시도일 수 있습니다.",
    zh: "严重：检测到具有最大z-index的可疑覆盖层（严重风险）。这可能是劫持您点击的尝试。"
  },

  // maliciousDomainKeyword
  maliciousDomainKeyword: {
    en: "CRITICAL: This domain contains keywords commonly associated with phishing or malware (critical risk). The domain name itself suggests malicious intent.",
    nl: "KRITIEK: Dit domein bevat sleutelwoorden die vaak geassocieerd worden met phishing of malware (kritiek risico). De domeinnaam zelf suggereert kwaadaardige bedoelingen.",
    de: "KRITISCH: Diese Domain enthält Schlüsselwörter, die häufig mit Phishing oder Malware in Verbindung gebracht werden (kritisches Risiko). Der Domainname selbst deutet auf böswillige Absichten hin.",
    fr: "CRITIQUE: Ce domaine contient des mots-clés couramment associés au phishing ou aux logiciels malveillants (risque critique). Le nom de domaine lui-même suggère une intention malveillante.",
    es: "CRÍTICO: Este dominio contiene palabras clave comúnmente asociadas con phishing o malware (riesgo crítico). El nombre de dominio en sí sugiere intención maliciosa.",
    it: "CRITICO: Questo dominio contiene parole chiave comunemente associate a phishing o malware (rischio critico). Il nome di dominio stesso suggerisce intenti malevoli.",
    pt: "CRÍTICO: Este domínio contém palavras-chave comumente associadas a phishing ou malware (risco crítico). O próprio nome de domínio sugere intenção maliciosa.",
    pt_BR: "CRÍTICO: Este domínio contém palavras-chave comumente associadas a phishing ou malware (risco crítico). O próprio nome de domínio sugere intenção maliciosa.",
    ru: "КРИТИЧНО: Этот домен содержит ключевые слова, обычно связанные с фишингом или вредоносным ПО (критический риск). Само доменное имя указывает на злонамеренные намерения.",
    uk: "КРИТИЧНО: Цей домен містить ключові слова, зазвичай пов'язані з фішингом або шкідливим ПЗ (критичний ризик). Сама назва домену вказує на зловмисні наміри.",
    pl: "KRYTYCZNE: Ta domena zawiera słowa kluczowe często związane z phishingiem lub złośliwym oprogramowaniem (krytyczne ryzyko). Sama nazwa domeny sugeruje złośliwe zamiary.",
    cs: "KRITICKÉ: Tato doména obsahuje klíčová slova běžně spojovaná s phishingem nebo malwarem (kritické riziko). Samotný název domény naznačuje škodlivý záměr.",
    ro: "CRITIC: Acest domeniu conține cuvinte cheie asociate frecvent cu phishing sau malware (risc critic). Numele domeniului în sine sugerează intenții rău intenționate.",
    hu: "KRITIKUS: Ez a domain gyakran adathalászattal vagy rosszindulatú programokkal kapcsolatos kulcsszavakat tartalmaz (kritikus kockázat). Maga a domain név rosszindulatú szándékra utal.",
    tr: "KRİTİK: Bu alan adı yaygın olarak kimlik avı veya kötü amaçlı yazılımla ilişkilendirilen anahtar kelimeler içeriyor (kritik risk). Alan adının kendisi kötü niyetli niyet gösteriyor.",
    el: "ΚΡΙΣΙΜΟ: Αυτός ο τομέας περιέχει λέξεις-κλειδιά που συνδέονται συχνά με phishing ή κακόβουλο λογισμικό (κρίσιμος κίνδυνος). Το ίδιο το όνομα τομέα υποδηλώνει κακόβουλη πρόθεση.",
    ar: "حرج: يحتوي هذا النطاق على كلمات مفتاحية مرتبطة عادة بالتصيد أو البرامج الضارة (خطر حرج). اسم النطاق نفسه يشير إلى نية خبيثة.",
    hi: "गंभीर: इस डोमेन में आमतौर पर फ़िशिंग या मैलवेयर से जुड़े कीवर्ड हैं (गंभीर जोखिम)। डोमेन नाम स्वयं दुर्भावनापूर्ण इरादे का सुझाव देता है।",
    th: "วิกฤต: โดเมนนี้มีคำหลักที่มักเกี่ยวข้องกับฟิชชิงหรือมัลแวร์ (ความเสี่ยงวิกฤต) ชื่อโดเมนเองบ่งบอกถึงเจตนาร้าย",
    vi: "NGHIÊM TRỌNG: Tên miền này chứa các từ khóa thường liên quan đến lừa đảo hoặc phần mềm độc hại (rủi ro nghiêm trọng). Tên miền cho thấy ý định độc hại.",
    id: "KRITIS: Domain ini mengandung kata kunci yang umumnya terkait dengan phishing atau malware (risiko kritis). Nama domain itu sendiri menunjukkan niat jahat.",
    ja: "重大: このドメインには、フィッシングやマルウェアに一般的に関連するキーワードが含まれています（重大リスク）。ドメイン名自体が悪意のある意図を示唆しています。",
    ko: "심각: 이 도메인에는 피싱 또는 맬웨어와 일반적으로 관련된 키워드가 포함되어 있습니다(심각한 위험). 도메인 이름 자체가 악의적인 의도를 나타냅니다.",
    zh: "严重：此域名包含通常与钓鱼或恶意软件相关的关键词（严重风险）。域名本身暗示了恶意意图。"
  }
};

// Get all locale directories (excluding temp files)
const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && !f.startsWith('tmpclaude');
});

console.log(`Found ${locales.length} locales to update`);

let updated = 0;
let skipped = 0;

locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');

  if (!fs.existsSync(messagesPath)) {
    console.log(`Warning: Skipping ${locale}: messages.json not found`);
    return;
  }

  try {
    const content = fs.readFileSync(messagesPath, 'utf8');
    const messages = JSON.parse(content);
    let localeUpdated = false;

    // Add each new key if it doesn't exist
    for (const [key, trans] of Object.entries(translations)) {
      if (!messages[key]) {
        messages[key] = {
          message: trans[locale] || trans['en']
        };
        localeUpdated = true;
        console.log(`  + ${locale}: Added ${key}`);
      }
    }

    if (localeUpdated) {
      fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n');
      console.log(`UPDATED ${locale}`);
      updated++;
    } else {
      console.log(`OK ${locale}: All keys present`);
      skipped++;
    }

  } catch (err) {
    console.error(`ERROR ${locale}: ${err.message}`);
  }
});

console.log(`\nSummary: ${updated} locales updated, ${skipped} already up-to-date`);
