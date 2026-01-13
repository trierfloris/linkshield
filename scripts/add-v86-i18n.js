/**
 * Add v8.6.0 i18n keys for new security features
 * - Unicode detection expansions
 * - Fail-safe fresh install notification
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

const newKeys = {
  // New Unicode detection keys
  enclosedAlphanumericsDetected: {
    en: "This domain contains enclosed alphanumeric characters (high risk). Characters like ①②③ or ⓐⓑⓒ are used to create lookalike domains for phishing.",
    nl: "Dit domein bevat omsloten alfanumerieke tekens (hoog risico). Tekens zoals ①②③ of ⓐⓑⓒ worden gebruikt om lookalike-domeinen voor phishing te maken.",
    de: "Diese Domain enthält umschlossene alphanumerische Zeichen (hohes Risiko). Zeichen wie ①②③ oder ⓐⓑⓒ werden verwendet, um ähnlich aussehende Domains für Phishing zu erstellen.",
    fr: "Ce domaine contient des caractères alphanumériques encerclés (risque élevé). Des caractères comme ①②③ ou ⓐⓑⓒ sont utilisés pour créer des domaines similaires pour le phishing.",
    es: "Este dominio contiene caracteres alfanuméricos encerrados (alto riesgo). Caracteres como ①②③ o ⓐⓑⓒ se usan para crear dominios similares para phishing.",
    it: "Questo dominio contiene caratteri alfanumerici racchiusi (alto rischio). Caratteri come ①②③ o ⓐⓑⓒ vengono usati per creare domini simili per il phishing.",
    pt: "Este domínio contém caracteres alfanuméricos inclusos (alto risco). Caracteres como ①②③ ou ⓐⓑⓒ são usados para criar domínios semelhantes para phishing.",
    pt_BR: "Este domínio contém caracteres alfanuméricos inclusos (alto risco). Caracteres como ①②③ ou ⓐⓑⓒ são usados para criar domínios semelhantes para phishing.",
    ru: "Этот домен содержит заключённые в круг буквенно-цифровые символы (высокий риск). Символы вроде ①②③ или ⓐⓑⓒ используются для создания похожих доменов для фишинга.",
    ja: "このドメインには囲み英数字が含まれています（高リスク）。①②③やⓐⓑⓒのような文字はフィッシング用の偽ドメイン作成に使用されます。",
    ko: "이 도메인에는 동그라미 영숫자가 포함되어 있습니다(높은 위험). ①②③ 또는 ⓐⓑⓒ와 같은 문자는 피싱용 유사 도메인을 만드는 데 사용됩니다.",
    zh: "此域名包含带圈字母数字（高风险）。①②③或ⓐⓑⓒ等字符被用于创建钓鱼用的相似域名。",
    ar: "يحتوي هذا النطاق على أحرف أبجدية رقمية محاطة (خطر عالٍ). تُستخدم أحرف مثل ①②③ أو ⓐⓑⓒ لإنشاء نطاقات مشابهة للتصيد الاحتيالي.",
    hi: "इस डोमेन में घेरे में अक्षरांकीय वर्ण हैं (उच्च जोखिम)। ①②③ या ⓐⓑⓒ जैसे वर्णों का उपयोग फ़िशिंग के लिए समान डोमेन बनाने के लिए किया जाता है।",
    th: "โดเมนนี้มีตัวอักษรและตัวเลขในวงกลม (ความเสี่ยงสูง) ตัวอักษรเช่น ①②③ หรือ ⓐⓑⓒ ถูกใช้สร้างโดเมนที่คล้ายกันเพื่อฟิชชิ่ง",
    vi: "Tên miền này chứa các ký tự chữ số trong vòng tròn (rủi ro cao). Các ký tự như ①②③ hoặc ⓐⓑⓒ được sử dụng để tạo tên miền giả mạo để lừa đảo.",
    tr: "Bu alan adı çevrelenmiş alfasayısal karakterler içeriyor (yüksek risk). ①②③ veya ⓐⓑⓒ gibi karakterler kimlik avı için benzer alan adları oluşturmak için kullanılır.",
    pl: "Ta domena zawiera zamknięte w kółka znaki alfanumeryczne (wysokie ryzyko). Znaki takie jak ①②③ lub ⓐⓑⓒ są używane do tworzenia podobnych domen do phishingu.",
    uk: "Цей домен містить обведені алфавітно-цифрові символи (високий ризик). Символи на кшталт ①②③ або ⓐⓑⓒ використовуються для створення схожих доменів для фішингу.",
    cs: "Tato doména obsahuje uzavřené alfanumerické znaky (vysoké riziko). Znaky jako ①②③ nebo ⓐⓑⓒ se používají k vytváření podobných domén pro phishing.",
    el: "Αυτός ο τομέας περιέχει αλφαριθμητικούς χαρακτήρες σε κύκλο (υψηλός κίνδυνος). Χαρακτήρες όπως ①②③ ή ⓐⓑⓒ χρησιμοποιούνται για τη δημιουργία παρόμοιων τομέων για phishing.",
    hu: "Ez a domain bekerített alfanumerikus karaktereket tartalmaz (magas kockázat). Az olyan karakterek, mint ①②③ vagy ⓐⓑⓒ, hasonló domainek létrehozására használatosak adathalászathoz.",
    ro: "Acest domeniu conține caractere alfanumerice încercuite (risc ridicat). Caractere precum ①②③ sau ⓐⓑⓒ sunt folosite pentru a crea domenii similare pentru phishing.",
    id: "Domain ini berisi karakter alfanumerik dalam lingkaran (risiko tinggi). Karakter seperti ①②③ atau ⓐⓑⓒ digunakan untuk membuat domain serupa untuk phishing."
  },
  superscriptSubscriptDetected: {
    en: "This domain contains superscript or subscript characters (high risk). Characters like ¹²³ or ₀₁₂ are used to create deceptive lookalike domains.",
    nl: "Dit domein bevat superscript of subscript tekens (hoog risico). Tekens zoals ¹²³ of ₀₁₂ worden gebruikt om misleidende lookalike-domeinen te maken.",
    de: "Diese Domain enthält hoch- oder tiefgestellte Zeichen (hohes Risiko). Zeichen wie ¹²³ oder ₀₁₂ werden verwendet, um täuschend ähnliche Domains zu erstellen.",
    fr: "Ce domaine contient des caractères en exposant ou en indice (risque élevé). Des caractères comme ¹²³ ou ₀₁₂ sont utilisés pour créer des domaines trompeurs similaires.",
    es: "Este dominio contiene caracteres en superíndice o subíndice (alto riesgo). Caracteres como ¹²³ o ₀₁₂ se usan para crear dominios engañosos similares.",
    it: "Questo dominio contiene caratteri apice o pedice (alto rischio). Caratteri come ¹²³ o ₀₁₂ vengono usati per creare domini ingannevoli simili.",
    pt: "Este domínio contém caracteres sobrescritos ou subscritos (alto risco). Caracteres como ¹²³ ou ₀₁₂ são usados para criar domínios enganosos semelhantes.",
    pt_BR: "Este domínio contém caracteres sobrescritos ou subscritos (alto risco). Caracteres como ¹²³ ou ₀₁₂ são usados para criar domínios enganosos semelhantes.",
    ru: "Этот домен содержит надстрочные или подстрочные символы (высокий риск). Символы вроде ¹²³ или ₀₁₂ используются для создания обманчиво похожих доменов.",
    ja: "このドメインには上付きまたは下付き文字が含まれています（高リスク）。¹²³や₀₁₂のような文字は欺瞞的な偽ドメイン作成に使用されます。",
    ko: "이 도메인에는 위 첨자 또는 아래 첨자 문자가 포함되어 있습니다(높은 위험). ¹²³ 또는 ₀₁₂와 같은 문자는 기만적인 유사 도메인을 만드는 데 사용됩니다.",
    zh: "此域名包含上标或下标字符（高风险）。¹²³或₀₁₂等字符被用于创建欺骗性的相似域名。",
    ar: "يحتوي هذا النطاق على أحرف مرتفعة أو منخفضة (خطر عالٍ). تُستخدم أحرف مثل ¹²³ أو ₀₁₂ لإنشاء نطاقات مخادعة مشابهة.",
    hi: "इस डोमेन में सुपरस्क्रिप्ट या सबस्क्रिप्ट वर्ण हैं (उच्च जोखिम)। ¹²³ या ₀₁₂ जैसे वर्णों का उपयोग भ्रामक समान डोमेन बनाने के लिए किया जाता है।",
    th: "โดเมนนี้มีตัวอักษรยกหรือห้อย (ความเสี่ยงสูง) ตัวอักษรเช่น ¹²³ หรือ ₀₁₂ ถูกใช้สร้างโดเมนหลอกลวงที่คล้ายกัน",
    vi: "Tên miền này chứa các ký tự chỉ số trên hoặc dưới (rủi ro cao). Các ký tự như ¹²³ hoặc ₀₁₂ được sử dụng để tạo tên miền giả mạo đánh lừa.",
    tr: "Bu alan adı üst simge veya alt simge karakterler içeriyor (yüksek risk). ¹²³ veya ₀₁₂ gibi karakterler aldatıcı benzer alan adları oluşturmak için kullanılır.",
    pl: "Ta domena zawiera znaki w indeksie górnym lub dolnym (wysokie ryzyko). Znaki takie jak ¹²³ lub ₀₁₂ są używane do tworzenia mylących podobnych domen.",
    uk: "Цей домен містить надрядкові або підрядкові символи (високий ризик). Символи на кшталт ¹²³ або ₀₁₂ використовуються для створення оманливо схожих доменів.",
    cs: "Tato doména obsahuje horní nebo dolní indexové znaky (vysoké riziko). Znaky jako ¹²³ nebo ₀₁₂ se používají k vytváření klamavých podobných domén.",
    el: "Αυτός ο τομέας περιέχει εκθέτες ή δείκτες (υψηλός κίνδυνος). Χαρακτήρες όπως ¹²³ ή ₀₁₂ χρησιμοποιούνται για τη δημιουργία παραπλανητικά παρόμοιων τομέων.",
    hu: "Ez a domain felső vagy alsó indexű karaktereket tartalmaz (magas kockázat). Az olyan karakterek, mint ¹²³ vagy ₀₁₂, megtévesztő hasonló domainek létrehozására használatosak.",
    ro: "Acest domeniu conține caractere superscript sau subscript (risc ridicat). Caractere precum ¹²³ sau ₀₁₂ sunt folosite pentru a crea domenii înșelătoare similare.",
    id: "Domain ini berisi karakter superskrip atau subskrip (risiko tinggi). Karakter seperti ¹²³ atau ₀₁₂ digunakan untuk membuat domain serupa yang menipu."
  },
  numberFormsDetected: {
    en: "This domain contains number form characters (medium risk). Characters like ⅓, ⅔, or Roman numerals can be used to create confusing domain names.",
    nl: "Dit domein bevat getalvorm-tekens (gemiddeld risico). Tekens zoals ⅓, ⅔ of Romeinse cijfers kunnen worden gebruikt om verwarrende domeinnamen te maken.",
    de: "Diese Domain enthält Zahlenformzeichen (mittleres Risiko). Zeichen wie ⅓, ⅔ oder römische Ziffern können verwendet werden, um verwirrende Domainnamen zu erstellen.",
    fr: "Ce domaine contient des caractères de forme numérique (risque moyen). Des caractères comme ⅓, ⅔ ou des chiffres romains peuvent être utilisés pour créer des noms de domaine confus.",
    es: "Este dominio contiene caracteres de forma numérica (riesgo medio). Caracteres como ⅓, ⅔ o números romanos pueden usarse para crear nombres de dominio confusos.",
    it: "Questo dominio contiene caratteri di forma numerica (rischio medio). Caratteri come ⅓, ⅔ o numeri romani possono essere usati per creare nomi di dominio confusi.",
    pt: "Este domínio contém caracteres de forma numérica (risco médio). Caracteres como ⅓, ⅔ ou numerais romanos podem ser usados para criar nomes de domínio confusos.",
    pt_BR: "Este domínio contém caracteres de forma numérica (risco médio). Caracteres como ⅓, ⅔ ou numerais romanos podem ser usados para criar nomes de domínio confusos.",
    ru: "Этот домен содержит символы числовых форм (средний риск). Символы вроде ⅓, ⅔ или римские цифры могут использоваться для создания запутанных доменных имён.",
    ja: "このドメインには数字形式の文字が含まれています（中リスク）。⅓、⅔、ローマ数字などは紛らわしいドメイン名の作成に使用される可能性があります。",
    ko: "이 도메인에는 숫자 형식 문자가 포함되어 있습니다(중간 위험). ⅓, ⅔ 또는 로마 숫자와 같은 문자는 혼란스러운 도메인 이름을 만드는 데 사용될 수 있습니다.",
    zh: "此域名包含数字形式字符（中等风险）。⅓、⅔或罗马数字等字符可用于创建令人困惑的域名。",
    ar: "يحتوي هذا النطاق على أحرف شكل الأرقام (خطر متوسط). يمكن استخدام أحرف مثل ⅓ أو ⅔ أو الأرقام الرومانية لإنشاء أسماء نطاقات مربكة.",
    hi: "इस डोमेन में संख्या रूप वर्ण हैं (मध्यम जोखिम)। ⅓, ⅔ या रोमन अंक जैसे वर्णों का उपयोग भ्रामक डोमेन नाम बनाने के लिए किया जा सकता है।",
    th: "โดเมนนี้มีตัวอักษรรูปแบบตัวเลข (ความเสี่ยงปานกลาง) ตัวอักษรเช่น ⅓, ⅔ หรือเลขโรมันสามารถใช้สร้างชื่อโดเมนที่สับสน",
    vi: "Tên miền này chứa các ký tự dạng số (rủi ro trung bình). Các ký tự như ⅓, ⅔ hoặc chữ số La Mã có thể được sử dụng để tạo tên miền gây nhầm lẫn.",
    tr: "Bu alan adı sayı formu karakterleri içeriyor (orta risk). ⅓, ⅔ veya Roma rakamları gibi karakterler kafa karıştırıcı alan adları oluşturmak için kullanılabilir.",
    pl: "Ta domena zawiera znaki form liczbowych (średnie ryzyko). Znaki takie jak ⅓, ⅔ lub cyfry rzymskie mogą być używane do tworzenia mylących nazw domen.",
    uk: "Цей домен містить символи числових форм (середній ризик). Символи на кшталт ⅓, ⅔ або римські цифри можуть використовуватися для створення заплутаних доменних імен.",
    cs: "Tato doména obsahuje znaky číselných forem (střední riziko). Znaky jako ⅓, ⅔ nebo římské číslice mohou být použity k vytváření matoucích doménových jmen.",
    el: "Αυτός ο τομέας περιέχει χαρακτήρες μορφής αριθμών (μέτριος κίνδυνος). Χαρακτήρες όπως ⅓, ⅔ ή ρωμαϊκοί αριθμοί μπορούν να χρησιμοποιηθούν για τη δημιουργία συγκεχυμένων ονομάτων τομέα.",
    hu: "Ez a domain számformátum karaktereket tartalmaz (közepes kockázat). Az olyan karakterek, mint ⅓, ⅔ vagy római számok, zavaró domanevek létrehozására használhatók.",
    ro: "Acest domeniu conține caractere de formă numerică (risc mediu). Caractere precum ⅓, ⅔ sau cifre romane pot fi folosite pentru a crea nume de domenii confuze.",
    id: "Domain ini berisi karakter bentuk angka (risiko sedang). Karakter seperti ⅓, ⅔, atau angka Romawi dapat digunakan untuk membuat nama domain yang membingungkan."
  },
  nonAsciiCharactersDetected: {
    en: "This domain contains non-ASCII characters (medium risk). Special characters outside the standard alphabet may indicate an attempt to deceive users.",
    nl: "Dit domein bevat niet-ASCII-tekens (gemiddeld risico). Speciale tekens buiten het standaardalfabet kunnen duiden op een poging om gebruikers te misleiden.",
    de: "Diese Domain enthält Nicht-ASCII-Zeichen (mittleres Risiko). Sonderzeichen außerhalb des Standardalphabets können auf einen Täuschungsversuch hinweisen.",
    fr: "Ce domaine contient des caractères non-ASCII (risque moyen). Les caractères spéciaux en dehors de l'alphabet standard peuvent indiquer une tentative de tromper les utilisateurs.",
    es: "Este dominio contiene caracteres no ASCII (riesgo medio). Los caracteres especiales fuera del alfabeto estándar pueden indicar un intento de engañar a los usuarios.",
    it: "Questo dominio contiene caratteri non-ASCII (rischio medio). I caratteri speciali al di fuori dell'alfabeto standard potrebbero indicare un tentativo di ingannare gli utenti.",
    pt: "Este domínio contém caracteres não-ASCII (risco médio). Caracteres especiais fora do alfabeto padrão podem indicar uma tentativa de enganar os usuários.",
    pt_BR: "Este domínio contém caracteres não-ASCII (risco médio). Caracteres especiais fora do alfabeto padrão podem indicar uma tentativa de enganar os usuários.",
    ru: "Этот домен содержит не-ASCII символы (средний риск). Специальные символы за пределами стандартного алфавита могут указывать на попытку обмана пользователей.",
    ja: "このドメインには非ASCII文字が含まれています（中リスク）。標準アルファベット外の特殊文字はユーザーを欺く試みを示す可能性があります。",
    ko: "이 도메인에는 비ASCII 문자가 포함되어 있습니다(중간 위험). 표준 알파벳 이외의 특수 문자는 사용자를 속이려는 시도를 나타낼 수 있습니다.",
    zh: "此域名包含非ASCII字符（中等风险）。标准字母表之外的特殊字符可能表示试图欺骗用户。",
    ar: "يحتوي هذا النطاق على أحرف غير ASCII (خطر متوسط). قد تشير الأحرف الخاصة خارج الأبجدية القياسية إلى محاولة لخداع المستخدمين.",
    hi: "इस डोमेन में गैर-ASCII वर्ण हैं (मध्यम जोखिम)। मानक वर्णमाला के बाहर के विशेष वर्ण उपयोगकर्ताओं को धोखा देने के प्रयास का संकेत दे सकते हैं।",
    th: "โดเมนนี้มีตัวอักษรที่ไม่ใช่ ASCII (ความเสี่ยงปานกลาง) ตัวอักษรพิเศษนอกตัวอักษรมาตรฐานอาจบ่งชี้ถึงความพยายามหลอกลวงผู้ใช้",
    vi: "Tên miền này chứa các ký tự không phải ASCII (rủi ro trung bình). Các ký tự đặc biệt ngoài bảng chữ cái tiêu chuẩn có thể cho thấy ý định lừa đảo người dùng.",
    tr: "Bu alan adı ASCII olmayan karakterler içeriyor (orta risk). Standart alfabe dışındaki özel karakterler kullanıcıları aldatma girişimini gösterebilir.",
    pl: "Ta domena zawiera znaki spoza ASCII (średnie ryzyko). Znaki specjalne spoza standardowego alfabetu mogą wskazywać na próbę oszukania użytkowników.",
    uk: "Цей домен містить не-ASCII символи (середній ризик). Спеціальні символи за межами стандартного алфавіту можуть вказувати на спробу обману користувачів.",
    cs: "Tato doména obsahuje ne-ASCII znaky (střední riziko). Speciální znaky mimo standardní abecedu mohou naznačovat pokus o oklamání uživatelů.",
    el: "Αυτός ο τομέας περιέχει χαρακτήρες μη-ASCII (μέτριος κίνδυνος). Ειδικοί χαρακτήρες εκτός του τυπικού αλφαβήτου μπορεί να υποδεικνύουν προσπάθεια εξαπάτησης χρηστών.",
    hu: "Ez a domain nem-ASCII karaktereket tartalmaz (közepes kockázat). A szabványos ábécén kívüli speciális karakterek felhasználók megtévesztésére irányuló kísérletre utalhatnak.",
    ro: "Acest domeniu conține caractere non-ASCII (risc mediu). Caracterele speciale din afara alfabetului standard pot indica o încercare de a înșela utilizatorii.",
    id: "Domain ini berisi karakter non-ASCII (risiko sedang). Karakter khusus di luar alfabet standar mungkin menunjukkan upaya untuk menipu pengguna."
  },
  failSafeFreshInstallTitle: {
    en: "Protection Enabled",
    nl: "Bescherming ingeschakeld",
    de: "Schutz aktiviert",
    fr: "Protection activée",
    es: "Protección habilitada",
    it: "Protezione abilitata",
    pt: "Proteção ativada",
    pt_BR: "Proteção ativada",
    ru: "Защита включена",
    ja: "保護が有効",
    ko: "보호 활성화됨",
    zh: "保护已启用",
    ar: "تم تفعيل الحماية",
    hi: "सुरक्षा सक्षम",
    th: "เปิดใช้งานการป้องกัน",
    vi: "Đã bật bảo vệ",
    tr: "Koruma etkinleştirildi",
    pl: "Ochrona włączona",
    uk: "Захист увімкнено",
    cs: "Ochrana povolena",
    el: "Η προστασία ενεργοποιήθηκε",
    hu: "Védelem engedélyezve",
    ro: "Protecție activată",
    id: "Perlindungan diaktifkan"
  },
  failSafeFreshInstallMessage: {
    en: "LinkShield protection is active. Please verify your license when possible.",
    nl: "LinkShield-bescherming is actief. Verifieer uw licentie wanneer mogelijk.",
    de: "LinkShield-Schutz ist aktiv. Bitte verifizieren Sie Ihre Lizenz wenn möglich.",
    fr: "La protection LinkShield est active. Veuillez vérifier votre licence dès que possible.",
    es: "La protección de LinkShield está activa. Por favor verifique su licencia cuando sea posible.",
    it: "La protezione LinkShield è attiva. Si prega di verificare la licenza quando possibile.",
    pt: "A proteção LinkShield está ativa. Por favor, verifique sua licença quando possível.",
    pt_BR: "A proteção LinkShield está ativa. Por favor, verifique sua licença quando possível.",
    ru: "Защита LinkShield активна. Пожалуйста, подтвердите лицензию при возможности.",
    ja: "LinkShield保護がアクティブです。可能な場合はライセンスを確認してください。",
    ko: "LinkShield 보호가 활성화되었습니다. 가능할 때 라이선스를 확인해 주세요.",
    zh: "LinkShield保护已激活。请在可能时验证您的许可证。",
    ar: "حماية LinkShield نشطة. يرجى التحقق من ترخيصك عندما يكون ذلك ممكنًا.",
    hi: "LinkShield सुरक्षा सक्रिय है। कृपया संभव होने पर अपना लाइसेंस सत्यापित करें।",
    th: "การป้องกัน LinkShield ทำงานอยู่ กรุณาตรวจสอบใบอนุญาตของคุณเมื่อเป็นไปได้",
    vi: "Bảo vệ LinkShield đang hoạt động. Vui lòng xác minh giấy phép của bạn khi có thể.",
    tr: "LinkShield koruması aktif. Lütfen mümkün olduğunda lisansınızı doğrulayın.",
    pl: "Ochrona LinkShield jest aktywna. Proszę zweryfikować licencję, gdy to możliwe.",
    uk: "Захист LinkShield активний. Будь ласка, підтвердіть ліцензію, коли це можливо.",
    cs: "Ochrana LinkShield je aktivní. Prosím ověřte svou licenci, když to bude možné.",
    el: "Η προστασία LinkShield είναι ενεργή. Παρακαλώ επιβεβαιώστε την άδειά σας όταν είναι δυνατόν.",
    hu: "A LinkShield védelem aktív. Kérjük, ellenőrizze licencét, amikor lehetséges.",
    ro: "Protecția LinkShield este activă. Vă rugăm să verificați licența când este posibil.",
    id: "Perlindungan LinkShield aktif. Mohon verifikasi lisensi Anda bila memungkinkan."
  }
};

const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory();
});

console.log(`Found ${locales.length} locales to update`);

let updated = 0;
let alreadyUpToDate = 0;

locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');
  if (!fs.existsSync(messagesPath)) {
    console.log(`SKIP ${locale}: messages.json not found`);
    return;
  }

  let messages;
  try {
    messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));
  } catch (e) {
    console.log(`ERROR ${locale}: Could not parse messages.json`);
    return;
  }

  let changed = false;
  for (const [key, translations] of Object.entries(newKeys)) {
    if (!messages[key]) {
      const translation = translations[locale] || translations.en;
      messages[key] = { message: translation };
      console.log(`  + ${locale}: Added ${key}`);
      changed = true;
    }
  }

  if (changed) {
    fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');
    console.log(`UPDATED ${locale}`);
    updated++;
  } else {
    console.log(`OK ${locale}: All keys present`);
    alreadyUpToDate++;
  }
});

console.log(`\nSummary: ${updated} locales updated, ${alreadyUpToDate} already up-to-date`);
