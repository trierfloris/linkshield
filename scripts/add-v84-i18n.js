/**
 * Script to add v8.4.0 security i18n keys to all locale files
 * Adds: dataUriBlocked, javascriptUriBlocked, vbscriptUriBlocked, blobUriBlocked,
 *       mathematicalCharsDetected, greekCharsDetected, scriptCharsDetected, digitInDomainDetected
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

// Translations for all 24 locales
const translations = {
  en: {
    dataUriBlocked: "CRITICAL: This link contains a data: URI (critical risk). Data URIs can embed and execute malicious content directly in your browser. This is a common attack vector for phishing and malware delivery.",
    javascriptUriBlocked: "CRITICAL: This link contains a javascript: URI (critical risk). JavaScript URIs can execute arbitrary code in your browser context, potentially stealing your data or credentials.",
    vbscriptUriBlocked: "CRITICAL: This link contains a vbscript: URI (critical risk). VBScript URIs can execute dangerous code targeting Windows systems. This is a serious security threat.",
    blobUriBlocked: "CRITICAL: This link contains a blob: URI (critical risk). Blob URIs can execute arbitrary code or deliver malware. This link has been blocked for your protection.",
    mathematicalCharsDetected: "This domain contains Mathematical Unicode characters (high risk). Mathematical symbols that look like regular letters (like bold or italic variants) are being used to impersonate a legitimate website.",
    greekCharsDetected: "This domain contains Greek characters mixed with Latin letters (high risk). Greek letters like omicron and nu look identical to Latin 'o' and 'v', making this a potential spoofing attack.",
    scriptCharsDetected: "This domain contains Letterlike Symbols (high risk). Special Unicode script characters are being used to impersonate a legitimate website.",
    digitInDomainDetected: "This domain uses digit substitution to impersonate a known brand (high risk). Numbers like 0, 1, 3, 5 are used to replace letters (e.g., g00gle, paypa1, amaz0n)."
  },
  nl: {
    dataUriBlocked: "KRITIEK: Deze link bevat een data: URI (kritiek risico). Data-URI's kunnen schadelijke inhoud direct in uw browser uitvoeren. Dit is een veelgebruikte aanvalstechniek voor phishing en malware.",
    javascriptUriBlocked: "KRITIEK: Deze link bevat een javascript: URI (kritiek risico). JavaScript-URI's kunnen willekeurige code uitvoeren in uw browsercontext, waardoor uw gegevens of inloggegevens kunnen worden gestolen.",
    vbscriptUriBlocked: "KRITIEK: Deze link bevat een vbscript: URI (kritiek risico). VBScript-URI's kunnen gevaarlijke code uitvoeren op Windows-systemen. Dit is een ernstige beveiligingsdreiging.",
    blobUriBlocked: "KRITIEK: Deze link bevat een blob: URI (kritiek risico). Blob-URI's kunnen willekeurige code uitvoeren of malware afleveren. Deze link is geblokkeerd voor uw bescherming.",
    mathematicalCharsDetected: "Dit domein bevat wiskundige Unicode-tekens (hoog risico). Wiskundige symbolen die eruitzien als normale letters worden gebruikt om een legitieme website na te bootsen.",
    greekCharsDetected: "Dit domein bevat Griekse letters gemengd met Latijnse letters (hoog risico). Griekse letters zoals omicron en nu zien er identiek uit aan Latijnse 'o' en 'v', wat dit een mogelijke spoofing-aanval maakt.",
    scriptCharsDetected: "Dit domein bevat letterachtige symbolen (hoog risico). Speciale Unicode-scripttekens worden gebruikt om een legitieme website na te bootsen.",
    digitInDomainDetected: "Dit domein gebruikt cijfervervanging om een bekend merk na te bootsen (hoog risico). Cijfers zoals 0, 1, 3, 5 worden gebruikt ter vervanging van letters (bijv. g00gle, paypa1, amaz0n)."
  },
  de: {
    dataUriBlocked: "KRITISCH: Dieser Link enthält eine data: URI (kritisches Risiko). Data-URIs können schädliche Inhalte direkt in Ihrem Browser ausführen. Dies ist ein häufiger Angriffsvektor für Phishing und Malware.",
    javascriptUriBlocked: "KRITISCH: Dieser Link enthält eine javascript: URI (kritisches Risiko). JavaScript-URIs können beliebigen Code in Ihrem Browser-Kontext ausführen und möglicherweise Ihre Daten oder Zugangsdaten stehlen.",
    vbscriptUriBlocked: "KRITISCH: Dieser Link enthält eine vbscript: URI (kritisches Risiko). VBScript-URIs können gefährlichen Code auf Windows-Systemen ausführen. Dies ist eine ernsthafte Sicherheitsbedrohung.",
    blobUriBlocked: "KRITISCH: Dieser Link enthält eine blob: URI (kritisches Risiko). Blob-URIs können beliebigen Code ausführen oder Malware verbreiten. Dieser Link wurde zu Ihrem Schutz blockiert.",
    mathematicalCharsDetected: "Diese Domain enthält mathematische Unicode-Zeichen (hohes Risiko). Mathematische Symbole, die wie normale Buchstaben aussehen, werden verwendet, um eine legitime Website zu imitieren.",
    greekCharsDetected: "Diese Domain enthält griechische Buchstaben gemischt mit lateinischen Buchstaben (hohes Risiko). Griechische Buchstaben wie Omikron und Nu sehen identisch aus wie die lateinischen 'o' und 'v', was dies zu einem potenziellen Spoofing-Angriff macht.",
    scriptCharsDetected: "Diese Domain enthält buchstabenähnliche Symbole (hohes Risiko). Spezielle Unicode-Skriptzeichen werden verwendet, um eine legitime Website zu imitieren.",
    digitInDomainDetected: "Diese Domain verwendet Ziffernersetzung, um eine bekannte Marke zu imitieren (hohes Risiko). Zahlen wie 0, 1, 3, 5 werden anstelle von Buchstaben verwendet (z.B. g00gle, paypa1, amaz0n)."
  },
  fr: {
    dataUriBlocked: "CRITIQUE: Ce lien contient une URI data: (risque critique). Les URI data: peuvent exécuter du contenu malveillant directement dans votre navigateur. C'est un vecteur d'attaque courant pour le phishing et les malwares.",
    javascriptUriBlocked: "CRITIQUE: Ce lien contient une URI javascript: (risque critique). Les URI JavaScript peuvent exécuter du code arbitraire dans le contexte de votre navigateur, pouvant voler vos données ou identifiants.",
    vbscriptUriBlocked: "CRITIQUE: Ce lien contient une URI vbscript: (risque critique). Les URI VBScript peuvent exécuter du code dangereux sur les systèmes Windows. C'est une menace de sécurité sérieuse.",
    blobUriBlocked: "CRITIQUE: Ce lien contient une URI blob: (risque critique). Les URI blob peuvent exécuter du code arbitraire ou distribuer des malwares. Ce lien a été bloqué pour votre protection.",
    mathematicalCharsDetected: "Ce domaine contient des caractères Unicode mathématiques (risque élevé). Des symboles mathématiques ressemblant à des lettres normales sont utilisés pour imiter un site web légitime.",
    greekCharsDetected: "Ce domaine contient des caractères grecs mélangés avec des lettres latines (risque élevé). Les lettres grecques comme omicron et nu sont identiques aux 'o' et 'v' latins, ce qui en fait une potentielle attaque de spoofing.",
    scriptCharsDetected: "Ce domaine contient des symboles de type lettre (risque élevé). Des caractères Unicode de script spéciaux sont utilisés pour imiter un site web légitime.",
    digitInDomainDetected: "Ce domaine utilise la substitution de chiffres pour imiter une marque connue (risque élevé). Les chiffres comme 0, 1, 3, 5 sont utilisés à la place des lettres (ex: g00gle, paypa1, amaz0n)."
  },
  es: {
    dataUriBlocked: "CRÍTICO: Este enlace contiene una URI data: (riesgo crítico). Las URI data: pueden ejecutar contenido malicioso directamente en su navegador. Este es un vector de ataque común para phishing y malware.",
    javascriptUriBlocked: "CRÍTICO: Este enlace contiene una URI javascript: (riesgo crítico). Las URI JavaScript pueden ejecutar código arbitrario en el contexto de su navegador, potencialmente robando sus datos o credenciales.",
    vbscriptUriBlocked: "CRÍTICO: Este enlace contiene una URI vbscript: (riesgo crítico). Las URI VBScript pueden ejecutar código peligroso en sistemas Windows. Esta es una amenaza de seguridad seria.",
    blobUriBlocked: "CRÍTICO: Este enlace contiene una URI blob: (riesgo crítico). Las URI blob pueden ejecutar código arbitrario o distribuir malware. Este enlace ha sido bloqueado para su protección.",
    mathematicalCharsDetected: "Este dominio contiene caracteres Unicode matemáticos (alto riesgo). Símbolos matemáticos que parecen letras normales se están usando para suplantar un sitio web legítimo.",
    greekCharsDetected: "Este dominio contiene caracteres griegos mezclados con letras latinas (alto riesgo). Las letras griegas como omicron y nu son idénticas a las 'o' y 'v' latinas, lo que lo convierte en un potencial ataque de suplantación.",
    scriptCharsDetected: "Este dominio contiene símbolos de tipo letra (alto riesgo). Caracteres Unicode de script especiales se están usando para suplantar un sitio web legítimo.",
    digitInDomainDetected: "Este dominio usa sustitución de dígitos para suplantar una marca conocida (alto riesgo). Números como 0, 1, 3, 5 se usan en lugar de letras (ej: g00gle, paypa1, amaz0n)."
  },
  it: {
    dataUriBlocked: "CRITICO: Questo link contiene un URI data: (rischio critico). Gli URI data: possono eseguire contenuti dannosi direttamente nel tuo browser. Questo è un vettore di attacco comune per phishing e malware.",
    javascriptUriBlocked: "CRITICO: Questo link contiene un URI javascript: (rischio critico). Gli URI JavaScript possono eseguire codice arbitrario nel contesto del tuo browser, potenzialmente rubando i tuoi dati o credenziali.",
    vbscriptUriBlocked: "CRITICO: Questo link contiene un URI vbscript: (rischio critico). Gli URI VBScript possono eseguire codice pericoloso sui sistemi Windows. Questa è una seria minaccia alla sicurezza.",
    blobUriBlocked: "CRITICO: Questo link contiene un URI blob: (rischio critico). Gli URI blob possono eseguire codice arbitrario o distribuire malware. Questo link è stato bloccato per la tua protezione.",
    mathematicalCharsDetected: "Questo dominio contiene caratteri Unicode matematici (alto rischio). Simboli matematici che sembrano lettere normali vengono utilizzati per impersonare un sito web legittimo.",
    greekCharsDetected: "Questo dominio contiene caratteri greci mescolati con lettere latine (alto rischio). Le lettere greche come omicron e nu sono identiche alle 'o' e 'v' latine, rendendolo un potenziale attacco di spoofing.",
    scriptCharsDetected: "Questo dominio contiene simboli simili a lettere (alto rischio). Caratteri Unicode di script speciali vengono utilizzati per impersonare un sito web legittimo.",
    digitInDomainDetected: "Questo dominio usa la sostituzione di cifre per impersonare un marchio noto (alto rischio). Numeri come 0, 1, 3, 5 vengono usati al posto delle lettere (es: g00gle, paypa1, amaz0n)."
  },
  pt: {
    dataUriBlocked: "CRÍTICO: Este link contém uma URI data: (risco crítico). URIs data: podem executar conteúdo malicioso diretamente no seu navegador. Este é um vetor de ataque comum para phishing e malware.",
    javascriptUriBlocked: "CRÍTICO: Este link contém uma URI javascript: (risco crítico). URIs JavaScript podem executar código arbitrário no contexto do seu navegador, potencialmente roubando seus dados ou credenciais.",
    vbscriptUriBlocked: "CRÍTICO: Este link contém uma URI vbscript: (risco crítico). URIs VBScript podem executar código perigoso em sistemas Windows. Esta é uma ameaça de segurança séria.",
    blobUriBlocked: "CRÍTICO: Este link contém uma URI blob: (risco crítico). URIs blob podem executar código arbitrário ou distribuir malware. Este link foi bloqueado para sua proteção.",
    mathematicalCharsDetected: "Este domínio contém caracteres Unicode matemáticos (alto risco). Símbolos matemáticos que parecem letras normais estão sendo usados para imitar um site legítimo.",
    greekCharsDetected: "Este domínio contém caracteres gregos misturados com letras latinas (alto risco). Letras gregas como omicron e nu são idênticas às 'o' e 'v' latinas, tornando isso um potencial ataque de spoofing.",
    scriptCharsDetected: "Este domínio contém símbolos parecidos com letras (alto risco). Caracteres Unicode de script especiais estão sendo usados para imitar um site legítimo.",
    digitInDomainDetected: "Este domínio usa substituição de dígitos para imitar uma marca conhecida (alto risco). Números como 0, 1, 3, 5 são usados no lugar de letras (ex: g00gle, paypa1, amaz0n)."
  },
  pt_BR: {
    dataUriBlocked: "CRÍTICO: Este link contém uma URI data: (risco crítico). URIs data: podem executar conteúdo malicioso diretamente no seu navegador. Este é um vetor de ataque comum para phishing e malware.",
    javascriptUriBlocked: "CRÍTICO: Este link contém uma URI javascript: (risco crítico). URIs JavaScript podem executar código arbitrário no contexto do seu navegador, potencialmente roubando seus dados ou credenciais.",
    vbscriptUriBlocked: "CRÍTICO: Este link contém uma URI vbscript: (risco crítico). URIs VBScript podem executar código perigoso em sistemas Windows. Esta é uma ameaça de segurança séria.",
    blobUriBlocked: "CRÍTICO: Este link contém uma URI blob: (risco crítico). URIs blob podem executar código arbitrário ou distribuir malware. Este link foi bloqueado para sua proteção.",
    mathematicalCharsDetected: "Este domínio contém caracteres Unicode matemáticos (alto risco). Símbolos matemáticos que parecem letras normais estão sendo usados para imitar um site legítimo.",
    greekCharsDetected: "Este domínio contém caracteres gregos misturados com letras latinas (alto risco). Letras gregas como omicron e nu são idênticas às 'o' e 'v' latinas, tornando isso um potencial ataque de spoofing.",
    scriptCharsDetected: "Este domínio contém símbolos parecidos com letras (alto risco). Caracteres Unicode de script especiais estão sendo usados para imitar um site legítimo.",
    digitInDomainDetected: "Este domínio usa substituição de dígitos para imitar uma marca conhecida (alto risco). Números como 0, 1, 3, 5 são usados no lugar de letras (ex: g00gle, paypa1, amaz0n)."
  },
  ru: {
    dataUriBlocked: "КРИТИЧНО: Эта ссылка содержит URI data: (критический риск). URI data: могут выполнять вредоносный контент прямо в вашем браузере. Это распространённый вектор атаки для фишинга и вредоносного ПО.",
    javascriptUriBlocked: "КРИТИЧНО: Эта ссылка содержит URI javascript: (критический риск). URI JavaScript могут выполнять произвольный код в контексте вашего браузера, потенциально похищая ваши данные или учётные данные.",
    vbscriptUriBlocked: "КРИТИЧНО: Эта ссылка содержит URI vbscript: (критический риск). URI VBScript могут выполнять опасный код в системах Windows. Это серьёзная угроза безопасности.",
    blobUriBlocked: "КРИТИЧНО: Эта ссылка содержит URI blob: (критический риск). URI blob могут выполнять произвольный код или распространять вредоносное ПО. Эта ссылка заблокирована для вашей защиты.",
    mathematicalCharsDetected: "Этот домен содержит математические символы Unicode (высокий риск). Математические символы, похожие на обычные буквы, используются для имитации легитимного веб-сайта.",
    greekCharsDetected: "Этот домен содержит греческие буквы, смешанные с латинскими (высокий риск). Греческие буквы, такие как омикрон и ню, идентичны латинским 'o' и 'v', что делает это потенциальной атакой подмены.",
    scriptCharsDetected: "Этот домен содержит буквоподобные символы (высокий риск). Специальные скриптовые символы Unicode используются для имитации легитимного веб-сайта.",
    digitInDomainDetected: "Этот домен использует замену цифр для имитации известного бренда (высокий риск). Цифры 0, 1, 3, 5 используются вместо букв (например, g00gle, paypa1, amaz0n)."
  },
  uk: {
    dataUriBlocked: "КРИТИЧНО: Це посилання містить URI data: (критичний ризик). URI data: можуть виконувати шкідливий вміст безпосередньо у вашому браузері. Це поширений вектор атаки для фішингу та шкідливого ПЗ.",
    javascriptUriBlocked: "КРИТИЧНО: Це посилання містить URI javascript: (критичний ризик). URI JavaScript можуть виконувати довільний код у контексті вашого браузера, потенційно викрадаючи ваші дані або облікові дані.",
    vbscriptUriBlocked: "КРИТИЧНО: Це посилання містить URI vbscript: (критичний ризик). URI VBScript можуть виконувати небезпечний код у системах Windows. Це серйозна загроза безпеці.",
    blobUriBlocked: "КРИТИЧНО: Це посилання містить URI blob: (критичний ризик). URI blob можуть виконувати довільний код або розповсюджувати шкідливе ПЗ. Це посилання заблоковано для вашого захисту.",
    mathematicalCharsDetected: "Цей домен містить математичні символи Unicode (високий ризик). Математичні символи, схожі на звичайні літери, використовуються для імітації легітимного веб-сайту.",
    greekCharsDetected: "Цей домен містить грецькі літери, змішані з латинськими (високий ризик). Грецькі літери, такі як омікрон та ню, ідентичні латинським 'o' та 'v', що робить це потенційною атакою підміни.",
    scriptCharsDetected: "Цей домен містить літероподібні символи (високий ризик). Спеціальні скриптові символи Unicode використовуються для імітації легітимного веб-сайту.",
    digitInDomainDetected: "Цей домен використовує заміну цифр для імітації відомого бренду (високий ризик). Цифри 0, 1, 3, 5 використовуються замість літер (наприклад, g00gle, paypa1, amaz0n)."
  },
  pl: {
    dataUriBlocked: "KRYTYCZNE: Ten link zawiera URI data: (krytyczne ryzyko). URI data: mogą wykonywać złośliwą zawartość bezpośrednio w przeglądarce. To powszechny wektor ataku dla phishingu i malware.",
    javascriptUriBlocked: "KRYTYCZNE: Ten link zawiera URI javascript: (krytyczne ryzyko). URI JavaScript mogą wykonywać dowolny kod w kontekście przeglądarki, potencjalnie kradnąc dane lub poświadczenia.",
    vbscriptUriBlocked: "KRYTYCZNE: Ten link zawiera URI vbscript: (krytyczne ryzyko). URI VBScript mogą wykonywać niebezpieczny kod w systemach Windows. To poważne zagrożenie bezpieczeństwa.",
    blobUriBlocked: "KRYTYCZNE: Ten link zawiera URI blob: (krytyczne ryzyko). URI blob mogą wykonywać dowolny kod lub rozpowszechniać malware. Ten link został zablokowany dla Twojej ochrony.",
    mathematicalCharsDetected: "Ta domena zawiera matematyczne znaki Unicode (wysokie ryzyko). Symbole matematyczne wyglądające jak normalne litery są używane do podszywania się pod legalną stronę.",
    greekCharsDetected: "Ta domena zawiera greckie litery zmieszane z łacińskimi (wysokie ryzyko). Greckie litery jak omikron i ny są identyczne z łacińskimi 'o' i 'v', co czyni to potencjalnym atakiem spoofingu.",
    scriptCharsDetected: "Ta domena zawiera symbole przypominające litery (wysokie ryzyko). Specjalne skryptowe znaki Unicode są używane do podszywania się pod legalną stronę.",
    digitInDomainDetected: "Ta domena używa podstawienia cyfr, aby podszywać się pod znaną markę (wysokie ryzyko). Cyfry 0, 1, 3, 5 są używane zamiast liter (np. g00gle, paypa1, amaz0n)."
  },
  cs: {
    dataUriBlocked: "KRITICKÉ: Tento odkaz obsahuje URI data: (kritické riziko). URI data: mohou spouštět škodlivý obsah přímo ve vašem prohlížeči. Toto je běžný vektor útoku pro phishing a malware.",
    javascriptUriBlocked: "KRITICKÉ: Tento odkaz obsahuje URI javascript: (kritické riziko). URI JavaScript mohou spouštět libovolný kód v kontextu vašeho prohlížeče, potenciálně kradouce vaše data nebo přihlašovací údaje.",
    vbscriptUriBlocked: "KRITICKÉ: Tento odkaz obsahuje URI vbscript: (kritické riziko). URI VBScript mohou spouštět nebezpečný kód na systémech Windows. Toto je vážná bezpečnostní hrozba.",
    blobUriBlocked: "KRITICKÉ: Tento odkaz obsahuje URI blob: (kritické riziko). URI blob mohou spouštět libovolný kód nebo šířit malware. Tento odkaz byl zablokován pro vaši ochranu.",
    mathematicalCharsDetected: "Tato doména obsahuje matematické Unicode znaky (vysoké riziko). Matematické symboly, které vypadají jako normální písmena, jsou používány k napodobení legitimního webu.",
    greekCharsDetected: "Tato doména obsahuje řecká písmena smíchaná s latinskými (vysoké riziko). Řecká písmena jako omikron a ný jsou identická s latinskými 'o' a 'v', což z toho činí potenciální spoofingový útok.",
    scriptCharsDetected: "Tato doména obsahuje symboly podobné písmenům (vysoké riziko). Speciální skriptové Unicode znaky jsou používány k napodobení legitimního webu.",
    digitInDomainDetected: "Tato doména používá nahrazení číslic k napodobení známé značky (vysoké riziko). Čísla 0, 1, 3, 5 jsou používána místo písmen (např. g00gle, paypa1, amaz0n)."
  },
  ro: {
    dataUriBlocked: "CRITIC: Acest link conține un URI data: (risc critic). URI-urile data: pot executa conținut malițios direct în browser. Acesta este un vector de atac comun pentru phishing și malware.",
    javascriptUriBlocked: "CRITIC: Acest link conține un URI javascript: (risc critic). URI-urile JavaScript pot executa cod arbitrar în contextul browserului, putând fura datele sau credențialele dvs.",
    vbscriptUriBlocked: "CRITIC: Acest link conține un URI vbscript: (risc critic). URI-urile VBScript pot executa cod periculos pe sistemele Windows. Aceasta este o amenințare serioasă de securitate.",
    blobUriBlocked: "CRITIC: Acest link conține un URI blob: (risc critic). URI-urile blob pot executa cod arbitrar sau distribui malware. Acest link a fost blocat pentru protecția dvs.",
    mathematicalCharsDetected: "Acest domeniu conține caractere Unicode matematice (risc ridicat). Simboluri matematice care arată ca litere normale sunt folosite pentru a imita un site web legitim.",
    greekCharsDetected: "Acest domeniu conține caractere grecești amestecate cu litere latine (risc ridicat). Literele grecești precum omicron și nu sunt identice cu 'o' și 'v' latine, făcând acesta un potențial atac de spoofing.",
    scriptCharsDetected: "Acest domeniu conține simboluri asemănătoare literelor (risc ridicat). Caractere Unicode de script speciale sunt folosite pentru a imita un site web legitim.",
    digitInDomainDetected: "Acest domeniu folosește substituirea cifrelor pentru a imita o marcă cunoscută (risc ridicat). Numere ca 0, 1, 3, 5 sunt folosite în loc de litere (ex: g00gle, paypa1, amaz0n)."
  },
  hu: {
    dataUriBlocked: "KRITIKUS: Ez a link data: URI-t tartalmaz (kritikus kockázat). A data: URI-k rosszindulatú tartalmat futtathatnak közvetlenül a böngészőben. Ez egy gyakori támadási vektor az adathalászathoz és a malware-hez.",
    javascriptUriBlocked: "KRITIKUS: Ez a link javascript: URI-t tartalmaz (kritikus kockázat). A JavaScript URI-k tetszőleges kódot futtathatnak a böngésző kontextusában, potenciálisan ellopva az adatait vagy hitelesítő adatait.",
    vbscriptUriBlocked: "KRITIKUS: Ez a link vbscript: URI-t tartalmaz (kritikus kockázat). A VBScript URI-k veszélyes kódot futtathatnak Windows rendszereken. Ez súlyos biztonsági fenyegetés.",
    blobUriBlocked: "KRITIKUS: Ez a link blob: URI-t tartalmaz (kritikus kockázat). A blob URI-k tetszőleges kódot futtathatnak vagy malware-t terjeszthetnek. Ez a link blokkolva lett az Ön védelme érdekében.",
    mathematicalCharsDetected: "Ez a domain matematikai Unicode karaktereket tartalmaz (magas kockázat). A normál betűkhöz hasonló matematikai szimbólumokat használnak egy legitim weboldal megszemélyesítésére.",
    greekCharsDetected: "Ez a domain görög betűket tartalmaz latin betűkkel keverve (magas kockázat). A görög betűk, mint az omikron és a nü, azonosak a latin 'o' és 'v' betűkkel, ami potenciális spoofing támadássá teszi.",
    scriptCharsDetected: "Ez a domain betűhöz hasonló szimbólumokat tartalmaz (magas kockázat). Speciális Unicode script karaktereket használnak egy legitim weboldal megszemélyesítésére.",
    digitInDomainDetected: "Ez a domain számhelyettesítést használ egy ismert márka megszemélyesítésére (magas kockázat). A 0, 1, 3, 5 számokat betűk helyett használják (pl. g00gle, paypa1, amaz0n)."
  },
  tr: {
    dataUriBlocked: "KRİTİK: Bu bağlantı data: URI içeriyor (kritik risk). Data: URI'leri doğrudan tarayıcınızda kötü amaçlı içerik çalıştırabilir. Bu, kimlik avı ve kötü amaçlı yazılım için yaygın bir saldırı vektörüdür.",
    javascriptUriBlocked: "KRİTİK: Bu bağlantı javascript: URI içeriyor (kritik risk). JavaScript URI'leri tarayıcı bağlamınızda rastgele kod çalıştırabilir, potansiyel olarak verilerinizi veya kimlik bilgilerinizi çalabilir.",
    vbscriptUriBlocked: "KRİTİK: Bu bağlantı vbscript: URI içeriyor (kritik risk). VBScript URI'leri Windows sistemlerinde tehlikeli kod çalıştırabilir. Bu ciddi bir güvenlik tehdididir.",
    blobUriBlocked: "KRİTİK: Bu bağlantı blob: URI içeriyor (kritik risk). Blob URI'leri rastgele kod çalıştırabilir veya kötü amaçlı yazılım dağıtabilir. Bu bağlantı korumanız için engellendi.",
    mathematicalCharsDetected: "Bu alan adı matematiksel Unicode karakterler içeriyor (yüksek risk). Normal harflere benzeyen matematiksel semboller meşru bir web sitesini taklit etmek için kullanılıyor.",
    greekCharsDetected: "Bu alan adı Latin harflerle karışık Yunan harfler içeriyor (yüksek risk). Omikron ve nu gibi Yunan harfleri Latin 'o' ve 'v' ile aynıdır, bu da bunu potansiyel bir sahtecilik saldırısı yapar.",
    scriptCharsDetected: "Bu alan adı harf benzeri semboller içeriyor (yüksek risk). Özel Unicode script karakterleri meşru bir web sitesini taklit etmek için kullanılıyor.",
    digitInDomainDetected: "Bu alan adı bilinen bir markayı taklit etmek için rakam değiştirme kullanıyor (yüksek risk). 0, 1, 3, 5 gibi rakamlar harfler yerine kullanılıyor (örn: g00gle, paypa1, amaz0n)."
  },
  el: {
    dataUriBlocked: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει data: URI (κρίσιμος κίνδυνος). Τα data: URI μπορούν να εκτελέσουν κακόβουλο περιεχόμενο απευθείας στο πρόγραμμα περιήγησής σας. Αυτό είναι ένα κοινό διάνυσμα επίθεσης για phishing και κακόβουλο λογισμικό.",
    javascriptUriBlocked: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει javascript: URI (κρίσιμος κίνδυνος). Τα JavaScript URI μπορούν να εκτελέσουν αυθαίρετο κώδικα στο πλαίσιο του προγράμματος περιήγησής σας, πιθανώς κλέβοντας τα δεδομένα ή τα διαπιστευτήριά σας.",
    vbscriptUriBlocked: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει vbscript: URI (κρίσιμος κίνδυνος). Τα VBScript URI μπορούν να εκτελέσουν επικίνδυνο κώδικα σε συστήματα Windows. Αυτή είναι μια σοβαρή απειλή ασφαλείας.",
    blobUriBlocked: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει blob: URI (κρίσιμος κίνδυνος). Τα blob URI μπορούν να εκτελέσουν αυθαίρετο κώδικα ή να διανείμουν κακόβουλο λογισμικό. Αυτός ο σύνδεσμος έχει αποκλειστεί για την προστασία σας.",
    mathematicalCharsDetected: "Αυτός ο τομέας περιέχει μαθηματικούς χαρακτήρες Unicode (υψηλός κίνδυνος). Μαθηματικά σύμβολα που μοιάζουν με κανονικά γράμματα χρησιμοποιούνται για να μιμηθούν μια νόμιμη ιστοσελίδα.",
    greekCharsDetected: "Αυτός ο τομέας περιέχει ελληνικά γράμματα αναμεμειγμένα με λατινικά (υψηλός κίνδυνος). Ελληνικά γράμματα όπως το όμικρον και το νι είναι πανομοιότυπα με τα λατινικά 'o' και 'v', καθιστώντας αυτό πιθανή επίθεση spoofing.",
    scriptCharsDetected: "Αυτός ο τομέας περιέχει σύμβολα που μοιάζουν με γράμματα (υψηλός κίνδυνος). Ειδικοί χαρακτήρες script Unicode χρησιμοποιούνται για να μιμηθούν μια νόμιμη ιστοσελίδα.",
    digitInDomainDetected: "Αυτός ο τομέας χρησιμοποιεί αντικατάσταση ψηφίων για να μιμηθεί μια γνωστή μάρκα (υψηλός κίνδυνος). Αριθμοί όπως 0, 1, 3, 5 χρησιμοποιούνται αντί για γράμματα (π.χ. g00gle, paypa1, amaz0n)."
  },
  ar: {
    dataUriBlocked: "حرج: يحتوي هذا الرابط على data: URI (خطر حرج). يمكن لـ data: URIs تنفيذ محتوى ضار مباشرة في متصفحك. هذا ناقل هجوم شائع للتصيد والبرمجيات الخبيثة.",
    javascriptUriBlocked: "حرج: يحتوي هذا الرابط على javascript: URI (خطر حرج). يمكن لـ JavaScript URIs تنفيذ كود تعسفي في سياق متصفحك، مما قد يسرق بياناتك أو بيانات اعتمادك.",
    vbscriptUriBlocked: "حرج: يحتوي هذا الرابط على vbscript: URI (خطر حرج). يمكن لـ VBScript URIs تنفيذ كود خطير على أنظمة Windows. هذا تهديد أمني خطير.",
    blobUriBlocked: "حرج: يحتوي هذا الرابط على blob: URI (خطر حرج). يمكن لـ blob URIs تنفيذ كود تعسفي أو توزيع برمجيات خبيثة. تم حظر هذا الرابط لحمايتك.",
    mathematicalCharsDetected: "يحتوي هذا النطاق على أحرف Unicode رياضية (خطر عالي). تُستخدم الرموز الرياضية التي تبدو كأحرف عادية لانتحال شخصية موقع ويب شرعي.",
    greekCharsDetected: "يحتوي هذا النطاق على أحرف يونانية مختلطة بأحرف لاتينية (خطر عالي). الأحرف اليونانية مثل أوميكرون ونو متطابقة مع 'o' و 'v' اللاتينية، مما يجعل هذا هجوم انتحال محتمل.",
    scriptCharsDetected: "يحتوي هذا النطاق على رموز شبيهة بالحروف (خطر عالي). تُستخدم أحرف Unicode نصية خاصة لانتحال شخصية موقع ويب شرعي.",
    digitInDomainDetected: "يستخدم هذا النطاق استبدال الأرقام لانتحال علامة تجارية معروفة (خطر عالي). تُستخدم الأرقام مثل 0، 1، 3، 5 بدلاً من الأحرف (مثل: g00gle، paypa1، amaz0n)."
  },
  hi: {
    dataUriBlocked: "गंभीर: इस लिंक में data: URI है (गंभीर जोखिम)। Data: URIs आपके ब्राउज़र में सीधे दुर्भावनापूर्ण सामग्री निष्पादित कर सकते हैं। यह फ़िशिंग और मैलवेयर के लिए एक सामान्य हमला वेक्टर है।",
    javascriptUriBlocked: "गंभीर: इस लिंक में javascript: URI है (गंभीर जोखिम)। JavaScript URIs आपके ब्राउज़र संदर्भ में मनमाना कोड निष्पादित कर सकते हैं, संभावित रूप से आपका डेटा या क्रेडेंशियल चुरा सकते हैं।",
    vbscriptUriBlocked: "गंभीर: इस लिंक में vbscript: URI है (गंभीर जोखिम)। VBScript URIs Windows सिस्टम पर खतरनाक कोड निष्पादित कर सकते हैं। यह एक गंभीर सुरक्षा खतरा है।",
    blobUriBlocked: "गंभीर: इस लिंक में blob: URI है (गंभीर जोखिम)। Blob URIs मनमाना कोड निष्पादित कर सकते हैं या मैलवेयर वितरित कर सकते हैं। यह लिंक आपकी सुरक्षा के लिए अवरुद्ध कर दिया गया है।",
    mathematicalCharsDetected: "इस डोमेन में गणितीय यूनिकोड वर्ण हैं (उच्च जोखिम)। सामान्य अक्षरों जैसे दिखने वाले गणितीय प्रतीकों का उपयोग एक वैध वेबसाइट का प्रतिरूपण करने के लिए किया जा रहा है।",
    greekCharsDetected: "इस डोमेन में लैटिन अक्षरों के साथ मिश्रित ग्रीक अक्षर हैं (उच्च जोखिम)। ओमिक्रॉन और न्यू जैसे ग्रीक अक्षर लैटिन 'o' और 'v' के समान हैं, जो इसे संभावित स्पूफिंग हमला बनाता है।",
    scriptCharsDetected: "इस डोमेन में अक्षर-जैसे प्रतीक हैं (उच्च जोखिम)। विशेष यूनिकोड स्क्रिप्ट वर्णों का उपयोग एक वैध वेबसाइट का प्रतिरूपण करने के लिए किया जा रहा है।",
    digitInDomainDetected: "यह डोमेन एक ज्ञात ब्रांड का प्रतिरूपण करने के लिए अंक प्रतिस्थापन का उपयोग करता है (उच्च जोखिम)। 0, 1, 3, 5 जैसे नंबर अक्षरों के स्थान पर उपयोग किए जाते हैं (उदा: g00gle, paypa1, amaz0n)।"
  },
  th: {
    dataUriBlocked: "วิกฤต: ลิงก์นี้มี data: URI (ความเสี่ยงวิกฤต) Data: URIs สามารถเรียกใช้เนื้อหาที่เป็นอันตรายโดยตรงในเบราว์เซอร์ของคุณ นี่คือเวกเตอร์การโจมตีทั่วไปสำหรับฟิชชิ่งและมัลแวร์",
    javascriptUriBlocked: "วิกฤต: ลิงก์นี้มี javascript: URI (ความเสี่ยงวิกฤต) JavaScript URIs สามารถเรียกใช้โค้ดตามอำเภอใจในบริบทเบราว์เซอร์ของคุณ อาจขโมยข้อมูลหรือข้อมูลรับรองของคุณ",
    vbscriptUriBlocked: "วิกฤต: ลิงก์นี้มี vbscript: URI (ความเสี่ยงวิกฤต) VBScript URIs สามารถเรียกใช้โค้ดอันตรายบนระบบ Windows นี่คือภัยคุกคามความปลอดภัยร้ายแรง",
    blobUriBlocked: "วิกฤต: ลิงก์นี้มี blob: URI (ความเสี่ยงวิกฤต) Blob URIs สามารถเรียกใช้โค้ดตามอำเภอใจหรือแพร่กระจายมัลแวร์ ลิงก์นี้ถูกบล็อกเพื่อการป้องกันของคุณ",
    mathematicalCharsDetected: "โดเมนนี้มีอักขระ Unicode ทางคณิตศาสตร์ (ความเสี่ยงสูง) สัญลักษณ์ทางคณิตศาสตร์ที่ดูเหมือนตัวอักษรปกติถูกใช้เพื่อเลียนแบบเว็บไซต์ที่ถูกต้อง",
    greekCharsDetected: "โดเมนนี้มีตัวอักษรกรีกผสมกับตัวอักษรละติน (ความเสี่ยงสูง) ตัวอักษรกรีกเช่น omicron และ nu เหมือนกับ 'o' และ 'v' ละติน ทำให้นี่อาจเป็นการโจมตี spoofing",
    scriptCharsDetected: "โดเมนนี้มีสัญลักษณ์คล้ายตัวอักษร (ความเสี่ยงสูง) อักขระสคริปต์ Unicode พิเศษถูกใช้เพื่อเลียนแบบเว็บไซต์ที่ถูกต้อง",
    digitInDomainDetected: "โดเมนนี้ใช้การแทนที่ตัวเลขเพื่อเลียนแบบแบรนด์ที่รู้จัก (ความเสี่ยงสูง) ตัวเลขเช่น 0, 1, 3, 5 ถูกใช้แทนตัวอักษร (เช่น g00gle, paypa1, amaz0n)"
  },
  vi: {
    dataUriBlocked: "NGHIÊM TRỌNG: Liên kết này chứa data: URI (rủi ro nghiêm trọng). Data: URIs có thể thực thi nội dung độc hại trực tiếp trong trình duyệt của bạn. Đây là vector tấn công phổ biến cho phishing và phần mềm độc hại.",
    javascriptUriBlocked: "NGHIÊM TRỌNG: Liên kết này chứa javascript: URI (rủi ro nghiêm trọng). JavaScript URIs có thể thực thi mã tùy ý trong ngữ cảnh trình duyệt của bạn, có thể đánh cắp dữ liệu hoặc thông tin đăng nhập của bạn.",
    vbscriptUriBlocked: "NGHIÊM TRỌNG: Liên kết này chứa vbscript: URI (rủi ro nghiêm trọng). VBScript URIs có thể thực thi mã nguy hiểm trên hệ thống Windows. Đây là mối đe dọa bảo mật nghiêm trọng.",
    blobUriBlocked: "NGHIÊM TRỌNG: Liên kết này chứa blob: URI (rủi ro nghiêm trọng). Blob URIs có thể thực thi mã tùy ý hoặc phân phối phần mềm độc hại. Liên kết này đã bị chặn để bảo vệ bạn.",
    mathematicalCharsDetected: "Tên miền này chứa ký tự Unicode toán học (rủi ro cao). Các ký hiệu toán học trông giống chữ cái bình thường đang được sử dụng để mạo danh một trang web hợp pháp.",
    greekCharsDetected: "Tên miền này chứa chữ cái Hy Lạp trộn lẫn với chữ cái Latin (rủi ro cao). Các chữ cái Hy Lạp như omicron và nu giống hệt với 'o' và 'v' Latin, khiến đây trở thành cuộc tấn công giả mạo tiềm năng.",
    scriptCharsDetected: "Tên miền này chứa ký hiệu giống chữ cái (rủi ro cao). Các ký tự script Unicode đặc biệt đang được sử dụng để mạo danh một trang web hợp pháp.",
    digitInDomainDetected: "Tên miền này sử dụng thay thế chữ số để mạo danh một thương hiệu nổi tiếng (rủi ro cao). Các số như 0, 1, 3, 5 được sử dụng thay vì chữ cái (ví dụ: g00gle, paypa1, amaz0n)."
  },
  id: {
    dataUriBlocked: "KRITIS: Tautan ini berisi data: URI (risiko kritis). Data: URI dapat mengeksekusi konten berbahaya langsung di browser Anda. Ini adalah vektor serangan umum untuk phishing dan malware.",
    javascriptUriBlocked: "KRITIS: Tautan ini berisi javascript: URI (risiko kritis). JavaScript URI dapat mengeksekusi kode arbitrer dalam konteks browser Anda, berpotensi mencuri data atau kredensial Anda.",
    vbscriptUriBlocked: "KRITIS: Tautan ini berisi vbscript: URI (risiko kritis). VBScript URI dapat mengeksekusi kode berbahaya pada sistem Windows. Ini adalah ancaman keamanan serius.",
    blobUriBlocked: "KRITIS: Tautan ini berisi blob: URI (risiko kritis). Blob URI dapat mengeksekusi kode arbitrer atau mendistribusikan malware. Tautan ini telah diblokir untuk perlindungan Anda.",
    mathematicalCharsDetected: "Domain ini berisi karakter Unicode matematika (risiko tinggi). Simbol matematika yang terlihat seperti huruf biasa digunakan untuk meniru situs web yang sah.",
    greekCharsDetected: "Domain ini berisi huruf Yunani yang dicampur dengan huruf Latin (risiko tinggi). Huruf Yunani seperti omicron dan nu identik dengan 'o' dan 'v' Latin, menjadikan ini potensi serangan spoofing.",
    scriptCharsDetected: "Domain ini berisi simbol mirip huruf (risiko tinggi). Karakter skrip Unicode khusus digunakan untuk meniru situs web yang sah.",
    digitInDomainDetected: "Domain ini menggunakan substitusi digit untuk meniru merek terkenal (risiko tinggi). Angka seperti 0, 1, 3, 5 digunakan sebagai pengganti huruf (misalnya: g00gle, paypa1, amaz0n)."
  },
  ja: {
    dataUriBlocked: "重大: このリンクにはdata: URIが含まれています（重大リスク）。Data: URIはブラウザで直接悪意のあるコンテンツを実行できます。これはフィッシングやマルウェアの一般的な攻撃ベクトルです。",
    javascriptUriBlocked: "重大: このリンクにはjavascript: URIが含まれています（重大リスク）。JavaScript URIはブラウザコンテキストで任意のコードを実行でき、データや資格情報を盗む可能性があります。",
    vbscriptUriBlocked: "重大: このリンクにはvbscript: URIが含まれています（重大リスク）。VBScript URIはWindowsシステムで危険なコードを実行できます。これは深刻なセキュリティ脅威です。",
    blobUriBlocked: "重大: このリンクにはblob: URIが含まれています（重大リスク）。Blob URIは任意のコードを実行したり、マルウェアを配布したりできます。このリンクはあなたの保護のためにブロックされました。",
    mathematicalCharsDetected: "このドメインには数学的なUnicode文字が含まれています（高リスク）。通常の文字のように見える数学記号が、正当なウェブサイトを偽装するために使用されています。",
    greekCharsDetected: "このドメインにはラテン文字と混在したギリシャ文字が含まれています（高リスク）。オミクロンやニューなどのギリシャ文字はラテン語の'o'と'v'と同一であり、これを潜在的なスプーフィング攻撃にしています。",
    scriptCharsDetected: "このドメインには文字のようなシンボルが含まれています（高リスク）。特殊なUnicodeスクリプト文字が、正当なウェブサイトを偽装するために使用されています。",
    digitInDomainDetected: "このドメインは既知のブランドを偽装するために数字の置換を使用しています（高リスク）。0、1、3、5などの数字が文字の代わりに使用されています（例：g00gle、paypa1、amaz0n）。"
  },
  ko: {
    dataUriBlocked: "심각: 이 링크에는 data: URI가 포함되어 있습니다 (심각한 위험). Data: URI는 브라우저에서 직접 악성 콘텐츠를 실행할 수 있습니다. 이것은 피싱 및 악성 소프트웨어의 일반적인 공격 벡터입니다.",
    javascriptUriBlocked: "심각: 이 링크에는 javascript: URI가 포함되어 있습니다 (심각한 위험). JavaScript URI는 브라우저 컨텍스트에서 임의의 코드를 실행하여 데이터나 자격 증명을 훔칠 수 있습니다.",
    vbscriptUriBlocked: "심각: 이 링크에는 vbscript: URI가 포함되어 있습니다 (심각한 위험). VBScript URI는 Windows 시스템에서 위험한 코드를 실행할 수 있습니다. 이것은 심각한 보안 위협입니다.",
    blobUriBlocked: "심각: 이 링크에는 blob: URI가 포함되어 있습니다 (심각한 위험). Blob URI는 임의의 코드를 실행하거나 악성 소프트웨어를 배포할 수 있습니다. 이 링크는 귀하의 보호를 위해 차단되었습니다.",
    mathematicalCharsDetected: "이 도메인에는 수학적 Unicode 문자가 포함되어 있습니다 (높은 위험). 일반 문자처럼 보이는 수학 기호가 합법적인 웹사이트를 사칭하는 데 사용되고 있습니다.",
    greekCharsDetected: "이 도메인에는 라틴 문자와 혼합된 그리스 문자가 포함되어 있습니다 (높은 위험). 오미크론과 뉴와 같은 그리스 문자는 라틴어 'o'와 'v'와 동일하여 잠재적인 스푸핑 공격이 됩니다.",
    scriptCharsDetected: "이 도메인에는 문자와 유사한 기호가 포함되어 있습니다 (높은 위험). 특수 Unicode 스크립트 문자가 합법적인 웹사이트를 사칭하는 데 사용되고 있습니다.",
    digitInDomainDetected: "이 도메인은 알려진 브랜드를 사칭하기 위해 숫자 대체를 사용합니다 (높은 위험). 0, 1, 3, 5와 같은 숫자가 문자 대신 사용됩니다 (예: g00gle, paypa1, amaz0n)."
  },
  zh: {
    dataUriBlocked: "严重：此链接包含 data: URI（严重风险）。Data: URI 可以直接在您的浏览器中执行恶意内容。这是钓鱼和恶意软件的常见攻击载体。",
    javascriptUriBlocked: "严重：此链接包含 javascript: URI（严重风险）。JavaScript URI 可以在您的浏览器上下文中执行任意代码，可能窃取您的数据或凭据。",
    vbscriptUriBlocked: "严重：此链接包含 vbscript: URI（严重风险）。VBScript URI 可以在 Windows 系统上执行危险代码。这是严重的安全威胁。",
    blobUriBlocked: "严重：此链接包含 blob: URI（严重风险）。Blob URI 可以执行任意代码或分发恶意软件。此链接已被阻止以保护您。",
    mathematicalCharsDetected: "此域名包含数学 Unicode 字符（高风险）。看起来像普通字母的数学符号正被用于冒充合法网站。",
    greekCharsDetected: "此域名包含与拉丁字母混合的希腊字母（高风险）。像 omicron 和 nu 这样的希腊字母与拉丁语的 'o' 和 'v' 相同，使其成为潜在的欺骗攻击。",
    scriptCharsDetected: "此域名包含类似字母的符号（高风险）。特殊的 Unicode 脚本字符正被用于冒充合法网站。",
    digitInDomainDetected: "此域名使用数字替换来冒充知名品牌（高风险）。数字如 0、1、3、5 被用来替代字母（例如：g00gle、paypa1、amaz0n）。"
  }
};

// Keys to add
const keysToAdd = [
  'dataUriBlocked',
  'javascriptUriBlocked',
  'vbscriptUriBlocked',
  'blobUriBlocked',
  'mathematicalCharsDetected',
  'greekCharsDetected',
  'scriptCharsDetected',
  'digitInDomainDetected'
];

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
    console.log(`Warning: Skipping ${locale}: messages.json not found`);
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
      console.log(`OK ${locale}: All keys already present`);
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
    console.log(`UPDATED ${locale}: Added ${missingKeys.length} keys (${missingKeys.join(', ')})`);
    updated++;

  } catch (err) {
    console.error(`ERROR ${locale}: ${err.message}`);
  }
});

console.log(`\nSummary: ${updated} locales updated`);
