/**
 * Script to add missing security i18n keys to all locale files
 * SECURITY FIX v8.2.0: Homoglyph, URI scheme, and mixed-script attack messages
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

// Translations for all 24 locales
const translations = {
  en: {
    dangerousJavascriptUri: "CRITICAL: This link contains executable JavaScript code (critical risk). Clicking it could run malicious scripts in your browser.",
    dangerousVbscriptUri: "CRITICAL: This link contains executable VBScript code (critical risk). This is a dangerous attack technique targeting Windows systems.",
    dangerousDataUri: "CRITICAL: This link contains embedded data that could execute code (critical risk). Data URIs can be used for phishing or malware delivery.",
    criticalSecurityThreat: "CRITICAL SECURITY THREAT: This link has been identified as extremely dangerous. Do not click under any circumstances.",
    mixedScriptAttack: "CRITICAL: This web address mixes characters from different alphabets (e.g., Latin and Cyrillic). This is a sophisticated spoofing attack where characters that look identical are from different scripts.",
    nonAsciiDomain: "This domain contains non-ASCII characters (high risk). International characters in domain names can be used to impersonate legitimate websites.",
    homoglyphCharactersDetected: "CRITICAL: Homoglyph characters detected in this domain (critical risk). Characters that look like Latin letters but are actually from other scripts (e.g., Cyrillic) are being used to impersonate a legitimate website."
  },
  nl: {
    dangerousJavascriptUri: "KRITIEK: Deze link bevat uitvoerbare JavaScript-code (kritiek risico). Klikken kan schadelijke scripts in je browser uitvoeren.",
    dangerousVbscriptUri: "KRITIEK: Deze link bevat uitvoerbare VBScript-code (kritiek risico). Dit is een gevaarlijke aanvalstechniek gericht op Windows-systemen.",
    dangerousDataUri: "KRITIEK: Deze link bevat ingesloten data die code kan uitvoeren (kritiek risico). Data-URI's kunnen worden gebruikt voor phishing of malware.",
    criticalSecurityThreat: "KRITIEKE BEVEILIGINGSDREIGING: Deze link is geïdentificeerd als extreem gevaarlijk. Klik in geen geval.",
    mixedScriptAttack: "KRITIEK: Dit webadres mengt tekens uit verschillende alfabetten (bijv. Latijn en Cyrillisch). Dit is een geavanceerde spoofing-aanval waarbij identiek lijkende tekens van verschillende scripts komen.",
    nonAsciiDomain: "Dit domein bevat niet-ASCII-tekens (hoog risico). Internationale tekens in domeinnamen kunnen worden gebruikt om legitieme websites na te bootsen.",
    homoglyphCharactersDetected: "KRITIEK: Homoglyph-tekens gedetecteerd in dit domein (kritiek risico). Tekens die lijken op Latijnse letters maar eigenlijk van andere scripts zijn (bijv. Cyrillisch) worden gebruikt om een legitieme website na te bootsen."
  },
  de: {
    dangerousJavascriptUri: "KRITISCH: Dieser Link enthält ausführbaren JavaScript-Code (kritisches Risiko). Ein Klick könnte schädliche Skripte in Ihrem Browser ausführen.",
    dangerousVbscriptUri: "KRITISCH: Dieser Link enthält ausführbaren VBScript-Code (kritisches Risiko). Dies ist eine gefährliche Angriffstechnik für Windows-Systeme.",
    dangerousDataUri: "KRITISCH: Dieser Link enthält eingebettete Daten, die Code ausführen könnten (kritisches Risiko). Data-URIs können für Phishing oder Malware verwendet werden.",
    criticalSecurityThreat: "KRITISCHE SICHERHEITSBEDROHUNG: Dieser Link wurde als extrem gefährlich identifiziert. Klicken Sie unter keinen Umständen.",
    mixedScriptAttack: "KRITISCH: Diese Webadresse mischt Zeichen aus verschiedenen Alphabeten (z.B. Lateinisch und Kyrillisch). Dies ist ein ausgeklügelter Spoofing-Angriff mit identisch aussehenden Zeichen aus verschiedenen Schriften.",
    nonAsciiDomain: "Diese Domain enthält Nicht-ASCII-Zeichen (hohes Risiko). Internationale Zeichen in Domainnamen können verwendet werden, um legitime Websites zu imitieren.",
    homoglyphCharactersDetected: "KRITISCH: Homoglyph-Zeichen in dieser Domain erkannt (kritisches Risiko). Zeichen, die wie lateinische Buchstaben aussehen, aber aus anderen Schriften stammen (z.B. Kyrillisch), werden verwendet, um eine legitime Website zu imitieren."
  },
  fr: {
    dangerousJavascriptUri: "CRITIQUE: Ce lien contient du code JavaScript exécutable (risque critique). Cliquer pourrait exécuter des scripts malveillants dans votre navigateur.",
    dangerousVbscriptUri: "CRITIQUE: Ce lien contient du code VBScript exécutable (risque critique). C'est une technique d'attaque dangereuse ciblant les systèmes Windows.",
    dangerousDataUri: "CRITIQUE: Ce lien contient des données intégrées qui pourraient exécuter du code (risque critique). Les URI de données peuvent être utilisées pour le phishing ou la diffusion de malware.",
    criticalSecurityThreat: "MENACE DE SÉCURITÉ CRITIQUE: Ce lien a été identifié comme extrêmement dangereux. Ne cliquez en aucun cas.",
    mixedScriptAttack: "CRITIQUE: Cette adresse web mélange des caractères de différents alphabets (ex: Latin et Cyrillique). C'est une attaque de spoofing sophistiquée utilisant des caractères identiques de différents scripts.",
    nonAsciiDomain: "Ce domaine contient des caractères non-ASCII (risque élevé). Les caractères internationaux dans les noms de domaine peuvent être utilisés pour imiter des sites légitimes.",
    homoglyphCharactersDetected: "CRITIQUE: Caractères homoglyphes détectés dans ce domaine (risque critique). Des caractères ressemblant aux lettres latines mais provenant d'autres scripts (ex: Cyrillique) sont utilisés pour imiter un site légitime."
  },
  es: {
    dangerousJavascriptUri: "CRÍTICO: Este enlace contiene código JavaScript ejecutable (riesgo crítico). Hacer clic podría ejecutar scripts maliciosos en tu navegador.",
    dangerousVbscriptUri: "CRÍTICO: Este enlace contiene código VBScript ejecutable (riesgo crítico). Esta es una técnica de ataque peligrosa dirigida a sistemas Windows.",
    dangerousDataUri: "CRÍTICO: Este enlace contiene datos incrustados que podrían ejecutar código (riesgo crítico). Las URI de datos pueden usarse para phishing o distribución de malware.",
    criticalSecurityThreat: "AMENAZA DE SEGURIDAD CRÍTICA: Este enlace ha sido identificado como extremadamente peligroso. No hagas clic bajo ninguna circunstancia.",
    mixedScriptAttack: "CRÍTICO: Esta dirección web mezcla caracteres de diferentes alfabetos (ej: Latino y Cirílico). Este es un ataque de suplantación sofisticado donde caracteres idénticos provienen de diferentes scripts.",
    nonAsciiDomain: "Este dominio contiene caracteres no ASCII (alto riesgo). Los caracteres internacionales en nombres de dominio pueden usarse para suplantar sitios legítimos.",
    homoglyphCharactersDetected: "CRÍTICO: Caracteres homóglifos detectados en este dominio (riesgo crítico). Caracteres que parecen letras latinas pero son de otros scripts (ej: Cirílico) se usan para suplantar un sitio legítimo."
  },
  it: {
    dangerousJavascriptUri: "CRITICO: Questo link contiene codice JavaScript eseguibile (rischio critico). Cliccare potrebbe eseguire script dannosi nel tuo browser.",
    dangerousVbscriptUri: "CRITICO: Questo link contiene codice VBScript eseguibile (rischio critico). Questa è una tecnica di attacco pericolosa mirata ai sistemi Windows.",
    dangerousDataUri: "CRITICO: Questo link contiene dati incorporati che potrebbero eseguire codice (rischio critico). Gli URI di dati possono essere utilizzati per phishing o distribuzione di malware.",
    criticalSecurityThreat: "MINACCIA DI SICUREZZA CRITICA: Questo link è stato identificato come estremamente pericoloso. Non cliccare in nessun caso.",
    mixedScriptAttack: "CRITICO: Questo indirizzo web mescola caratteri di diversi alfabeti (es: Latino e Cirillico). Questo è un attacco di spoofing sofisticato dove caratteri identici provengono da script diversi.",
    nonAsciiDomain: "Questo dominio contiene caratteri non-ASCII (alto rischio). I caratteri internazionali nei nomi di dominio possono essere utilizzati per impersonare siti legittimi.",
    homoglyphCharactersDetected: "CRITICO: Caratteri omoglifi rilevati in questo dominio (rischio critico). Caratteri che sembrano lettere latine ma sono di altri script (es: Cirillico) vengono usati per impersonare un sito legittimo."
  },
  pt: {
    dangerousJavascriptUri: "CRÍTICO: Este link contém código JavaScript executável (risco crítico). Clicar pode executar scripts maliciosos no seu navegador.",
    dangerousVbscriptUri: "CRÍTICO: Este link contém código VBScript executável (risco crítico). Esta é uma técnica de ataque perigosa direcionada a sistemas Windows.",
    dangerousDataUri: "CRÍTICO: Este link contém dados incorporados que podem executar código (risco crítico). URIs de dados podem ser usadas para phishing ou distribuição de malware.",
    criticalSecurityThreat: "AMEAÇA DE SEGURANÇA CRÍTICA: Este link foi identificado como extremamente perigoso. Não clique em nenhuma circunstância.",
    mixedScriptAttack: "CRÍTICO: Este endereço web mistura caracteres de diferentes alfabetos (ex: Latino e Cirílico). Este é um ataque de spoofing sofisticado onde caracteres idênticos vêm de scripts diferentes.",
    nonAsciiDomain: "Este domínio contém caracteres não-ASCII (alto risco). Caracteres internacionais em nomes de domínio podem ser usados para personificar sites legítimos.",
    homoglyphCharactersDetected: "CRÍTICO: Caracteres homóglifos detectados neste domínio (risco crítico). Caracteres que parecem letras latinas mas são de outros scripts (ex: Cirílico) estão sendo usados para personificar um site legítimo."
  },
  pt_BR: {
    dangerousJavascriptUri: "CRÍTICO: Este link contém código JavaScript executável (risco crítico). Clicar pode executar scripts maliciosos no seu navegador.",
    dangerousVbscriptUri: "CRÍTICO: Este link contém código VBScript executável (risco crítico). Esta é uma técnica de ataque perigosa direcionada a sistemas Windows.",
    dangerousDataUri: "CRÍTICO: Este link contém dados incorporados que podem executar código (risco crítico). URIs de dados podem ser usadas para phishing ou distribuição de malware.",
    criticalSecurityThreat: "AMEAÇA DE SEGURANÇA CRÍTICA: Este link foi identificado como extremamente perigoso. Não clique em nenhuma circunstância.",
    mixedScriptAttack: "CRÍTICO: Este endereço web mistura caracteres de diferentes alfabetos (ex: Latino e Cirílico). Este é um ataque de spoofing sofisticado onde caracteres idênticos vêm de scripts diferentes.",
    nonAsciiDomain: "Este domínio contém caracteres não-ASCII (alto risco). Caracteres internacionais em nomes de domínio podem ser usados para se passar por sites legítimos.",
    homoglyphCharactersDetected: "CRÍTICO: Caracteres homóglifos detectados neste domínio (risco crítico). Caracteres que parecem letras latinas mas são de outros scripts (ex: Cirílico) estão sendo usados para se passar por um site legítimo."
  },
  ru: {
    dangerousJavascriptUri: "КРИТИЧНО: Эта ссылка содержит исполняемый JavaScript-код (критический риск). Нажатие может запустить вредоносные скрипты в вашем браузере.",
    dangerousVbscriptUri: "КРИТИЧНО: Эта ссылка содержит исполняемый VBScript-код (критический риск). Это опасная техника атаки, нацеленная на системы Windows.",
    dangerousDataUri: "КРИТИЧНО: Эта ссылка содержит встроенные данные, которые могут выполнить код (критический риск). Data URI могут использоваться для фишинга или распространения вредоносного ПО.",
    criticalSecurityThreat: "КРИТИЧЕСКАЯ УГРОЗА БЕЗОПАСНОСТИ: Эта ссылка определена как чрезвычайно опасная. Ни в коем случае не нажимайте.",
    mixedScriptAttack: "КРИТИЧНО: Этот веб-адрес смешивает символы из разных алфавитов (например, латиницы и кириллицы). Это сложная атака подмены, где идентичные символы из разных письменностей.",
    nonAsciiDomain: "Этот домен содержит не-ASCII символы (высокий риск). Международные символы в доменных именах могут использоваться для имитации легитимных сайтов.",
    homoglyphCharactersDetected: "КРИТИЧНО: В этом домене обнаружены омоглифы (критический риск). Символы, похожие на латинские буквы, но из других письменностей (например, кириллицы), используются для имитации легитимного сайта."
  },
  uk: {
    dangerousJavascriptUri: "КРИТИЧНО: Це посилання містить виконуваний JavaScript-код (критичний ризик). Натискання може запустити шкідливі скрипти у вашому браузері.",
    dangerousVbscriptUri: "КРИТИЧНО: Це посилання містить виконуваний VBScript-код (критичний ризик). Це небезпечна техніка атаки, спрямована на системи Windows.",
    dangerousDataUri: "КРИТИЧНО: Це посилання містить вбудовані дані, які можуть виконати код (критичний ризик). Data URI можуть використовуватися для фішингу або розповсюдження шкідливого ПЗ.",
    criticalSecurityThreat: "КРИТИЧНА ЗАГРОЗА БЕЗПЕЦІ: Це посилання визначено як надзвичайно небезпечне. Ні в якому разі не натискайте.",
    mixedScriptAttack: "КРИТИЧНО: Ця веб-адреса змішує символи з різних алфавітів (наприклад, латиниці та кирилиці). Це складна атака підміни, де ідентичні символи з різних писемностей.",
    nonAsciiDomain: "Цей домен містить не-ASCII символи (високий ризик). Міжнародні символи в доменних іменах можуть використовуватися для імітації легітимних сайтів.",
    homoglyphCharactersDetected: "КРИТИЧНО: У цьому домені виявлено омогліфи (критичний ризик). Символи, схожі на латинські букви, але з інших писемностей (наприклад, кирилиці), використовуються для імітації легітимного сайту."
  },
  pl: {
    dangerousJavascriptUri: "KRYTYCZNE: Ten link zawiera wykonywalny kod JavaScript (krytyczne ryzyko). Kliknięcie może uruchomić złośliwe skrypty w przeglądarce.",
    dangerousVbscriptUri: "KRYTYCZNE: Ten link zawiera wykonywalny kod VBScript (krytyczne ryzyko). To niebezpieczna technika ataku skierowana na systemy Windows.",
    dangerousDataUri: "KRYTYCZNE: Ten link zawiera osadzone dane, które mogą wykonać kod (krytyczne ryzyko). URI danych mogą być używane do phishingu lub dystrybucji malware.",
    criticalSecurityThreat: "KRYTYCZNE ZAGROŻENIE BEZPIECZEŃSTWA: Ten link został zidentyfikowany jako ekstremalnie niebezpieczny. Pod żadnym pozorem nie klikaj.",
    mixedScriptAttack: "KRYTYCZNE: Ten adres internetowy miesza znaki z różnych alfabetów (np. łacińskiego i cyrylicy). To wyrafinowany atak spoofingowy, gdzie identyczne znaki pochodzą z różnych pism.",
    nonAsciiDomain: "Ta domena zawiera znaki spoza ASCII (wysokie ryzyko). Międzynarodowe znaki w nazwach domen mogą być używane do podszywania się pod legalne strony.",
    homoglyphCharactersDetected: "KRYTYCZNE: Wykryto znaki homoglify w tej domenie (krytyczne ryzyko). Znaki wyglądające jak litery łacińskie, ale pochodzące z innych pism (np. cyrylicy), są używane do podszywania się pod legalną stronę."
  },
  cs: {
    dangerousJavascriptUri: "KRITICKÉ: Tento odkaz obsahuje spustitelný JavaScript kód (kritické riziko). Kliknutí může spustit škodlivé skripty ve vašem prohlížeči.",
    dangerousVbscriptUri: "KRITICKÉ: Tento odkaz obsahuje spustitelný VBScript kód (kritické riziko). Jedná se o nebezpečnou útočnou techniku zaměřenou na systémy Windows.",
    dangerousDataUri: "KRITICKÉ: Tento odkaz obsahuje vložená data, která mohou spustit kód (kritické riziko). Data URI mohou být použity pro phishing nebo šíření malwaru.",
    criticalSecurityThreat: "KRITICKÁ BEZPEČNOSTNÍ HROZBA: Tento odkaz byl identifikován jako extrémně nebezpečný. Za žádných okolností neklikejte.",
    mixedScriptAttack: "KRITICKÉ: Tato webová adresa míchá znaky z různých abeced (např. latinky a cyrilice). Jedná se o sofistikovaný spoofingový útok, kde identické znaky pocházejí z různých písem.",
    nonAsciiDomain: "Tato doména obsahuje ne-ASCII znaky (vysoké riziko). Mezinárodní znaky v názvech domén mohou být použity k napodobování legitimních webů.",
    homoglyphCharactersDetected: "KRITICKÉ: V této doméně byly zjištěny homoglyfové znaky (kritické riziko). Znaky vypadající jako latinská písmena, ale pocházející z jiných písem (např. cyrilice), jsou používány k napodobování legitimního webu."
  },
  ro: {
    dangerousJavascriptUri: "CRITIC: Acest link conține cod JavaScript executabil (risc critic). Clicul poate executa scripturi malițioase în browser.",
    dangerousVbscriptUri: "CRITIC: Acest link conține cod VBScript executabil (risc critic). Aceasta este o tehnică de atac periculoasă care vizează sistemele Windows.",
    dangerousDataUri: "CRITIC: Acest link conține date încorporate care pot executa cod (risc critic). URI-urile de date pot fi folosite pentru phishing sau distribuirea de malware.",
    criticalSecurityThreat: "AMENINȚARE DE SECURITATE CRITICĂ: Acest link a fost identificat ca extrem de periculos. Nu faceți clic în nicio circumstanță.",
    mixedScriptAttack: "CRITIC: Această adresă web amestecă caractere din alfabete diferite (ex: Latin și Chirilic). Acesta este un atac de spoofing sofisticat unde caractere identice provin din scripturi diferite.",
    nonAsciiDomain: "Acest domeniu conține caractere non-ASCII (risc ridicat). Caracterele internaționale în numele de domeniu pot fi folosite pentru a imita site-uri legitime.",
    homoglyphCharactersDetected: "CRITIC: Caractere homoglife detectate în acest domeniu (risc critic). Caracterele care arată ca litere latine dar sunt din alte scripturi (ex: Chirilic) sunt folosite pentru a imita un site legitim."
  },
  hu: {
    dangerousJavascriptUri: "KRITIKUS: Ez a link futtatható JavaScript kódot tartalmaz (kritikus kockázat). A kattintás rosszindulatú szkripteket futtathat a böngészőben.",
    dangerousVbscriptUri: "KRITIKUS: Ez a link futtatható VBScript kódot tartalmaz (kritikus kockázat). Ez egy veszélyes támadási technika Windows rendszerek ellen.",
    dangerousDataUri: "KRITIKUS: Ez a link beágyazott adatokat tartalmaz, amelyek kódot futtathatnak (kritikus kockázat). A Data URI-k használhatók adathalászathoz vagy malware terjesztéséhez.",
    criticalSecurityThreat: "KRITIKUS BIZTONSÁGI FENYEGETÉS: Ez a link rendkívül veszélyesnek lett azonosítva. Semmilyen körülmények között ne kattintson.",
    mixedScriptAttack: "KRITIKUS: Ez a webcím különböző ábécék karaktereit keveri (pl. Latin és Cirill). Ez egy kifinomult hamisítási támadás, ahol azonos karakterek különböző írásrendszerekből származnak.",
    nonAsciiDomain: "Ez a domain nem-ASCII karaktereket tartalmaz (magas kockázat). A nemzetközi karakterek a domain nevekben használhatók legitim weboldalak megszemélyesítésére.",
    homoglyphCharactersDetected: "KRITIKUS: Homoglif karakterek észlelve ebben a domainben (kritikus kockázat). Latin betűknek látszó, de más írásrendszerekből származó karakterek (pl. Cirill) használatával próbálják megszemélyesíteni a legitim weboldalt."
  },
  tr: {
    dangerousJavascriptUri: "KRİTİK: Bu bağlantı çalıştırılabilir JavaScript kodu içeriyor (kritik risk). Tıklamak tarayıcınızda kötü amaçlı komut dosyaları çalıştırabilir.",
    dangerousVbscriptUri: "KRİTİK: Bu bağlantı çalıştırılabilir VBScript kodu içeriyor (kritik risk). Bu, Windows sistemlerini hedef alan tehlikeli bir saldırı tekniğidir.",
    dangerousDataUri: "KRİTİK: Bu bağlantı kod çalıştırabilecek gömülü veriler içeriyor (kritik risk). Data URI'ler oltalama veya kötü amaçlı yazılım dağıtımı için kullanılabilir.",
    criticalSecurityThreat: "KRİTİK GÜVENLİK TEHDİDİ: Bu bağlantı son derece tehlikeli olarak tanımlandı. Hiçbir koşulda tıklamayın.",
    mixedScriptAttack: "KRİTİK: Bu web adresi farklı alfabelerden karakterler karıştırıyor (örn: Latin ve Kiril). Bu, aynı görünen karakterlerin farklı yazı sistemlerinden geldiği sofistike bir kimlik sahteciliği saldırısıdır.",
    nonAsciiDomain: "Bu alan adı ASCII olmayan karakterler içeriyor (yüksek risk). Alan adlarındaki uluslararası karakterler meşru web sitelerini taklit etmek için kullanılabilir.",
    homoglyphCharactersDetected: "KRİTİK: Bu alan adında homoglif karakterler tespit edildi (kritik risk). Latin harflere benzeyen ancak başka yazı sistemlerinden gelen karakterler (örn: Kiril) meşru bir web sitesini taklit etmek için kullanılıyor."
  },
  el: {
    dangerousJavascriptUri: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει εκτελέσιμο κώδικα JavaScript (κρίσιμος κίνδυνος). Το κλικ μπορεί να εκτελέσει κακόβουλα σενάρια στον περιηγητή σας.",
    dangerousVbscriptUri: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει εκτελέσιμο κώδικα VBScript (κρίσιμος κίνδυνος). Αυτή είναι μια επικίνδυνη τεχνική επίθεσης που στοχεύει συστήματα Windows.",
    dangerousDataUri: "ΚΡΙΣΙΜΟ: Αυτός ο σύνδεσμος περιέχει ενσωματωμένα δεδομένα που μπορούν να εκτελέσουν κώδικα (κρίσιμος κίνδυνος). Τα Data URIs μπορούν να χρησιμοποιηθούν για phishing ή διανομή κακόβουλου λογισμικού.",
    criticalSecurityThreat: "ΚΡΙΣΙΜΗ ΑΠΕΙΛΗ ΑΣΦΑΛΕΙΑΣ: Αυτός ο σύνδεσμος έχει αναγνωριστεί ως εξαιρετικά επικίνδυνος. Μην κάνετε κλικ σε καμία περίπτωση.",
    mixedScriptAttack: "ΚΡΙΣΙΜΟ: Αυτή η διεύθυνση ιστού αναμειγνύει χαρακτήρες από διαφορετικά αλφάβητα (π.χ. Λατινικά και Κυριλλικά). Αυτή είναι μια εξελιγμένη επίθεση πλαστογράφησης όπου πανομοιότυποι χαρακτήρες προέρχονται από διαφορετικά συστήματα γραφής.",
    nonAsciiDomain: "Αυτός ο τομέας περιέχει χαρακτήρες που δεν είναι ASCII (υψηλός κίνδυνος). Οι διεθνείς χαρακτήρες στα ονόματα τομέων μπορούν να χρησιμοποιηθούν για την απομίμηση νόμιμων ιστοσελίδων.",
    homoglyphCharactersDetected: "ΚΡΙΣΙΜΟ: Εντοπίστηκαν χαρακτήρες ομογλύφων σε αυτόν τον τομέα (κρίσιμος κίνδυνος). Χαρακτήρες που μοιάζουν με λατινικά γράμματα αλλά προέρχονται από άλλα συστήματα γραφής (π.χ. Κυριλλικά) χρησιμοποιούνται για την απομίμηση νόμιμης ιστοσελίδας."
  },
  ar: {
    dangerousJavascriptUri: "حرج: يحتوي هذا الرابط على كود JavaScript قابل للتنفيذ (خطر حرج). قد يؤدي النقر إلى تشغيل نصوص برمجية ضارة في متصفحك.",
    dangerousVbscriptUri: "حرج: يحتوي هذا الرابط على كود VBScript قابل للتنفيذ (خطر حرج). هذه تقنية هجوم خطيرة تستهدف أنظمة Windows.",
    dangerousDataUri: "حرج: يحتوي هذا الرابط على بيانات مضمنة يمكنها تنفيذ كود (خطر حرج). يمكن استخدام Data URIs للتصيد الاحتيالي أو توزيع البرمجيات الخبيثة.",
    criticalSecurityThreat: "تهديد أمني حرج: تم تحديد هذا الرابط على أنه خطير للغاية. لا تنقر تحت أي ظرف.",
    mixedScriptAttack: "حرج: يمزج عنوان الويب هذا أحرفاً من أبجديات مختلفة (مثل اللاتينية والسيريلية). هذا هجوم انتحال متطور حيث تأتي الأحرف المتطابقة من نصوص مختلفة.",
    nonAsciiDomain: "يحتوي هذا النطاق على أحرف غير ASCII (خطر عالي). يمكن استخدام الأحرف الدولية في أسماء النطاقات لانتحال مواقع شرعية.",
    homoglyphCharactersDetected: "حرج: تم اكتشاف أحرف متشابهة في هذا النطاق (خطر حرج). يتم استخدام أحرف تشبه الحروف اللاتينية ولكنها من نصوص أخرى (مثل السيريلية) لانتحال موقع شرعي."
  },
  hi: {
    dangerousJavascriptUri: "गंभीर: इस लिंक में निष्पादन योग्य JavaScript कोड है (गंभीर जोखिम)। क्लिक करने से आपके ब्राउज़र में दुर्भावनापूर्ण स्क्रिप्ट चल सकती हैं।",
    dangerousVbscriptUri: "गंभीर: इस लिंक में निष्पादन योग्य VBScript कोड है (गंभीर जोखिम)। यह Windows सिस्टम को लक्षित करने वाली एक खतरनाक हमला तकनीक है।",
    dangerousDataUri: "गंभीर: इस लिंक में एम्बेडेड डेटा है जो कोड निष्पादित कर सकता है (गंभीर जोखिम)। Data URIs का उपयोग फ़िशिंग या मैलवेयर वितरण के लिए किया जा सकता है।",
    criticalSecurityThreat: "गंभीर सुरक्षा खतरा: इस लिंक को अत्यंत खतरनाक के रूप में पहचाना गया है। किसी भी परिस्थिति में क्लिक न करें।",
    mixedScriptAttack: "गंभीर: यह वेब पता विभिन्न वर्णमालाओं के वर्णों को मिलाता है (जैसे लैटिन और सिरिलिक)। यह एक परिष्कृत स्पूफिंग हमला है जहां समान दिखने वाले वर्ण विभिन्न स्क्रिप्ट से आते हैं।",
    nonAsciiDomain: "इस डोमेन में गैर-ASCII वर्ण हैं (उच्च जोखिम)। डोमेन नामों में अंतर्राष्ट्रीय वर्णों का उपयोग वैध वेबसाइटों का प्रतिरूपण करने के लिए किया जा सकता है।",
    homoglyphCharactersDetected: "गंभीर: इस डोमेन में होमोग्लिफ़ वर्ण पाए गए (गंभीर जोखिम)। लैटिन अक्षरों जैसे दिखने वाले लेकिन वास्तव में अन्य स्क्रिप्ट के वर्ण (जैसे सिरिलिक) का उपयोग एक वैध वेबसाइट का प्रतिरूपण करने के लिए किया जा रहा है।"
  },
  th: {
    dangerousJavascriptUri: "วิกฤต: ลิงก์นี้มีโค้ด JavaScript ที่สามารถรันได้ (ความเสี่ยงวิกฤต) การคลิกอาจรันสคริปต์ที่เป็นอันตรายในเบราว์เซอร์ของคุณ",
    dangerousVbscriptUri: "วิกฤต: ลิงก์นี้มีโค้ด VBScript ที่สามารถรันได้ (ความเสี่ยงวิกฤต) นี่เป็นเทคนิคการโจมตีที่อันตรายซึ่งมุ่งเป้าไปที่ระบบ Windows",
    dangerousDataUri: "วิกฤต: ลิงก์นี้มีข้อมูลฝังตัวที่สามารถรันโค้ดได้ (ความเสี่ยงวิกฤต) Data URIs สามารถใช้สำหรับฟิชชิ่งหรือแพร่กระจายมัลแวร์",
    criticalSecurityThreat: "ภัยคุกคามด้านความปลอดภัยวิกฤต: ลิงก์นี้ถูกระบุว่าเป็นอันตรายอย่างยิ่ง อย่าคลิกไม่ว่าในกรณีใด",
    mixedScriptAttack: "วิกฤต: ที่อยู่เว็บนี้ผสมอักขระจากตัวอักษรต่างกัน (เช่น ละตินและซีริลลิก) นี่เป็นการโจมตีปลอมแปลงที่ซับซ้อนซึ่งอักขระที่เหมือนกันมาจากระบบการเขียนที่ต่างกัน",
    nonAsciiDomain: "โดเมนนี้มีอักขระที่ไม่ใช่ ASCII (ความเสี่ยงสูง) อักขระสากลในชื่อโดเมนสามารถใช้เพื่อปลอมแปลงเว็บไซต์ที่ถูกต้อง",
    homoglyphCharactersDetected: "วิกฤต: ตรวจพบอักขระโฮโมกลิฟในโดเมนนี้ (ความเสี่ยงวิกฤต) อักขระที่ดูเหมือนตัวอักษรละตินแต่จริงๆ มาจากระบบการเขียนอื่น (เช่น ซีริลลิก) ถูกใช้เพื่อปลอมแปลงเว็บไซต์ที่ถูกต้อง"
  },
  vi: {
    dangerousJavascriptUri: "NGHIÊM TRỌNG: Liên kết này chứa mã JavaScript có thể thực thi (rủi ro nghiêm trọng). Nhấp có thể chạy các tập lệnh độc hại trong trình duyệt của bạn.",
    dangerousVbscriptUri: "NGHIÊM TRỌNG: Liên kết này chứa mã VBScript có thể thực thi (rủi ro nghiêm trọng). Đây là kỹ thuật tấn công nguy hiểm nhắm vào hệ thống Windows.",
    dangerousDataUri: "NGHIÊM TRỌNG: Liên kết này chứa dữ liệu nhúng có thể thực thi mã (rủi ro nghiêm trọng). Data URIs có thể được sử dụng cho lừa đảo hoặc phân phối phần mềm độc hại.",
    criticalSecurityThreat: "MỐI ĐE DỌA BẢO MẬT NGHIÊM TRỌNG: Liên kết này đã được xác định là cực kỳ nguy hiểm. Không nhấp trong bất kỳ trường hợp nào.",
    mixedScriptAttack: "NGHIÊM TRỌNG: Địa chỉ web này trộn lẫn các ký tự từ các bảng chữ cái khác nhau (ví dụ: Latin và Cyrillic). Đây là một cuộc tấn công giả mạo tinh vi nơi các ký tự giống hệt nhau đến từ các hệ thống chữ viết khác nhau.",
    nonAsciiDomain: "Tên miền này chứa các ký tự không phải ASCII (rủi ro cao). Các ký tự quốc tế trong tên miền có thể được sử dụng để mạo danh các trang web hợp pháp.",
    homoglyphCharactersDetected: "NGHIÊM TRỌNG: Phát hiện các ký tự homoglyph trong tên miền này (rủi ro nghiêm trọng). Các ký tự trông giống chữ cái Latin nhưng thực sự từ các hệ thống chữ viết khác (ví dụ: Cyrillic) đang được sử dụng để mạo danh một trang web hợp pháp."
  },
  id: {
    dangerousJavascriptUri: "KRITIS: Tautan ini berisi kode JavaScript yang dapat dieksekusi (risiko kritis). Mengklik dapat menjalankan skrip berbahaya di browser Anda.",
    dangerousVbscriptUri: "KRITIS: Tautan ini berisi kode VBScript yang dapat dieksekusi (risiko kritis). Ini adalah teknik serangan berbahaya yang menargetkan sistem Windows.",
    dangerousDataUri: "KRITIS: Tautan ini berisi data tertanam yang dapat mengeksekusi kode (risiko kritis). Data URI dapat digunakan untuk phishing atau distribusi malware.",
    criticalSecurityThreat: "ANCAMAN KEAMANAN KRITIS: Tautan ini telah diidentifikasi sebagai sangat berbahaya. Jangan klik dalam keadaan apapun.",
    mixedScriptAttack: "KRITIS: Alamat web ini mencampur karakter dari alfabet berbeda (misalnya Latin dan Sirilik). Ini adalah serangan spoofing canggih di mana karakter yang identik berasal dari skrip berbeda.",
    nonAsciiDomain: "Domain ini berisi karakter non-ASCII (risiko tinggi). Karakter internasional dalam nama domain dapat digunakan untuk menyamar sebagai situs web yang sah.",
    homoglyphCharactersDetected: "KRITIS: Karakter homoglif terdeteksi di domain ini (risiko kritis). Karakter yang terlihat seperti huruf Latin tetapi sebenarnya dari skrip lain (misalnya Sirilik) digunakan untuk menyamar sebagai situs web yang sah."
  },
  ja: {
    dangerousJavascriptUri: "重大: このリンクには実行可能なJavaScriptコードが含まれています（重大リスク）。クリックするとブラウザで悪意のあるスクリプトが実行される可能性があります。",
    dangerousVbscriptUri: "重大: このリンクには実行可能なVBScriptコードが含まれています（重大リスク）。これはWindowsシステムを標的とした危険な攻撃手法です。",
    dangerousDataUri: "重大: このリンクにはコードを実行できる埋め込みデータが含まれています（重大リスク）。Data URIはフィッシングやマルウェア配布に使用される可能性があります。",
    criticalSecurityThreat: "重大なセキュリティ脅威: このリンクは非常に危険と特定されました。いかなる状況でもクリックしないでください。",
    mixedScriptAttack: "重大: このウェブアドレスは異なるアルファベットの文字を混在させています（例：ラテン文字とキリル文字）。これは同一に見える文字が異なる文字体系から来る高度ななりすまし攻撃です。",
    nonAsciiDomain: "このドメインには非ASCII文字が含まれています（高リスク）。ドメイン名の国際文字は、正規のウェブサイトになりすますために使用される可能性があります。",
    homoglyphCharactersDetected: "重大: このドメインでホモグリフ文字が検出されました（重大リスク）。ラテン文字に見えるが実際は他の文字体系の文字（例：キリル文字）が正規のウェブサイトになりすますために使用されています。"
  },
  ko: {
    dangerousJavascriptUri: "심각: 이 링크에는 실행 가능한 JavaScript 코드가 포함되어 있습니다 (심각한 위험). 클릭하면 브라우저에서 악성 스크립트가 실행될 수 있습니다.",
    dangerousVbscriptUri: "심각: 이 링크에는 실행 가능한 VBScript 코드가 포함되어 있습니다 (심각한 위험). 이것은 Windows 시스템을 대상으로 하는 위험한 공격 기법입니다.",
    dangerousDataUri: "심각: 이 링크에는 코드를 실행할 수 있는 임베디드 데이터가 포함되어 있습니다 (심각한 위험). Data URI는 피싱이나 악성코드 배포에 사용될 수 있습니다.",
    criticalSecurityThreat: "심각한 보안 위협: 이 링크는 매우 위험한 것으로 확인되었습니다. 어떤 상황에서도 클릭하지 마십시오.",
    mixedScriptAttack: "심각: 이 웹 주소는 다른 알파벳의 문자를 혼합합니다 (예: 라틴어와 키릴 문자). 이것은 동일하게 보이는 문자가 다른 스크립트에서 오는 정교한 스푸핑 공격입니다.",
    nonAsciiDomain: "이 도메인에는 비ASCII 문자가 포함되어 있습니다 (높은 위험). 도메인 이름의 국제 문자는 합법적인 웹사이트를 사칭하는 데 사용될 수 있습니다.",
    homoglyphCharactersDetected: "심각: 이 도메인에서 호모글리프 문자가 감지되었습니다 (심각한 위험). 라틴 문자처럼 보이지만 실제로는 다른 스크립트의 문자 (예: 키릴 문자)가 합법적인 웹사이트를 사칭하는 데 사용되고 있습니다."
  },
  zh: {
    dangerousJavascriptUri: "严重：此链接包含可执行的JavaScript代码（严重风险）。点击可能会在您的浏览器中运行恶意脚本。",
    dangerousVbscriptUri: "严重：此链接包含可执行的VBScript代码（严重风险）。这是一种针对Windows系统的危险攻击技术。",
    dangerousDataUri: "严重：此链接包含可能执行代码的嵌入数据（严重风险）。Data URI可用于网络钓鱼或恶意软件分发。",
    criticalSecurityThreat: "严重安全威胁：此链接已被识别为极度危险。在任何情况下都不要点击。",
    mixedScriptAttack: "严重：此网址混合了来自不同字母表的字符（例如拉丁文和西里尔文）。这是一种复杂的欺骗攻击，其中看起来相同的字符来自不同的书写系统。",
    nonAsciiDomain: "此域名包含非ASCII字符（高风险）。域名中的国际字符可用于冒充合法网站。",
    homoglyphCharactersDetected: "严重：在此域名中检测到同形字符（严重风险）。看起来像拉丁字母但实际上来自其他书写系统（例如西里尔文）的字符正被用于冒充合法网站。"
  }
};

// Keys to add
const keysToAdd = [
  'dangerousJavascriptUri',
  'dangerousVbscriptUri',
  'dangerousDataUri',
  'criticalSecurityThreat',
  'mixedScriptAttack',
  'nonAsciiDomain',
  'homoglyphCharactersDetected'
];

// Process each locale
const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && f !== 'en'; // Skip English (already updated)
});

console.log(`Found ${locales.length} non-English locales to update`);

let updated = 0;
let skipped = 0;

locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');

  if (!fs.existsSync(messagesPath)) {
    console.log(`⚠️ Skipping ${locale}: messages.json not found`);
    skipped++;
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

console.log(`\n📊 Summary: ${updated} locales updated, ${skipped} skipped`);
