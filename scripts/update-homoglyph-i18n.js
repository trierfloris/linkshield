/**
 * Update homoglyphAttack message in all locales with proper translations
 * Including "(high risk)" indicator
 */

const fs = require('fs');
const path = require('path');

const LOCALES_DIR = path.join(__dirname, '..', '_locales');

// Professional translations for homoglyphAttack with (high risk) indicator
const translations = {
  ar: "يحتوي هذا العنوان على أحرف متشابهة (خطر عالي). تأكد من أنك على الموقع الصحيح قبل إدخال أي معلومات.",
  cs: "Tato adresa obsahuje podobně vypadající znaky (vysoké riziko). Před zadáním jakýchkoli informací ověřte, že jste na správném webu.",
  de: "Diese Adresse enthält ähnlich aussehende Zeichen (hohes Risiko). Überprüfen Sie, ob Sie auf der richtigen Website sind, bevor Sie Informationen eingeben.",
  el: "Αυτή η διεύθυνση περιέχει χαρακτήρες που μοιάζουν (υψηλός κίνδυνος). Επαληθεύστε ότι βρίσκεστε στη σωστή ιστοσελίδα πριν εισάγετε οποιαδήποτε πληροφορία.",
  en: "This address contains look-alike characters (high risk). Verify you're on the correct site before entering any information.",
  es: "Esta dirección contiene caracteres similares (alto riesgo). Verifique que está en el sitio correcto antes de ingresar cualquier información.",
  fr: "Cette adresse contient des caractères similaires (risque élevé). Vérifiez que vous êtes sur le bon site avant de saisir des informations.",
  hi: "इस पते में समान दिखने वाले अक्षर हैं (उच्च जोखिम)। कोई भी जानकारी दर्ज करने से पहले सुनिश्चित करें कि आप सही साइट पर हैं।",
  hu: "Ez a cím hasonló karaktereket tartalmaz (magas kockázat). Ellenőrizze, hogy a megfelelő oldalon van-e, mielőtt bármilyen információt megadna.",
  id: "Alamat ini mengandung karakter yang mirip (risiko tinggi). Pastikan Anda berada di situs yang benar sebelum memasukkan informasi apa pun.",
  it: "Questo indirizzo contiene caratteri simili (alto rischio). Verifica di essere sul sito corretto prima di inserire qualsiasi informazione.",
  ja: "このアドレスには類似した文字が含まれています（高リスク）。情報を入力する前に、正しいサイトにいることを確認してください。",
  ko: "이 주소에는 유사한 문자가 포함되어 있습니다 (높은 위험). 정보를 입력하기 전에 올바른 사이트에 있는지 확인하세요.",
  nl: "Dit adres bevat op elkaar lijkende tekens (hoog risico). Controleer of u op de juiste site bent voordat u informatie invoert.",
  pl: "Ten adres zawiera podobne znaki (wysokie ryzyko). Upewnij się, że jesteś na właściwej stronie przed wprowadzeniem jakichkolwiek informacji.",
  pt: "Este endereço contém caracteres semelhantes (alto risco). Verifique se está no site correto antes de inserir qualquer informação.",
  pt_BR: "Este endereço contém caracteres semelhantes (alto risco). Verifique se você está no site correto antes de inserir qualquer informação.",
  ro: "Această adresă conține caractere similare (risc ridicat). Verificați că sunteți pe site-ul corect înainte de a introduce orice informație.",
  ru: "Этот адрес содержит похожие символы (высокий риск). Убедитесь, что вы находитесь на правильном сайте, прежде чем вводить информацию.",
  th: "ที่อยู่นี้มีตัวอักษรที่คล้ายกัน (ความเสี่ยงสูง) โปรดตรวจสอบว่าคุณอยู่บนเว็บไซต์ที่ถูกต้องก่อนกรอกข้อมูลใดๆ",
  tr: "Bu adres benzer görünümlü karakterler içeriyor (yüksek risk). Herhangi bir bilgi girmeden önce doğru sitede olduğunuzdan emin olun.",
  uk: "Ця адреса містить схожі символи (високий ризик). Переконайтеся, що ви на правильному сайті, перш ніж вводити будь-яку інформацію.",
  vi: "Địa chỉ này chứa các ký tự tương tự (rủi ro cao). Xác minh bạn đang ở đúng trang web trước khi nhập bất kỳ thông tin nào.",
  zh: "此地址包含相似字符（高风险）。在输入任何信息之前，请确认您在正确的网站上。"
};

let updated = 0;
let errors = [];

// Get all locale directories
const locales = fs.readdirSync(LOCALES_DIR).filter(dir => {
  const messagesPath = path.join(LOCALES_DIR, dir, 'messages.json');
  return fs.existsSync(messagesPath);
});

console.log(`Found ${locales.length} locales to update\n`);

locales.forEach(locale => {
  const messagesPath = path.join(LOCALES_DIR, locale, 'messages.json');

  try {
    const content = fs.readFileSync(messagesPath, 'utf8');
    const messages = JSON.parse(content);

    if (translations[locale]) {
      // Update the homoglyphAttack message
      if (messages.homoglyphAttack) {
        const oldMessage = messages.homoglyphAttack.message;
        messages.homoglyphAttack.message = translations[locale];

        // Write back
        fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');

        console.log(`✓ ${locale}: Updated homoglyphAttack`);
        console.log(`  Old: ${oldMessage.substring(0, 50)}...`);
        console.log(`  New: ${translations[locale].substring(0, 50)}...`);
        updated++;
      } else {
        // Add the key if it doesn't exist
        messages.homoglyphAttack = {
          message: translations[locale]
        };
        fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');
        console.log(`✓ ${locale}: Added homoglyphAttack`);
        updated++;
      }
    } else {
      console.log(`⚠ ${locale}: No translation available, skipping`);
    }
  } catch (error) {
    console.log(`✗ ${locale}: Error - ${error.message}`);
    errors.push({ locale, error: error.message });
  }
});

console.log(`\n========================================`);
console.log(`SUMMARY`);
console.log(`========================================`);
console.log(`Updated: ${updated}/${locales.length} locales`);
if (errors.length > 0) {
  console.log(`Errors: ${errors.length}`);
  errors.forEach(e => console.log(`  - ${e.locale}: ${e.error}`));
}
console.log(`\nDone!`);
