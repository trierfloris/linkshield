/**
 * Add WebTransport i18n keys to all locale files
 */
const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');
const locales = fs.readdirSync(localesDir);

// Translations for each locale
const translations = {
  en: {
    webTransportWarningTitle: 'Suspicious Network Activity',
    webTransportWarningMessage: 'This page is using advanced network protocols in a potentially suspicious way.',
    webTransportDirectIP: 'Connection to direct IP address detected.',
    webTransportHighPort: 'Connection to unusual high port number.',
    webTransportRandomSubdomain: 'Connection to suspicious random subdomain (possible C2 server).',
    webTransportFreeTLD: 'Connection to free TLD domain (commonly used for malware).',
    webTransportHighConnectionRate: 'Unusually high connection rate detected.',
    webTransportHighDatagramRate: 'Unusually high data transfer rate detected.',
    webTransportObfuscatedUrl: 'Obfuscated or encoded URL detected.',
    webTransportInvalidUrl: 'Invalid or malformed connection URL.'
  },
  nl: {
    webTransportWarningTitle: 'Verdachte netwerkactiviteit',
    webTransportWarningMessage: 'Deze pagina gebruikt geavanceerde netwerkprotocollen op een mogelijk verdachte manier.',
    webTransportDirectIP: 'Verbinding naar direct IP-adres gedetecteerd.',
    webTransportHighPort: 'Verbinding naar ongebruikelijk hoog poortnummer.',
    webTransportRandomSubdomain: 'Verbinding naar verdacht willekeurig subdomein (mogelijk C2-server).',
    webTransportFreeTLD: 'Verbinding naar gratis TLD-domein (vaak gebruikt voor malware).',
    webTransportHighConnectionRate: 'Ongewoon hoge verbindingsfrequentie gedetecteerd.',
    webTransportHighDatagramRate: 'Ongewoon hoge dataoverdrachtsnelheid gedetecteerd.',
    webTransportObfuscatedUrl: 'Versleutelde of gecodeerde URL gedetecteerd.',
    webTransportInvalidUrl: 'Ongeldige of misvormde verbindings-URL.'
  },
  de: {
    webTransportWarningTitle: 'Verdächtige Netzwerkaktivität',
    webTransportWarningMessage: 'Diese Seite verwendet fortschrittliche Netzwerkprotokolle auf potenziell verdächtige Weise.',
    webTransportDirectIP: 'Verbindung zu direkter IP-Adresse erkannt.',
    webTransportHighPort: 'Verbindung zu ungewöhnlich hoher Portnummer.',
    webTransportRandomSubdomain: 'Verbindung zu verdächtiger zufälliger Subdomain (möglicher C2-Server).',
    webTransportFreeTLD: 'Verbindung zu kostenloser TLD-Domain (häufig für Malware verwendet).',
    webTransportHighConnectionRate: 'Ungewöhnlich hohe Verbindungsrate erkannt.',
    webTransportHighDatagramRate: 'Ungewöhnlich hohe Datenübertragungsrate erkannt.',
    webTransportObfuscatedUrl: 'Verschleierte oder codierte URL erkannt.',
    webTransportInvalidUrl: 'Ungültige oder fehlerhafte Verbindungs-URL.'
  },
  fr: {
    webTransportWarningTitle: 'Activité réseau suspecte',
    webTransportWarningMessage: 'Cette page utilise des protocoles réseau avancés de manière potentiellement suspecte.',
    webTransportDirectIP: 'Connexion à une adresse IP directe détectée.',
    webTransportHighPort: 'Connexion à un numéro de port inhabituellement élevé.',
    webTransportRandomSubdomain: 'Connexion à un sous-domaine aléatoire suspect (serveur C2 possible).',
    webTransportFreeTLD: 'Connexion à un domaine TLD gratuit (souvent utilisé pour les malwares).',
    webTransportHighConnectionRate: 'Taux de connexion anormalement élevé détecté.',
    webTransportHighDatagramRate: 'Taux de transfert de données anormalement élevé détecté.',
    webTransportObfuscatedUrl: 'URL obscurcie ou encodée détectée.',
    webTransportInvalidUrl: 'URL de connexion invalide ou malformée.'
  },
  es: {
    webTransportWarningTitle: 'Actividad de red sospechosa',
    webTransportWarningMessage: 'Esta página está utilizando protocolos de red avanzados de manera potencialmente sospechosa.',
    webTransportDirectIP: 'Conexión a dirección IP directa detectada.',
    webTransportHighPort: 'Conexión a número de puerto inusualmente alto.',
    webTransportRandomSubdomain: 'Conexión a subdominio aleatorio sospechoso (posible servidor C2).',
    webTransportFreeTLD: 'Conexión a dominio TLD gratuito (comúnmente usado para malware).',
    webTransportHighConnectionRate: 'Tasa de conexión inusualmente alta detectada.',
    webTransportHighDatagramRate: 'Tasa de transferencia de datos inusualmente alta detectada.',
    webTransportObfuscatedUrl: 'URL ofuscada o codificada detectada.',
    webTransportInvalidUrl: 'URL de conexión inválida o malformada.'
  },
  it: {
    webTransportWarningTitle: 'Attività di rete sospetta',
    webTransportWarningMessage: 'Questa pagina utilizza protocolli di rete avanzati in modo potenzialmente sospetto.',
    webTransportDirectIP: 'Rilevata connessione a indirizzo IP diretto.',
    webTransportHighPort: 'Connessione a numero di porta insolitamente alto.',
    webTransportRandomSubdomain: 'Connessione a sottodominio casuale sospetto (possibile server C2).',
    webTransportFreeTLD: 'Connessione a dominio TLD gratuito (comunemente usato per malware).',
    webTransportHighConnectionRate: 'Rilevata frequenza di connessione insolitamente alta.',
    webTransportHighDatagramRate: 'Rilevata velocità di trasferimento dati insolitamente alta.',
    webTransportObfuscatedUrl: 'Rilevato URL offuscato o codificato.',
    webTransportInvalidUrl: 'URL di connessione non valido o malformato.'
  },
  pt: {
    webTransportWarningTitle: 'Atividade de rede suspeita',
    webTransportWarningMessage: 'Esta página está usando protocolos de rede avançados de forma potencialmente suspeita.',
    webTransportDirectIP: 'Conexão com endereço IP direto detectada.',
    webTransportHighPort: 'Conexão com número de porta invulgarmente alto.',
    webTransportRandomSubdomain: 'Conexão com subdomínio aleatório suspeito (possível servidor C2).',
    webTransportFreeTLD: 'Conexão com domínio TLD gratuito (comumente usado para malware).',
    webTransportHighConnectionRate: 'Taxa de conexão invulgarmente alta detectada.',
    webTransportHighDatagramRate: 'Taxa de transferência de dados invulgarmente alta detectada.',
    webTransportObfuscatedUrl: 'URL ofuscado ou codificado detectado.',
    webTransportInvalidUrl: 'URL de conexão inválido ou malformado.'
  },
  pt_BR: {
    webTransportWarningTitle: 'Atividade de rede suspeita',
    webTransportWarningMessage: 'Esta página está usando protocolos de rede avançados de forma potencialmente suspeita.',
    webTransportDirectIP: 'Conexão com endereço IP direto detectada.',
    webTransportHighPort: 'Conexão com número de porta incomumente alto.',
    webTransportRandomSubdomain: 'Conexão com subdomínio aleatório suspeito (possível servidor C2).',
    webTransportFreeTLD: 'Conexão com domínio TLD gratuito (comumente usado para malware).',
    webTransportHighConnectionRate: 'Taxa de conexão incomumente alta detectada.',
    webTransportHighDatagramRate: 'Taxa de transferência de dados incomumente alta detectada.',
    webTransportObfuscatedUrl: 'URL ofuscado ou codificado detectado.',
    webTransportInvalidUrl: 'URL de conexão inválido ou malformado.'
  },
  ru: {
    webTransportWarningTitle: 'Подозрительная сетевая активность',
    webTransportWarningMessage: 'Эта страница использует продвинутые сетевые протоколы потенциально подозрительным образом.',
    webTransportDirectIP: 'Обнаружено подключение к прямому IP-адресу.',
    webTransportHighPort: 'Подключение к необычно высокому номеру порта.',
    webTransportRandomSubdomain: 'Подключение к подозрительному случайному поддомену (возможный C2-сервер).',
    webTransportFreeTLD: 'Подключение к бесплатному TLD-домену (часто используется для вредоносного ПО).',
    webTransportHighConnectionRate: 'Обнаружена необычно высокая частота подключений.',
    webTransportHighDatagramRate: 'Обнаружена необычно высокая скорость передачи данных.',
    webTransportObfuscatedUrl: 'Обнаружен запутанный или закодированный URL.',
    webTransportInvalidUrl: 'Недействительный или неправильный URL подключения.'
  },
  uk: {
    webTransportWarningTitle: 'Підозріла мережева активність',
    webTransportWarningMessage: 'Ця сторінка використовує просунуті мережеві протоколи потенційно підозрілим чином.',
    webTransportDirectIP: 'Виявлено підключення до прямої IP-адреси.',
    webTransportHighPort: 'Підключення до незвично високого номера порту.',
    webTransportRandomSubdomain: 'Підключення до підозрілого випадкового піддомену (можливий C2-сервер).',
    webTransportFreeTLD: 'Підключення до безкоштовного TLD-домену (часто використовується для шкідливого ПЗ).',
    webTransportHighConnectionRate: 'Виявлено незвично високу частоту підключень.',
    webTransportHighDatagramRate: 'Виявлено незвично високу швидкість передачі даних.',
    webTransportObfuscatedUrl: 'Виявлено заплутаний або закодований URL.',
    webTransportInvalidUrl: 'Недійсний або неправильний URL підключення.'
  },
  zh: {
    webTransportWarningTitle: '可疑网络活动',
    webTransportWarningMessage: '此页面正在以潜在可疑的方式使用高级网络协议。',
    webTransportDirectIP: '检测到直接IP地址连接。',
    webTransportHighPort: '连接到异常高的端口号。',
    webTransportRandomSubdomain: '连接到可疑的随机子域名（可能是C2服务器）。',
    webTransportFreeTLD: '连接到免费TLD域名（常用于恶意软件）。',
    webTransportHighConnectionRate: '检测到异常高的连接率。',
    webTransportHighDatagramRate: '检测到异常高的数据传输率。',
    webTransportObfuscatedUrl: '检测到混淆或编码的URL。',
    webTransportInvalidUrl: '无效或格式错误的连接URL。'
  },
  ja: {
    webTransportWarningTitle: '疑わしいネットワークアクティビティ',
    webTransportWarningMessage: 'このページは高度なネットワークプロトコルを潜在的に疑わしい方法で使用しています。',
    webTransportDirectIP: '直接IPアドレスへの接続が検出されました。',
    webTransportHighPort: '異常に高いポート番号への接続。',
    webTransportRandomSubdomain: '疑わしいランダムサブドメインへの接続（C2サーバーの可能性）。',
    webTransportFreeTLD: '無料TLDドメインへの接続（マルウェアに頻繁に使用される）。',
    webTransportHighConnectionRate: '異常に高い接続率が検出されました。',
    webTransportHighDatagramRate: '異常に高いデータ転送率が検出されました。',
    webTransportObfuscatedUrl: '難読化またはエンコードされたURLが検出されました。',
    webTransportInvalidUrl: '無効または不正な接続URL。'
  },
  ko: {
    webTransportWarningTitle: '의심스러운 네트워크 활동',
    webTransportWarningMessage: '이 페이지는 잠재적으로 의심스러운 방식으로 고급 네트워크 프로토콜을 사용하고 있습니다.',
    webTransportDirectIP: '직접 IP 주소 연결이 감지되었습니다.',
    webTransportHighPort: '비정상적으로 높은 포트 번호로의 연결.',
    webTransportRandomSubdomain: '의심스러운 무작위 하위 도메인 연결 (C2 서버 가능성).',
    webTransportFreeTLD: '무료 TLD 도메인 연결 (맬웨어에 자주 사용됨).',
    webTransportHighConnectionRate: '비정상적으로 높은 연결률이 감지되었습니다.',
    webTransportHighDatagramRate: '비정상적으로 높은 데이터 전송률이 감지되었습니다.',
    webTransportObfuscatedUrl: '난독화되거나 인코딩된 URL이 감지되었습니다.',
    webTransportInvalidUrl: '잘못되었거나 형식이 잘못된 연결 URL.'
  },
  ar: {
    webTransportWarningTitle: 'نشاط شبكة مشبوه',
    webTransportWarningMessage: 'هذه الصفحة تستخدم بروتوكولات شبكة متقدمة بطريقة مشبوهة محتملة.',
    webTransportDirectIP: 'تم اكتشاف اتصال بعنوان IP مباشر.',
    webTransportHighPort: 'اتصال برقم منفذ عالي بشكل غير عادي.',
    webTransportRandomSubdomain: 'اتصال بنطاق فرعي عشوائي مشبوه (خادم C2 محتمل).',
    webTransportFreeTLD: 'اتصال بنطاق TLD مجاني (يستخدم عادة للبرامج الضارة).',
    webTransportHighConnectionRate: 'تم اكتشاف معدل اتصال عالي بشكل غير عادي.',
    webTransportHighDatagramRate: 'تم اكتشاف معدل نقل بيانات عالي بشكل غير عادي.',
    webTransportObfuscatedUrl: 'تم اكتشاف عنوان URL مشفر أو مخفي.',
    webTransportInvalidUrl: 'عنوان URL للاتصال غير صالح أو مشوه.'
  },
  hi: {
    webTransportWarningTitle: 'संदिग्ध नेटवर्क गतिविधि',
    webTransportWarningMessage: 'यह पृष्ठ संभावित संदिग्ध तरीके से उन्नत नेटवर्क प्रोटोकॉल का उपयोग कर रहा है।',
    webTransportDirectIP: 'सीधे IP पते से कनेक्शन का पता चला।',
    webTransportHighPort: 'असामान्य रूप से उच्च पोर्ट नंबर से कनेक्शन।',
    webTransportRandomSubdomain: 'संदिग्ध यादृच्छिक सबडोमेन से कनेक्शन (संभावित C2 सर्वर)।',
    webTransportFreeTLD: 'मुफ्त TLD डोमेन से कनेक्शन (आमतौर पर मैलवेयर के लिए उपयोग किया जाता है)।',
    webTransportHighConnectionRate: 'असामान्य रूप से उच्च कनेक्शन दर का पता चला।',
    webTransportHighDatagramRate: 'असामान्य रूप से उच्च डेटा ट्रांसफर दर का पता चला।',
    webTransportObfuscatedUrl: 'अस्पष्ट या एन्कोडेड URL का पता चला।',
    webTransportInvalidUrl: 'अमान्य या विकृत कनेक्शन URL।'
  },
  th: {
    webTransportWarningTitle: 'กิจกรรมเครือข่ายที่น่าสงสัย',
    webTransportWarningMessage: 'หน้านี้กำลังใช้โปรโตคอลเครือข่ายขั้นสูงในลักษณะที่อาจน่าสงสัย',
    webTransportDirectIP: 'ตรวจพบการเชื่อมต่อไปยังที่อยู่ IP โดยตรง',
    webTransportHighPort: 'การเชื่อมต่อไปยังหมายเลขพอร์ตที่สูงผิดปกติ',
    webTransportRandomSubdomain: 'การเชื่อมต่อไปยังซับโดเมนสุ่มที่น่าสงสัย (อาจเป็นเซิร์ฟเวอร์ C2)',
    webTransportFreeTLD: 'การเชื่อมต่อไปยังโดเมน TLD ฟรี (มักใช้สำหรับมัลแวร์)',
    webTransportHighConnectionRate: 'ตรวจพบอัตราการเชื่อมต่อที่สูงผิดปกติ',
    webTransportHighDatagramRate: 'ตรวจพบอัตราการถ่ายโอนข้อมูลที่สูงผิดปกติ',
    webTransportObfuscatedUrl: 'ตรวจพบ URL ที่ถูกปิดบังหรือเข้ารหัส',
    webTransportInvalidUrl: 'URL การเชื่อมต่อไม่ถูกต้องหรือผิดรูปแบบ'
  },
  vi: {
    webTransportWarningTitle: 'Hoạt động mạng đáng ngờ',
    webTransportWarningMessage: 'Trang này đang sử dụng các giao thức mạng nâng cao theo cách có thể đáng ngờ.',
    webTransportDirectIP: 'Phát hiện kết nối đến địa chỉ IP trực tiếp.',
    webTransportHighPort: 'Kết nối đến số cổng cao bất thường.',
    webTransportRandomSubdomain: 'Kết nối đến tên miền phụ ngẫu nhiên đáng ngờ (có thể là máy chủ C2).',
    webTransportFreeTLD: 'Kết nối đến tên miền TLD miễn phí (thường được sử dụng cho phần mềm độc hại).',
    webTransportHighConnectionRate: 'Phát hiện tốc độ kết nối cao bất thường.',
    webTransportHighDatagramRate: 'Phát hiện tốc độ truyền dữ liệu cao bất thường.',
    webTransportObfuscatedUrl: 'Phát hiện URL bị che giấu hoặc mã hóa.',
    webTransportInvalidUrl: 'URL kết nối không hợp lệ hoặc sai định dạng.'
  },
  id: {
    webTransportWarningTitle: 'Aktivitas jaringan mencurigakan',
    webTransportWarningMessage: 'Halaman ini menggunakan protokol jaringan canggih dengan cara yang berpotensi mencurigakan.',
    webTransportDirectIP: 'Koneksi ke alamat IP langsung terdeteksi.',
    webTransportHighPort: 'Koneksi ke nomor port yang sangat tinggi.',
    webTransportRandomSubdomain: 'Koneksi ke subdomain acak yang mencurigakan (kemungkinan server C2).',
    webTransportFreeTLD: 'Koneksi ke domain TLD gratis (sering digunakan untuk malware).',
    webTransportHighConnectionRate: 'Tingkat koneksi yang sangat tinggi terdeteksi.',
    webTransportHighDatagramRate: 'Tingkat transfer data yang sangat tinggi terdeteksi.',
    webTransportObfuscatedUrl: 'URL yang disamarkan atau dikodekan terdeteksi.',
    webTransportInvalidUrl: 'URL koneksi tidak valid atau salah format.'
  },
  tr: {
    webTransportWarningTitle: 'Şüpheli ağ etkinliği',
    webTransportWarningMessage: 'Bu sayfa potansiyel olarak şüpheli bir şekilde gelişmiş ağ protokolleri kullanıyor.',
    webTransportDirectIP: 'Doğrudan IP adresine bağlantı algılandı.',
    webTransportHighPort: 'Alışılmadık derecede yüksek port numarasına bağlantı.',
    webTransportRandomSubdomain: 'Şüpheli rastgele alt alan adına bağlantı (olası C2 sunucusu).',
    webTransportFreeTLD: 'Ücretsiz TLD alan adına bağlantı (yaygın olarak kötü amaçlı yazılım için kullanılır).',
    webTransportHighConnectionRate: 'Alışılmadık derecede yüksek bağlantı hızı algılandı.',
    webTransportHighDatagramRate: 'Alışılmadık derecede yüksek veri aktarım hızı algılandı.',
    webTransportObfuscatedUrl: 'Gizlenmiş veya kodlanmış URL algılandı.',
    webTransportInvalidUrl: 'Geçersiz veya hatalı biçimlendirilmiş bağlantı URL\'si.'
  },
  pl: {
    webTransportWarningTitle: 'Podejrzana aktywność sieciowa',
    webTransportWarningMessage: 'Ta strona używa zaawansowanych protokołów sieciowych w potencjalnie podejrzany sposób.',
    webTransportDirectIP: 'Wykryto połączenie z bezpośrednim adresem IP.',
    webTransportHighPort: 'Połączenie z niezwykle wysokim numerem portu.',
    webTransportRandomSubdomain: 'Połączenie z podejrzaną losową subdomeną (możliwy serwer C2).',
    webTransportFreeTLD: 'Połączenie z darmową domeną TLD (często używaną dla złośliwego oprogramowania).',
    webTransportHighConnectionRate: 'Wykryto niezwykle wysoką częstotliwość połączeń.',
    webTransportHighDatagramRate: 'Wykryto niezwykle wysoką szybkość transferu danych.',
    webTransportObfuscatedUrl: 'Wykryto zaciemniony lub zakodowany URL.',
    webTransportInvalidUrl: 'Nieprawidłowy lub zniekształcony URL połączenia.'
  },
  cs: {
    webTransportWarningTitle: 'Podezřelá síťová aktivita',
    webTransportWarningMessage: 'Tato stránka používá pokročilé síťové protokoly potenciálně podezřelým způsobem.',
    webTransportDirectIP: 'Detekováno připojení k přímé IP adrese.',
    webTransportHighPort: 'Připojení k neobvykle vysokému číslu portu.',
    webTransportRandomSubdomain: 'Připojení k podezřelé náhodné subdoméně (možný C2 server).',
    webTransportFreeTLD: 'Připojení k bezplatné TLD doméně (často používané pro malware).',
    webTransportHighConnectionRate: 'Detekována neobvykle vysoká frekvence připojení.',
    webTransportHighDatagramRate: 'Detekována neobvykle vysoká rychlost přenosu dat.',
    webTransportObfuscatedUrl: 'Detekována obfuskovaná nebo zakódovaná URL.',
    webTransportInvalidUrl: 'Neplatná nebo poškozená URL připojení.'
  },
  el: {
    webTransportWarningTitle: 'Ύποπτη δραστηριότητα δικτύου',
    webTransportWarningMessage: 'Αυτή η σελίδα χρησιμοποιεί προηγμένα πρωτόκολλα δικτύου με πιθανώς ύποπτο τρόπο.',
    webTransportDirectIP: 'Εντοπίστηκε σύνδεση σε άμεση διεύθυνση IP.',
    webTransportHighPort: 'Σύνδεση σε ασυνήθιστα υψηλό αριθμό θύρας.',
    webTransportRandomSubdomain: 'Σύνδεση σε ύποπτο τυχαίο υποτομέα (πιθανός διακομιστής C2).',
    webTransportFreeTLD: 'Σύνδεση σε δωρεάν τομέα TLD (συχνά χρησιμοποιείται για κακόβουλο λογισμικό).',
    webTransportHighConnectionRate: 'Εντοπίστηκε ασυνήθιστα υψηλός ρυθμός σύνδεσης.',
    webTransportHighDatagramRate: 'Εντοπίστηκε ασυνήθιστα υψηλός ρυθμός μεταφοράς δεδομένων.',
    webTransportObfuscatedUrl: 'Εντοπίστηκε συσκοτισμένη ή κωδικοποιημένη διεύθυνση URL.',
    webTransportInvalidUrl: 'Μη έγκυρη ή κακοσχηματισμένη διεύθυνση URL σύνδεσης.'
  },
  hu: {
    webTransportWarningTitle: 'Gyanús hálózati tevékenység',
    webTransportWarningMessage: 'Ez az oldal potenciálisan gyanús módon használ fejlett hálózati protokollokat.',
    webTransportDirectIP: 'Közvetlen IP-címhez való csatlakozás észlelve.',
    webTransportHighPort: 'Szokatlanul magas portszámhoz való csatlakozás.',
    webTransportRandomSubdomain: 'Gyanús véletlenszerű aldomain csatlakozás (lehetséges C2 szerver).',
    webTransportFreeTLD: 'Ingyenes TLD domainhez való csatlakozás (gyakran használják rosszindulatú szoftverekhez).',
    webTransportHighConnectionRate: 'Szokatlanul magas kapcsolódási arány észlelve.',
    webTransportHighDatagramRate: 'Szokatlanul magas adatátviteli sebesség észlelve.',
    webTransportObfuscatedUrl: 'Eltakart vagy kódolt URL észlelve.',
    webTransportInvalidUrl: 'Érvénytelen vagy hibás formátumú csatlakozási URL.'
  },
  ro: {
    webTransportWarningTitle: 'Activitate de rețea suspectă',
    webTransportWarningMessage: 'Această pagină folosește protocoale de rețea avansate într-un mod potențial suspect.',
    webTransportDirectIP: 'Conexiune la adresă IP directă detectată.',
    webTransportHighPort: 'Conexiune la număr de port neobișnuit de mare.',
    webTransportRandomSubdomain: 'Conexiune la subdomeniu aleatoriu suspect (posibil server C2).',
    webTransportFreeTLD: 'Conexiune la domeniu TLD gratuit (folosit frecvent pentru malware).',
    webTransportHighConnectionRate: 'Rată de conexiune neobișnuit de mare detectată.',
    webTransportHighDatagramRate: 'Rată de transfer de date neobișnuit de mare detectată.',
    webTransportObfuscatedUrl: 'URL ofuscat sau codificat detectat.',
    webTransportInvalidUrl: 'URL de conexiune invalid sau malformat.'
  }
};

let updated = 0;
let skipped = 0;

for (const locale of locales) {
  const messagesPath = path.join(localesDir, locale, 'messages.json');
  if (!fs.existsSync(messagesPath)) continue;

  const content = fs.readFileSync(messagesPath, 'utf8');
  const messages = JSON.parse(content);

  // Check if keys already exist
  if (messages.webTransportWarningTitle) {
    console.log(`${locale}: Keys already exist, skipping`);
    skipped++;
    continue;
  }

  // Get translations for this locale, fallback to English
  const trans = translations[locale] || translations.en;

  // Add all WebTransport keys
  messages.webTransportWarningTitle = { message: trans.webTransportWarningTitle };
  messages.webTransportWarningMessage = { message: trans.webTransportWarningMessage };
  messages.webTransportDirectIP = { message: trans.webTransportDirectIP };
  messages.webTransportHighPort = { message: trans.webTransportHighPort };
  messages.webTransportRandomSubdomain = { message: trans.webTransportRandomSubdomain };
  messages.webTransportFreeTLD = { message: trans.webTransportFreeTLD };
  messages.webTransportHighConnectionRate = { message: trans.webTransportHighConnectionRate };
  messages.webTransportHighDatagramRate = { message: trans.webTransportHighDatagramRate };
  messages.webTransportObfuscatedUrl = { message: trans.webTransportObfuscatedUrl };
  messages.webTransportInvalidUrl = { message: trans.webTransportInvalidUrl };

  // Write back with proper formatting
  fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');
  updated++;
  console.log(`${locale}: Added 10 WebTransport keys`);
}

console.log(`\nSummary: Updated ${updated} locales, skipped ${skipped}`);
