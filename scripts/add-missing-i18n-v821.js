/**
 * Add missing i18n keys for LinkShield v8.2.1
 *
 * Missing keys identified by validate-i18n.js:
 * - dangerousUriBlocked
 * - TEST_MODE_ENABLED
 * - webTransportSuspiciousPattern
 * - webTransportHighStreamCount
 * - imagelessQR
 * - imagelessQrDangerTitle
 * - imagelessQrCautionTitle
 */

const fs = require('fs');
const path = require('path');

const LOCALES_DIR = path.join(__dirname, '..', '_locales');

// Translations for all 24 locales
const TRANSLATIONS = {
  en: {
    dangerousUriBlocked: {
      message: "A dangerous link type (like javascript:) was blocked for your safety."
    },
    TEST_MODE_ENABLED: {
      message: "Test mode is active - this is for development purposes only."
    },
    webTransportSuspiciousPattern: {
      message: "Suspicious network connection pattern detected (possible data exfiltration)."
    },
    webTransportHighStreamCount: {
      message: "Unusual number of network streams detected (possible command & control activity)."
    },
    imagelessQR: {
      message: "Hidden QR code detected (built from HTML elements instead of an image - evasion technique)."
    },
    imagelessQrDangerTitle: {
      message: "DANGER: Hidden QR Code Detected!"
    },
    imagelessQrCautionTitle: {
      message: "Caution: Hidden QR Code Detected"
    }
  },
  nl: {
    dangerousUriBlocked: {
      message: "Een gevaarlijk linktype (zoals javascript:) is geblokkeerd voor uw veiligheid."
    },
    TEST_MODE_ENABLED: {
      message: "Testmodus is actief - dit is alleen voor ontwikkelingsdoeleinden."
    },
    webTransportSuspiciousPattern: {
      message: "Verdacht netwerkverbindingspatroon gedetecteerd (mogelijke data-exfiltratie)."
    },
    webTransportHighStreamCount: {
      message: "Ongebruikelijk aantal netwerkstromen gedetecteerd (mogelijke command & control activiteit)."
    },
    imagelessQR: {
      message: "Verborgen QR-code gedetecteerd (opgebouwd uit HTML-elementen in plaats van een afbeelding - ontwijkingstechniek)."
    },
    imagelessQrDangerTitle: {
      message: "GEVAAR: Verborgen QR-code gedetecteerd!"
    },
    imagelessQrCautionTitle: {
      message: "Let op: Verborgen QR-code gedetecteerd"
    }
  },
  de: {
    dangerousUriBlocked: {
      message: "Ein gefährlicher Linktyp (wie javascript:) wurde zu Ihrer Sicherheit blockiert."
    },
    TEST_MODE_ENABLED: {
      message: "Testmodus ist aktiv - dies ist nur für Entwicklungszwecke."
    },
    webTransportSuspiciousPattern: {
      message: "Verdächtiges Netzwerkverbindungsmuster erkannt (mögliche Datenexfiltration)."
    },
    webTransportHighStreamCount: {
      message: "Ungewöhnliche Anzahl von Netzwerkströmen erkannt (mögliche Command & Control Aktivität)."
    },
    imagelessQR: {
      message: "Versteckter QR-Code erkannt (aus HTML-Elementen statt einem Bild erstellt - Umgehungstechnik)."
    },
    imagelessQrDangerTitle: {
      message: "GEFAHR: Versteckter QR-Code erkannt!"
    },
    imagelessQrCautionTitle: {
      message: "Vorsicht: Versteckter QR-Code erkannt"
    }
  },
  fr: {
    dangerousUriBlocked: {
      message: "Un type de lien dangereux (comme javascript:) a été bloqué pour votre sécurité."
    },
    TEST_MODE_ENABLED: {
      message: "Le mode test est actif - ceci est uniquement à des fins de développement."
    },
    webTransportSuspiciousPattern: {
      message: "Modèle de connexion réseau suspect détecté (possible exfiltration de données)."
    },
    webTransportHighStreamCount: {
      message: "Nombre inhabituel de flux réseau détecté (possible activité de commande et contrôle)."
    },
    imagelessQR: {
      message: "Code QR caché détecté (construit à partir d'éléments HTML au lieu d'une image - technique d'évasion)."
    },
    imagelessQrDangerTitle: {
      message: "DANGER: Code QR caché détecté!"
    },
    imagelessQrCautionTitle: {
      message: "Attention: Code QR caché détecté"
    }
  },
  es: {
    dangerousUriBlocked: {
      message: "Un tipo de enlace peligroso (como javascript:) fue bloqueado por su seguridad."
    },
    TEST_MODE_ENABLED: {
      message: "El modo de prueba está activo - esto es solo para propósitos de desarrollo."
    },
    webTransportSuspiciousPattern: {
      message: "Patrón de conexión de red sospechoso detectado (posible exfiltración de datos)."
    },
    webTransportHighStreamCount: {
      message: "Número inusual de flujos de red detectado (posible actividad de comando y control)."
    },
    imagelessQR: {
      message: "Código QR oculto detectado (construido con elementos HTML en lugar de una imagen - técnica de evasión)."
    },
    imagelessQrDangerTitle: {
      message: "¡PELIGRO: Código QR oculto detectado!"
    },
    imagelessQrCautionTitle: {
      message: "Precaución: Código QR oculto detectado"
    }
  },
  it: {
    dangerousUriBlocked: {
      message: "Un tipo di link pericoloso (come javascript:) è stato bloccato per la tua sicurezza."
    },
    TEST_MODE_ENABLED: {
      message: "La modalità test è attiva - questo è solo a scopo di sviluppo."
    },
    webTransportSuspiciousPattern: {
      message: "Rilevato pattern di connessione di rete sospetto (possibile esfiltrazione dati)."
    },
    webTransportHighStreamCount: {
      message: "Rilevato numero insolito di flussi di rete (possibile attività di comando e controllo)."
    },
    imagelessQR: {
      message: "Rilevato codice QR nascosto (costruito da elementi HTML invece di un'immagine - tecnica di evasione)."
    },
    imagelessQrDangerTitle: {
      message: "PERICOLO: Codice QR nascosto rilevato!"
    },
    imagelessQrCautionTitle: {
      message: "Attenzione: Codice QR nascosto rilevato"
    }
  },
  pt: {
    dangerousUriBlocked: {
      message: "Um tipo de link perigoso (como javascript:) foi bloqueado para sua segurança."
    },
    TEST_MODE_ENABLED: {
      message: "O modo de teste está ativo - isto é apenas para fins de desenvolvimento."
    },
    webTransportSuspiciousPattern: {
      message: "Padrão de conexão de rede suspeito detectado (possível exfiltração de dados)."
    },
    webTransportHighStreamCount: {
      message: "Número incomum de fluxos de rede detectado (possível atividade de comando e controle)."
    },
    imagelessQR: {
      message: "Código QR oculto detectado (construído a partir de elementos HTML em vez de uma imagem - técnica de evasão)."
    },
    imagelessQrDangerTitle: {
      message: "PERIGO: Código QR oculto detectado!"
    },
    imagelessQrCautionTitle: {
      message: "Cuidado: Código QR oculto detectado"
    }
  },
  pt_BR: {
    dangerousUriBlocked: {
      message: "Um tipo de link perigoso (como javascript:) foi bloqueado para sua segurança."
    },
    TEST_MODE_ENABLED: {
      message: "O modo de teste está ativo - isto é apenas para fins de desenvolvimento."
    },
    webTransportSuspiciousPattern: {
      message: "Padrão de conexão de rede suspeito detectado (possível exfiltração de dados)."
    },
    webTransportHighStreamCount: {
      message: "Número incomum de fluxos de rede detectado (possível atividade de comando e controle)."
    },
    imagelessQR: {
      message: "Código QR oculto detectado (construído a partir de elementos HTML em vez de uma imagem - técnica de evasão)."
    },
    imagelessQrDangerTitle: {
      message: "PERIGO: Código QR oculto detectado!"
    },
    imagelessQrCautionTitle: {
      message: "Cuidado: Código QR oculto detectado"
    }
  },
  ru: {
    dangerousUriBlocked: {
      message: "Опасный тип ссылки (например, javascript:) был заблокирован для вашей безопасности."
    },
    TEST_MODE_ENABLED: {
      message: "Тестовый режим активен - это только для целей разработки."
    },
    webTransportSuspiciousPattern: {
      message: "Обнаружен подозрительный паттерн сетевого соединения (возможная утечка данных)."
    },
    webTransportHighStreamCount: {
      message: "Обнаружено необычное количество сетевых потоков (возможная активность командного центра)."
    },
    imagelessQR: {
      message: "Обнаружен скрытый QR-код (построен из HTML-элементов вместо изображения - техника обхода)."
    },
    imagelessQrDangerTitle: {
      message: "ОПАСНОСТЬ: Обнаружен скрытый QR-код!"
    },
    imagelessQrCautionTitle: {
      message: "Внимание: Обнаружен скрытый QR-код"
    }
  },
  ja: {
    dangerousUriBlocked: {
      message: "危険なリンクタイプ（javascript:など）がセキュリティのためにブロックされました。"
    },
    TEST_MODE_ENABLED: {
      message: "テストモードがアクティブです - これは開発目的のみです。"
    },
    webTransportSuspiciousPattern: {
      message: "疑わしいネットワーク接続パターンが検出されました（データ流出の可能性）。"
    },
    webTransportHighStreamCount: {
      message: "異常な数のネットワークストリームが検出されました（C2活動の可能性）。"
    },
    imagelessQR: {
      message: "隠しQRコードが検出されました（画像ではなくHTML要素から構築 - 回避技術）。"
    },
    imagelessQrDangerTitle: {
      message: "危険: 隠しQRコードが検出されました！"
    },
    imagelessQrCautionTitle: {
      message: "注意: 隠しQRコードが検出されました"
    }
  },
  ko: {
    dangerousUriBlocked: {
      message: "위험한 링크 유형(예: javascript:)이 보안을 위해 차단되었습니다."
    },
    TEST_MODE_ENABLED: {
      message: "테스트 모드가 활성화되어 있습니다 - 개발 목적으로만 사용됩니다."
    },
    webTransportSuspiciousPattern: {
      message: "의심스러운 네트워크 연결 패턴이 감지되었습니다 (데이터 유출 가능성)."
    },
    webTransportHighStreamCount: {
      message: "비정상적인 수의 네트워크 스트림이 감지되었습니다 (C2 활동 가능성)."
    },
    imagelessQR: {
      message: "숨겨진 QR 코드가 감지되었습니다 (이미지 대신 HTML 요소로 구성 - 회피 기술)."
    },
    imagelessQrDangerTitle: {
      message: "위험: 숨겨진 QR 코드 감지!"
    },
    imagelessQrCautionTitle: {
      message: "주의: 숨겨진 QR 코드 감지"
    }
  },
  zh: {
    dangerousUriBlocked: {
      message: "危险的链接类型（如 javascript:）已被阻止以保护您的安全。"
    },
    TEST_MODE_ENABLED: {
      message: "测试模式已激活 - 仅用于开发目的。"
    },
    webTransportSuspiciousPattern: {
      message: "检测到可疑的网络连接模式（可能存在数据外泄）。"
    },
    webTransportHighStreamCount: {
      message: "检测到异常数量的网络流（可能存在命令与控制活动）。"
    },
    imagelessQR: {
      message: "检测到隐藏的二维码（由HTML元素构建而非图像 - 规避技术）。"
    },
    imagelessQrDangerTitle: {
      message: "危险：检测到隐藏的二维码！"
    },
    imagelessQrCautionTitle: {
      message: "注意：检测到隐藏的二维码"
    }
  },
  ar: {
    dangerousUriBlocked: {
      message: "تم حظر نوع رابط خطير (مثل javascript:) لحماية أمانك."
    },
    TEST_MODE_ENABLED: {
      message: "وضع الاختبار نشط - هذا لأغراض التطوير فقط."
    },
    webTransportSuspiciousPattern: {
      message: "تم اكتشاف نمط اتصال شبكة مشبوه (احتمال تسريب بيانات)."
    },
    webTransportHighStreamCount: {
      message: "تم اكتشاف عدد غير عادي من تدفقات الشبكة (احتمال نشاط قيادة وتحكم)."
    },
    imagelessQR: {
      message: "تم اكتشاف رمز QR مخفي (مبني من عناصر HTML بدلاً من صورة - تقنية تهرب)."
    },
    imagelessQrDangerTitle: {
      message: "خطر: تم اكتشاف رمز QR مخفي!"
    },
    imagelessQrCautionTitle: {
      message: "تنبيه: تم اكتشاف رمز QR مخفي"
    }
  },
  hi: {
    dangerousUriBlocked: {
      message: "आपकी सुरक्षा के लिए एक खतरनाक लिंक प्रकार (जैसे javascript:) को ब्लॉक किया गया।"
    },
    TEST_MODE_ENABLED: {
      message: "टेस्ट मोड सक्रिय है - यह केवल विकास उद्देश्यों के लिए है।"
    },
    webTransportSuspiciousPattern: {
      message: "संदिग्ध नेटवर्क कनेक्शन पैटर्न का पता चला (संभावित डेटा चोरी)।"
    },
    webTransportHighStreamCount: {
      message: "असामान्य संख्या में नेटवर्क स्ट्रीम का पता चला (संभावित C2 गतिविधि)।"
    },
    imagelessQR: {
      message: "छिपा हुआ QR कोड पता चला (छवि के बजाय HTML तत्वों से बनाया गया - चोरी तकनीक)।"
    },
    imagelessQrDangerTitle: {
      message: "खतरा: छिपा हुआ QR कोड पता चला!"
    },
    imagelessQrCautionTitle: {
      message: "सावधान: छिपा हुआ QR कोड पता चला"
    }
  },
  tr: {
    dangerousUriBlocked: {
      message: "Güvenliğiniz için tehlikeli bir bağlantı türü (javascript: gibi) engellendi."
    },
    TEST_MODE_ENABLED: {
      message: "Test modu aktif - bu yalnızca geliştirme amaçlıdır."
    },
    webTransportSuspiciousPattern: {
      message: "Şüpheli ağ bağlantı kalıbı tespit edildi (olası veri sızıntısı)."
    },
    webTransportHighStreamCount: {
      message: "Olağandışı sayıda ağ akışı tespit edildi (olası komuta ve kontrol aktivitesi)."
    },
    imagelessQR: {
      message: "Gizli QR kodu tespit edildi (resim yerine HTML öğelerinden oluşturulmuş - kaçınma tekniği)."
    },
    imagelessQrDangerTitle: {
      message: "TEHLİKE: Gizli QR Kodu Tespit Edildi!"
    },
    imagelessQrCautionTitle: {
      message: "Dikkat: Gizli QR Kodu Tespit Edildi"
    }
  },
  pl: {
    dangerousUriBlocked: {
      message: "Niebezpieczny typ linku (np. javascript:) został zablokowany dla Twojego bezpieczeństwa."
    },
    TEST_MODE_ENABLED: {
      message: "Tryb testowy jest aktywny - służy tylko do celów programistycznych."
    },
    webTransportSuspiciousPattern: {
      message: "Wykryto podejrzany wzorzec połączenia sieciowego (możliwa eksfiltracja danych)."
    },
    webTransportHighStreamCount: {
      message: "Wykryto nietypową liczbę strumieni sieciowych (możliwa aktywność C2)."
    },
    imagelessQR: {
      message: "Wykryto ukryty kod QR (zbudowany z elementów HTML zamiast obrazu - technika unikania)."
    },
    imagelessQrDangerTitle: {
      message: "NIEBEZPIECZEŃSTWO: Wykryto ukryty kod QR!"
    },
    imagelessQrCautionTitle: {
      message: "Uwaga: Wykryto ukryty kod QR"
    }
  },
  cs: {
    dangerousUriBlocked: {
      message: "Nebezpečný typ odkazu (jako javascript:) byl zablokován pro vaši bezpečnost."
    },
    TEST_MODE_ENABLED: {
      message: "Testovací režim je aktivní - toto je pouze pro vývojové účely."
    },
    webTransportSuspiciousPattern: {
      message: "Zjištěn podezřelý vzor síťového připojení (možná exfiltrace dat)."
    },
    webTransportHighStreamCount: {
      message: "Zjištěn neobvyklý počet síťových proudů (možná aktivita C2)."
    },
    imagelessQR: {
      message: "Zjištěn skrytý QR kód (vytvořen z HTML prvků místo obrázku - úniková technika)."
    },
    imagelessQrDangerTitle: {
      message: "NEBEZPEČÍ: Zjištěn skrytý QR kód!"
    },
    imagelessQrCautionTitle: {
      message: "Pozor: Zjištěn skrytý QR kód"
    }
  },
  el: {
    dangerousUriBlocked: {
      message: "Ένας επικίνδυνος τύπος συνδέσμου (όπως javascript:) αποκλείστηκε για την ασφάλειά σας."
    },
    TEST_MODE_ENABLED: {
      message: "Η λειτουργία δοκιμής είναι ενεργή - αυτό είναι μόνο για σκοπούς ανάπτυξης."
    },
    webTransportSuspiciousPattern: {
      message: "Εντοπίστηκε ύποπτο μοτίβο σύνδεσης δικτύου (πιθανή διαρροή δεδομένων)."
    },
    webTransportHighStreamCount: {
      message: "Εντοπίστηκε ασυνήθιστος αριθμός ροών δικτύου (πιθανή δραστηριότητα C2)."
    },
    imagelessQR: {
      message: "Εντοπίστηκε κρυφός κώδικας QR (κατασκευασμένος από στοιχεία HTML αντί εικόνας - τεχνική αποφυγής)."
    },
    imagelessQrDangerTitle: {
      message: "ΚΙΝΔΥΝΟΣ: Εντοπίστηκε κρυφός κώδικας QR!"
    },
    imagelessQrCautionTitle: {
      message: "Προσοχή: Εντοπίστηκε κρυφός κώδικας QR"
    }
  },
  hu: {
    dangerousUriBlocked: {
      message: "Egy veszélyes hivatkozástípus (mint a javascript:) blokkolva lett az Ön biztonsága érdekében."
    },
    TEST_MODE_ENABLED: {
      message: "A tesztmód aktív - ez csak fejlesztési célokra szolgál."
    },
    webTransportSuspiciousPattern: {
      message: "Gyanús hálózati kapcsolati minta észlelve (lehetséges adatszivárgás)."
    },
    webTransportHighStreamCount: {
      message: "Szokatlan számú hálózati adatfolyam észlelve (lehetséges C2 tevékenység)."
    },
    imagelessQR: {
      message: "Rejtett QR-kód észlelve (HTML elemekből építve kép helyett - elkerülési technika)."
    },
    imagelessQrDangerTitle: {
      message: "VESZÉLY: Rejtett QR-kód észlelve!"
    },
    imagelessQrCautionTitle: {
      message: "Figyelem: Rejtett QR-kód észlelve"
    }
  },
  id: {
    dangerousUriBlocked: {
      message: "Jenis tautan berbahaya (seperti javascript:) telah diblokir demi keamanan Anda."
    },
    TEST_MODE_ENABLED: {
      message: "Mode uji aktif - ini hanya untuk tujuan pengembangan."
    },
    webTransportSuspiciousPattern: {
      message: "Pola koneksi jaringan mencurigakan terdeteksi (kemungkinan eksfiltrasi data)."
    },
    webTransportHighStreamCount: {
      message: "Jumlah aliran jaringan yang tidak biasa terdeteksi (kemungkinan aktivitas C2)."
    },
    imagelessQR: {
      message: "Kode QR tersembunyi terdeteksi (dibangun dari elemen HTML bukan gambar - teknik penghindaran)."
    },
    imagelessQrDangerTitle: {
      message: "BAHAYA: Kode QR Tersembunyi Terdeteksi!"
    },
    imagelessQrCautionTitle: {
      message: "Peringatan: Kode QR Tersembunyi Terdeteksi"
    }
  },
  ro: {
    dangerousUriBlocked: {
      message: "Un tip de link periculos (precum javascript:) a fost blocat pentru siguranța dumneavoastră."
    },
    TEST_MODE_ENABLED: {
      message: "Modul de testare este activ - aceasta este doar pentru scopuri de dezvoltare."
    },
    webTransportSuspiciousPattern: {
      message: "Model de conexiune de rețea suspect detectat (posibilă exfiltrare de date)."
    },
    webTransportHighStreamCount: {
      message: "Număr neobișnuit de fluxuri de rețea detectat (posibilă activitate C2)."
    },
    imagelessQR: {
      message: "Cod QR ascuns detectat (construit din elemente HTML în loc de imagine - tehnică de evitare)."
    },
    imagelessQrDangerTitle: {
      message: "PERICOL: Cod QR ascuns detectat!"
    },
    imagelessQrCautionTitle: {
      message: "Atenție: Cod QR ascuns detectat"
    }
  },
  th: {
    dangerousUriBlocked: {
      message: "ลิงก์ประเภทอันตราย (เช่น javascript:) ถูกบล็อกเพื่อความปลอดภัยของคุณ"
    },
    TEST_MODE_ENABLED: {
      message: "โหมดทดสอบเปิดใช้งานอยู่ - นี่สำหรับวัตถุประสงค์ในการพัฒนาเท่านั้น"
    },
    webTransportSuspiciousPattern: {
      message: "ตรวจพบรูปแบบการเชื่อมต่อเครือข่ายที่น่าสงสัย (อาจมีการรั่วไหลของข้อมูล)"
    },
    webTransportHighStreamCount: {
      message: "ตรวจพบจำนวนสตรีมเครือข่ายที่ผิดปกติ (อาจมีกิจกรรม C2)"
    },
    imagelessQR: {
      message: "ตรวจพบ QR โค้ดที่ซ่อนอยู่ (สร้างจากองค์ประกอบ HTML แทนรูปภาพ - เทคนิคหลบเลี่ยง)"
    },
    imagelessQrDangerTitle: {
      message: "อันตราย: ตรวจพบ QR โค้ดที่ซ่อนอยู่!"
    },
    imagelessQrCautionTitle: {
      message: "ระวัง: ตรวจพบ QR โค้ดที่ซ่อนอยู่"
    }
  },
  uk: {
    dangerousUriBlocked: {
      message: "Небезпечний тип посилання (наприклад, javascript:) було заблоковано для вашої безпеки."
    },
    TEST_MODE_ENABLED: {
      message: "Тестовий режим активний - це лише для цілей розробки."
    },
    webTransportSuspiciousPattern: {
      message: "Виявлено підозрілий шаблон мережевого з'єднання (можливий витік даних)."
    },
    webTransportHighStreamCount: {
      message: "Виявлено незвичну кількість мережевих потоків (можлива активність C2)."
    },
    imagelessQR: {
      message: "Виявлено прихований QR-код (побудований з HTML-елементів замість зображення - техніка обходу)."
    },
    imagelessQrDangerTitle: {
      message: "НЕБЕЗПЕКА: Виявлено прихований QR-код!"
    },
    imagelessQrCautionTitle: {
      message: "Увага: Виявлено прихований QR-код"
    }
  },
  vi: {
    dangerousUriBlocked: {
      message: "Một loại liên kết nguy hiểm (như javascript:) đã bị chặn vì sự an toàn của bạn."
    },
    TEST_MODE_ENABLED: {
      message: "Chế độ thử nghiệm đang hoạt động - đây chỉ dành cho mục đích phát triển."
    },
    webTransportSuspiciousPattern: {
      message: "Phát hiện mẫu kết nối mạng đáng ngờ (có thể rò rỉ dữ liệu)."
    },
    webTransportHighStreamCount: {
      message: "Phát hiện số lượng luồng mạng bất thường (có thể có hoạt động C2)."
    },
    imagelessQR: {
      message: "Phát hiện mã QR ẩn (được xây dựng từ các phần tử HTML thay vì hình ảnh - kỹ thuật né tránh)."
    },
    imagelessQrDangerTitle: {
      message: "NGUY HIỂM: Phát hiện mã QR ẩn!"
    },
    imagelessQrCautionTitle: {
      message: "Cảnh báo: Phát hiện mã QR ẩn"
    }
  }
};

// Get all locales
function getLocales() {
  return fs.readdirSync(LOCALES_DIR).filter(dir => {
    const messagesPath = path.join(LOCALES_DIR, dir, 'messages.json');
    return fs.existsSync(messagesPath);
  });
}

// Add keys to a locale
function addKeysToLocale(locale) {
  const messagesPath = path.join(LOCALES_DIR, locale, 'messages.json');
  const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));

  // Get translations for this locale, fallback to English
  const translations = TRANSLATIONS[locale] || TRANSLATIONS.en;

  let added = 0;
  for (const [key, value] of Object.entries(translations)) {
    if (!messages[key]) {
      messages[key] = value;
      added++;
    }
  }

  // Write back
  fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2) + '\n', 'utf8');
  return added;
}

// Main
function main() {
  console.log('Adding missing i18n keys for LinkShield v8.2.1\n');

  const locales = getLocales();
  console.log(`Found ${locales.length} locales\n`);

  let totalAdded = 0;
  for (const locale of locales) {
    const added = addKeysToLocale(locale);
    totalAdded += added;
    console.log(`${locale}: ${added} keys added`);
  }

  console.log(`\n✅ Done! Added ${totalAdded} keys total across ${locales.length} locales`);
}

main();
