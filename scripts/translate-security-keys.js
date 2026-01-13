/**
 * Security Keys Translation Script for LinkShield v8.0.0
 * Translates 21 security keys to all supported languages
 */
const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

// Professional security-focused translations for all 22 languages
const translations = {
  // German (de)
  de: {
    visualHijackingDetected: "Visual Hijacking erkannt",
    visualHijackingMessage: "Ein verstecktes Overlay wurde erkannt, das versucht, Ihren Klick abzufangen. Dies ist eine häufige Phishing-Technik, um Sie auf bösartige Websites umzuleiten.",
    transparentHighZIndexOverlay: "Transparentes Overlay mit hohem Z-Index erkannt",
    invisibleClickjackOverlay: "Unsichtbares Clickjacking-Overlay erkannt",
    fullscreenTransparentOverlay: "Vollbild-transparentes Overlay erkannt",
    hiddenLinkOverlay: "Verstecktes Link-Overlay erkannt",
    detectionReason: "Erkennungsgrund",
    closeWarning: "Schließen",
    failSafeNetworkTitle: "Lizenzprüfung fehlgeschlagen",
    failSafeNetworkMessage: "Lizenz konnte aufgrund von Netzwerkproblemen nicht überprüft werden. Der Schutz bleibt im abgesicherten Modus aktiv.",
    failSafeGraceTitle: "Lizenzverifizierung erforderlich",
    failSafeGraceMessage: "Bitte verbinden Sie sich mit dem Internet, um Ihre Lizenz zu verifizieren. Der Schutz bleibt aktiv.",
    failSafePreservedTitle: "Schutz aktiv",
    failSafePreservedMessage: "Ihre Schutzregeln sind erhalten. Bitte verifizieren Sie Ihre Lizenz, wenn möglich.",
    failSafeDefaultTitle: "Abgesicherter Modus aktiv",
    failSafeDefaultMessage: "LinkShield läuft im abgesicherten Modus. Der Schutz bleibt aktiv.",
    dismissTooltip: "Schließen",
    dontShowAgain: "Nicht mehr anzeigen?",
    confirmYes: "Ja",
    confirmNo: "Nein",
    reportPhishingSuccess: "Gemeldet! Vielen Dank für Ihren Beitrag zur Verbesserung der Sicherheit."
  },

  // French (fr)
  fr: {
    visualHijackingDetected: "Détournement visuel détecté",
    visualHijackingMessage: "Une superposition cachée a été détectée, tentant d'intercepter votre clic. C'est une technique de phishing courante pour vous rediriger vers des sites malveillants.",
    transparentHighZIndexOverlay: "Superposition transparente avec z-index élevé détectée",
    invisibleClickjackOverlay: "Superposition de clickjacking invisible détectée",
    fullscreenTransparentOverlay: "Superposition transparente plein écran détectée",
    hiddenLinkOverlay: "Superposition de lien caché détectée",
    detectionReason: "Raison de détection",
    closeWarning: "Fermer",
    failSafeNetworkTitle: "Échec de la vérification de licence",
    failSafeNetworkMessage: "Impossible de vérifier la licence en raison de problèmes réseau. La protection reste active en mode sécurisé.",
    failSafeGraceTitle: "Vérification de licence requise",
    failSafeGraceMessage: "Veuillez vous connecter à Internet pour vérifier votre licence. La protection reste active.",
    failSafePreservedTitle: "Protection active",
    failSafePreservedMessage: "Vos règles de protection sont préservées. Veuillez vérifier votre licence dès que possible.",
    failSafeDefaultTitle: "Mode sécurisé actif",
    failSafeDefaultMessage: "LinkShield fonctionne en mode sécurisé. La protection reste active.",
    dismissTooltip: "Fermer",
    dontShowAgain: "Ne plus afficher ?",
    confirmYes: "Oui",
    confirmNo: "Non",
    reportPhishingSuccess: "Signalé ! Merci de contribuer à améliorer la sécurité."
  },

  // Spanish (es)
  es: {
    visualHijackingDetected: "Secuestro visual detectado",
    visualHijackingMessage: "Se detectó una superposición oculta que intenta interceptar su clic. Esta es una técnica común de phishing para redirigirlo a sitios maliciosos.",
    transparentHighZIndexOverlay: "Superposición transparente con z-index alto detectada",
    invisibleClickjackOverlay: "Superposición de clickjacking invisible detectada",
    fullscreenTransparentOverlay: "Superposición transparente de pantalla completa detectada",
    hiddenLinkOverlay: "Superposición de enlace oculto detectada",
    detectionReason: "Razón de detección",
    closeWarning: "Cerrar",
    failSafeNetworkTitle: "Error en verificación de licencia",
    failSafeNetworkMessage: "No se pudo verificar la licencia debido a problemas de red. La protección permanece activa en modo seguro.",
    failSafeGraceTitle: "Verificación de licencia requerida",
    failSafeGraceMessage: "Conéctese a Internet para verificar su licencia. La protección permanece activa.",
    failSafePreservedTitle: "Protección activa",
    failSafePreservedMessage: "Sus reglas de protección están preservadas. Verifique su licencia cuando sea posible.",
    failSafeDefaultTitle: "Modo seguro activo",
    failSafeDefaultMessage: "LinkShield está funcionando en modo seguro. La protección permanece activa.",
    dismissTooltip: "Cerrar",
    dontShowAgain: "¿No mostrar de nuevo?",
    confirmYes: "Sí",
    confirmNo: "No",
    reportPhishingSuccess: "¡Reportado! Gracias por ayudar a mejorar la seguridad."
  },

  // Italian (it)
  it: {
    visualHijackingDetected: "Dirottamento visivo rilevato",
    visualHijackingMessage: "È stato rilevato un overlay nascosto che tenta di intercettare il tuo clic. Questa è una tecnica di phishing comune per reindirizzarti a siti dannosi.",
    transparentHighZIndexOverlay: "Overlay trasparente con z-index alto rilevato",
    invisibleClickjackOverlay: "Overlay di clickjacking invisibile rilevato",
    fullscreenTransparentOverlay: "Overlay trasparente a schermo intero rilevato",
    hiddenLinkOverlay: "Overlay di link nascosto rilevato",
    detectionReason: "Motivo del rilevamento",
    closeWarning: "Chiudi",
    failSafeNetworkTitle: "Verifica licenza fallita",
    failSafeNetworkMessage: "Impossibile verificare la licenza a causa di problemi di rete. La protezione rimane attiva in modalità sicura.",
    failSafeGraceTitle: "Verifica licenza richiesta",
    failSafeGraceMessage: "Connettiti a Internet per verificare la tua licenza. La protezione rimane attiva.",
    failSafePreservedTitle: "Protezione attiva",
    failSafePreservedMessage: "Le tue regole di protezione sono preservate. Verifica la tua licenza quando possibile.",
    failSafeDefaultTitle: "Modalità sicura attiva",
    failSafeDefaultMessage: "LinkShield è in esecuzione in modalità sicura. La protezione rimane attiva.",
    dismissTooltip: "Chiudi",
    dontShowAgain: "Non mostrare più?",
    confirmYes: "Sì",
    confirmNo: "No",
    reportPhishingSuccess: "Segnalato! Grazie per contribuire a migliorare la sicurezza."
  },

  // Portuguese (pt)
  pt: {
    visualHijackingDetected: "Sequestro visual detetado",
    visualHijackingMessage: "Foi detetada uma sobreposição oculta a tentar intercetar o seu clique. Esta é uma técnica comum de phishing para o redirecionar para sites maliciosos.",
    transparentHighZIndexOverlay: "Sobreposição transparente com z-index alto detetada",
    invisibleClickjackOverlay: "Sobreposição de clickjacking invisível detetada",
    fullscreenTransparentOverlay: "Sobreposição transparente em ecrã inteiro detetada",
    hiddenLinkOverlay: "Sobreposição de link oculto detetada",
    detectionReason: "Razão da deteção",
    closeWarning: "Fechar",
    failSafeNetworkTitle: "Falha na verificação da licença",
    failSafeNetworkMessage: "Não foi possível verificar a licença devido a problemas de rede. A proteção permanece ativa em modo seguro.",
    failSafeGraceTitle: "Verificação de licença necessária",
    failSafeGraceMessage: "Ligue-se à Internet para verificar a sua licença. A proteção permanece ativa.",
    failSafePreservedTitle: "Proteção ativa",
    failSafePreservedMessage: "As suas regras de proteção estão preservadas. Verifique a sua licença quando possível.",
    failSafeDefaultTitle: "Modo seguro ativo",
    failSafeDefaultMessage: "O LinkShield está a funcionar em modo seguro. A proteção permanece ativa.",
    dismissTooltip: "Fechar",
    dontShowAgain: "Não mostrar novamente?",
    confirmYes: "Sim",
    confirmNo: "Não",
    reportPhishingSuccess: "Reportado! Obrigado por ajudar a melhorar a segurança."
  },

  // Portuguese Brazil (pt_BR)
  pt_BR: {
    visualHijackingDetected: "Sequestro visual detectado",
    visualHijackingMessage: "Uma sobreposição oculta foi detectada tentando interceptar seu clique. Esta é uma técnica comum de phishing para redirecioná-lo a sites maliciosos.",
    transparentHighZIndexOverlay: "Sobreposição transparente com z-index alto detectada",
    invisibleClickjackOverlay: "Sobreposição de clickjacking invisível detectada",
    fullscreenTransparentOverlay: "Sobreposição transparente em tela cheia detectada",
    hiddenLinkOverlay: "Sobreposição de link oculto detectada",
    detectionReason: "Motivo da detecção",
    closeWarning: "Fechar",
    failSafeNetworkTitle: "Falha na verificação da licença",
    failSafeNetworkMessage: "Não foi possível verificar a licença devido a problemas de rede. A proteção permanece ativa em modo seguro.",
    failSafeGraceTitle: "Verificação de licença necessária",
    failSafeGraceMessage: "Conecte-se à Internet para verificar sua licença. A proteção permanece ativa.",
    failSafePreservedTitle: "Proteção ativa",
    failSafePreservedMessage: "Suas regras de proteção estão preservadas. Verifique sua licença quando possível.",
    failSafeDefaultTitle: "Modo seguro ativo",
    failSafeDefaultMessage: "O LinkShield está funcionando em modo seguro. A proteção permanece ativa.",
    dismissTooltip: "Fechar",
    dontShowAgain: "Não mostrar novamente?",
    confirmYes: "Sim",
    confirmNo: "Não",
    reportPhishingSuccess: "Reportado! Obrigado por ajudar a melhorar a segurança."
  },

  // Polish (pl)
  pl: {
    visualHijackingDetected: "Wykryto przechwytywanie wizualne",
    visualHijackingMessage: "Wykryto ukrytą nakładkę próbującą przechwycić Twoje kliknięcie. To powszechna technika phishingowa mająca na celu przekierowanie Cię na złośliwe strony.",
    transparentHighZIndexOverlay: "Wykryto przezroczystą nakładkę z wysokim z-index",
    invisibleClickjackOverlay: "Wykryto niewidoczną nakładkę clickjacking",
    fullscreenTransparentOverlay: "Wykryto przezroczystą nakładkę pełnoekranową",
    hiddenLinkOverlay: "Wykryto ukrytą nakładkę linku",
    detectionReason: "Powód wykrycia",
    closeWarning: "Zamknij",
    failSafeNetworkTitle: "Weryfikacja licencji nie powiodła się",
    failSafeNetworkMessage: "Nie można zweryfikować licencji z powodu problemów z siecią. Ochrona pozostaje aktywna w trybie awaryjnym.",
    failSafeGraceTitle: "Wymagana weryfikacja licencji",
    failSafeGraceMessage: "Połącz się z Internetem, aby zweryfikować licencję. Ochrona pozostaje aktywna.",
    failSafePreservedTitle: "Ochrona aktywna",
    failSafePreservedMessage: "Twoje reguły ochrony są zachowane. Zweryfikuj licencję, gdy będzie to możliwe.",
    failSafeDefaultTitle: "Tryb awaryjny aktywny",
    failSafeDefaultMessage: "LinkShield działa w trybie awaryjnym. Ochrona pozostaje aktywna.",
    dismissTooltip: "Zamknij",
    dontShowAgain: "Nie pokazuj ponownie?",
    confirmYes: "Tak",
    confirmNo: "Nie",
    reportPhishingSuccess: "Zgłoszono! Dziękujemy za pomoc w poprawie bezpieczeństwa."
  },

  // Czech (cs)
  cs: {
    visualHijackingDetected: "Zjištěn vizuální únos",
    visualHijackingMessage: "Byla zjištěna skrytá překryvná vrstva, která se pokouší zachytit vaše kliknutí. Jedná se o běžnou phishingovou techniku k přesměrování na škodlivé weby.",
    transparentHighZIndexOverlay: "Zjištěna průhledná překryvná vrstva s vysokým z-indexem",
    invisibleClickjackOverlay: "Zjištěna neviditelná clickjacking překryvná vrstva",
    fullscreenTransparentOverlay: "Zjištěna průhledná celoobrazovková překryvná vrstva",
    hiddenLinkOverlay: "Zjištěna skrytá překryvná vrstva odkazu",
    detectionReason: "Důvod detekce",
    closeWarning: "Zavřít",
    failSafeNetworkTitle: "Ověření licence selhalo",
    failSafeNetworkMessage: "Licenci nelze ověřit kvůli problémům se sítí. Ochrana zůstává aktivní v nouzovém režimu.",
    failSafeGraceTitle: "Vyžadováno ověření licence",
    failSafeGraceMessage: "Připojte se k internetu pro ověření licence. Ochrana zůstává aktivní.",
    failSafePreservedTitle: "Ochrana aktivní",
    failSafePreservedMessage: "Vaše pravidla ochrany jsou zachována. Ověřte licenci, až to bude možné.",
    failSafeDefaultTitle: "Nouzový režim aktivní",
    failSafeDefaultMessage: "LinkShield běží v nouzovém režimu. Ochrana zůstává aktivní.",
    dismissTooltip: "Zavřít",
    dontShowAgain: "Už nezobrazovat?",
    confirmYes: "Ano",
    confirmNo: "Ne",
    reportPhishingSuccess: "Nahlášeno! Děkujeme za pomoc při zlepšování bezpečnosti."
  },

  // Hungarian (hu)
  hu: {
    visualHijackingDetected: "Vizuális eltérítés észlelve",
    visualHijackingMessage: "Rejtett átfedés észlelve, amely megpróbálja elfogni a kattintását. Ez egy gyakori adathalász technika, amely rosszindulatú oldalakra irányít át.",
    transparentHighZIndexOverlay: "Magas z-indexű átlátszó átfedés észlelve",
    invisibleClickjackOverlay: "Láthatatlan clickjacking átfedés észlelve",
    fullscreenTransparentOverlay: "Teljes képernyős átlátszó átfedés észlelve",
    hiddenLinkOverlay: "Rejtett link átfedés észlelve",
    detectionReason: "Észlelés oka",
    closeWarning: "Bezárás",
    failSafeNetworkTitle: "Licencellenőrzés sikertelen",
    failSafeNetworkMessage: "A licenc nem ellenőrizhető hálózati problémák miatt. A védelem biztonságos módban aktív marad.",
    failSafeGraceTitle: "Licenc ellenőrzés szükséges",
    failSafeGraceMessage: "Csatlakozzon az internethez a licenc ellenőrzéséhez. A védelem aktív marad.",
    failSafePreservedTitle: "Védelem aktív",
    failSafePreservedMessage: "A védelmi szabályok megmaradtak. Ellenőrizze a licencet, amikor lehetséges.",
    failSafeDefaultTitle: "Biztonságos mód aktív",
    failSafeDefaultMessage: "A LinkShield biztonságos módban fut. A védelem aktív marad.",
    dismissTooltip: "Bezárás",
    dontShowAgain: "Ne mutassa újra?",
    confirmYes: "Igen",
    confirmNo: "Nem",
    reportPhishingSuccess: "Jelentve! Köszönjük, hogy segít a biztonság javításában."
  },

  // Romanian (ro)
  ro: {
    visualHijackingDetected: "Deturnare vizuală detectată",
    visualHijackingMessage: "A fost detectată o suprapunere ascunsă care încearcă să intercepteze clicul dvs. Aceasta este o tehnică comună de phishing pentru a vă redirecționa către site-uri rău intenționate.",
    transparentHighZIndexOverlay: "Suprapunere transparentă cu z-index ridicat detectată",
    invisibleClickjackOverlay: "Suprapunere de clickjacking invizibilă detectată",
    fullscreenTransparentOverlay: "Suprapunere transparentă pe tot ecranul detectată",
    hiddenLinkOverlay: "Suprapunere de link ascuns detectată",
    detectionReason: "Motiv de detectare",
    closeWarning: "Închide",
    failSafeNetworkTitle: "Verificarea licenței a eșuat",
    failSafeNetworkMessage: "Licența nu a putut fi verificată din cauza problemelor de rețea. Protecția rămâne activă în modul sigur.",
    failSafeGraceTitle: "Verificare licență necesară",
    failSafeGraceMessage: "Conectați-vă la internet pentru a verifica licența. Protecția rămâne activă.",
    failSafePreservedTitle: "Protecție activă",
    failSafePreservedMessage: "Regulile de protecție sunt păstrate. Verificați licența când este posibil.",
    failSafeDefaultTitle: "Mod sigur activ",
    failSafeDefaultMessage: "LinkShield rulează în modul sigur. Protecția rămâne activă.",
    dismissTooltip: "Închide",
    dontShowAgain: "Nu mai afișa?",
    confirmYes: "Da",
    confirmNo: "Nu",
    reportPhishingSuccess: "Raportat! Vă mulțumim că ajutați la îmbunătățirea securității."
  },

  // Greek (el)
  el: {
    visualHijackingDetected: "Εντοπίστηκε οπτική υποκλοπή",
    visualHijackingMessage: "Εντοπίστηκε κρυφή επικάλυψη που προσπαθεί να υποκλέψει το κλικ σας. Αυτή είναι μια κοινή τεχνική phishing για να σας ανακατευθύνει σε κακόβουλες ιστοσελίδες.",
    transparentHighZIndexOverlay: "Εντοπίστηκε διαφανής επικάλυψη με υψηλό z-index",
    invisibleClickjackOverlay: "Εντοπίστηκε αόρατη επικάλυψη clickjacking",
    fullscreenTransparentOverlay: "Εντοπίστηκε διαφανής επικάλυψη πλήρους οθόνης",
    hiddenLinkOverlay: "Εντοπίστηκε κρυφή επικάλυψη συνδέσμου",
    detectionReason: "Λόγος ανίχνευσης",
    closeWarning: "Κλείσιμο",
    failSafeNetworkTitle: "Αποτυχία επαλήθευσης άδειας",
    failSafeNetworkMessage: "Δεν ήταν δυνατή η επαλήθευση της άδειας λόγω προβλημάτων δικτύου. Η προστασία παραμένει ενεργή σε ασφαλή λειτουργία.",
    failSafeGraceTitle: "Απαιτείται επαλήθευση άδειας",
    failSafeGraceMessage: "Συνδεθείτε στο διαδίκτυο για να επαληθεύσετε την άδειά σας. Η προστασία παραμένει ενεργή.",
    failSafePreservedTitle: "Προστασία ενεργή",
    failSafePreservedMessage: "Οι κανόνες προστασίας σας διατηρούνται. Επαληθεύστε την άδειά σας όταν είναι δυνατό.",
    failSafeDefaultTitle: "Ασφαλής λειτουργία ενεργή",
    failSafeDefaultMessage: "Το LinkShield λειτουργεί σε ασφαλή λειτουργία. Η προστασία παραμένει ενεργή.",
    dismissTooltip: "Κλείσιμο",
    dontShowAgain: "Να μην εμφανιστεί ξανά;",
    confirmYes: "Ναι",
    confirmNo: "Όχι",
    reportPhishingSuccess: "Αναφέρθηκε! Ευχαριστούμε που βοηθάτε στη βελτίωση της ασφάλειας."
  },

  // Ukrainian (uk)
  uk: {
    visualHijackingDetected: "Виявлено візуальне перехоплення",
    visualHijackingMessage: "Виявлено приховане накладання, яке намагається перехопити ваш клік. Це поширена фішингова техніка для перенаправлення на шкідливі сайти.",
    transparentHighZIndexOverlay: "Виявлено прозоре накладання з високим z-index",
    invisibleClickjackOverlay: "Виявлено невидиме clickjacking накладання",
    fullscreenTransparentOverlay: "Виявлено повноекранне прозоре накладання",
    hiddenLinkOverlay: "Виявлено приховане накладання посилання",
    detectionReason: "Причина виявлення",
    closeWarning: "Закрити",
    failSafeNetworkTitle: "Помилка перевірки ліцензії",
    failSafeNetworkMessage: "Не вдалося перевірити ліцензію через проблеми з мережею. Захист залишається активним у безпечному режимі.",
    failSafeGraceTitle: "Потрібна перевірка ліцензії",
    failSafeGraceMessage: "Підключіться до інтернету для перевірки ліцензії. Захист залишається активним.",
    failSafePreservedTitle: "Захист активний",
    failSafePreservedMessage: "Ваші правила захисту збережені. Перевірте ліцензію, коли це можливо.",
    failSafeDefaultTitle: "Безпечний режим активний",
    failSafeDefaultMessage: "LinkShield працює в безпечному режимі. Захист залишається активним.",
    dismissTooltip: "Закрити",
    dontShowAgain: "Більше не показувати?",
    confirmYes: "Так",
    confirmNo: "Ні",
    reportPhishingSuccess: "Повідомлено! Дякуємо за допомогу в покращенні безпеки."
  },

  // Russian (ru)
  ru: {
    visualHijackingDetected: "Обнаружен визуальный перехват",
    visualHijackingMessage: "Обнаружено скрытое наложение, пытающееся перехватить ваш клик. Это распространённая фишинговая техника для перенаправления на вредоносные сайты.",
    transparentHighZIndexOverlay: "Обнаружено прозрачное наложение с высоким z-index",
    invisibleClickjackOverlay: "Обнаружено невидимое clickjacking наложение",
    fullscreenTransparentOverlay: "Обнаружено полноэкранное прозрачное наложение",
    hiddenLinkOverlay: "Обнаружено скрытое наложение ссылки",
    detectionReason: "Причина обнаружения",
    closeWarning: "Закрыть",
    failSafeNetworkTitle: "Ошибка проверки лицензии",
    failSafeNetworkMessage: "Не удалось проверить лицензию из-за проблем с сетью. Защита остаётся активной в безопасном режиме.",
    failSafeGraceTitle: "Требуется проверка лицензии",
    failSafeGraceMessage: "Подключитесь к интернету для проверки лицензии. Защита остаётся активной.",
    failSafePreservedTitle: "Защита активна",
    failSafePreservedMessage: "Ваши правила защиты сохранены. Проверьте лицензию при возможности.",
    failSafeDefaultTitle: "Безопасный режим активен",
    failSafeDefaultMessage: "LinkShield работает в безопасном режиме. Защита остаётся активной.",
    dismissTooltip: "Закрыть",
    dontShowAgain: "Больше не показывать?",
    confirmYes: "Да",
    confirmNo: "Нет",
    reportPhishingSuccess: "Сообщено! Спасибо за помощь в улучшении безопасности."
  },

  // Japanese (ja)
  ja: {
    visualHijackingDetected: "ビジュアルハイジャックを検出",
    visualHijackingMessage: "クリックを傍受しようとする隠しオーバーレイが検出されました。これは悪意のあるサイトにリダイレクトする一般的なフィッシング手法です。",
    transparentHighZIndexOverlay: "高いz-indexの透明オーバーレイを検出",
    invisibleClickjackOverlay: "不可視のクリックジャッキングオーバーレイを検出",
    fullscreenTransparentOverlay: "フルスクリーン透明オーバーレイを検出",
    hiddenLinkOverlay: "隠しリンクオーバーレイを検出",
    detectionReason: "検出理由",
    closeWarning: "閉じる",
    failSafeNetworkTitle: "ライセンス確認に失敗",
    failSafeNetworkMessage: "ネットワークの問題によりライセンスを確認できませんでした。保護はセーフモードで有効なままです。",
    failSafeGraceTitle: "ライセンス確認が必要",
    failSafeGraceMessage: "ライセンスを確認するにはインターネットに接続してください。保護は有効なままです。",
    failSafePreservedTitle: "保護は有効",
    failSafePreservedMessage: "保護ルールは保持されています。可能な時にライセンスを確認してください。",
    failSafeDefaultTitle: "セーフモードが有効",
    failSafeDefaultMessage: "LinkShieldはセーフモードで動作しています。保護は有効なままです。",
    dismissTooltip: "閉じる",
    dontShowAgain: "今後表示しない？",
    confirmYes: "はい",
    confirmNo: "いいえ",
    reportPhishingSuccess: "報告完了！セキュリティ向上にご協力いただきありがとうございます。"
  },

  // Korean (ko)
  ko: {
    visualHijackingDetected: "비주얼 하이재킹 감지됨",
    visualHijackingMessage: "클릭을 가로채려는 숨겨진 오버레이가 감지되었습니다. 이것은 악성 사이트로 리디렉션하는 일반적인 피싱 기법입니다.",
    transparentHighZIndexOverlay: "높은 z-index의 투명 오버레이 감지됨",
    invisibleClickjackOverlay: "보이지 않는 클릭재킹 오버레이 감지됨",
    fullscreenTransparentOverlay: "전체 화면 투명 오버레이 감지됨",
    hiddenLinkOverlay: "숨겨진 링크 오버레이 감지됨",
    detectionReason: "감지 이유",
    closeWarning: "닫기",
    failSafeNetworkTitle: "라이선스 확인 실패",
    failSafeNetworkMessage: "네트워크 문제로 라이선스를 확인할 수 없습니다. 보호 기능은 안전 모드에서 활성 상태로 유지됩니다.",
    failSafeGraceTitle: "라이선스 확인 필요",
    failSafeGraceMessage: "라이선스를 확인하려면 인터넷에 연결하세요. 보호 기능은 활성 상태로 유지됩니다.",
    failSafePreservedTitle: "보호 활성",
    failSafePreservedMessage: "보호 규칙이 유지됩니다. 가능할 때 라이선스를 확인하세요.",
    failSafeDefaultTitle: "안전 모드 활성",
    failSafeDefaultMessage: "LinkShield가 안전 모드로 실행 중입니다. 보호 기능은 활성 상태로 유지됩니다.",
    dismissTooltip: "닫기",
    dontShowAgain: "다시 표시하지 않으시겠습니까?",
    confirmYes: "예",
    confirmNo: "아니오",
    reportPhishingSuccess: "신고 완료! 보안 향상에 도움을 주셔서 감사합니다."
  },

  // Chinese Simplified (zh)
  zh: {
    visualHijackingDetected: "检测到视觉劫持",
    visualHijackingMessage: "检测到试图拦截您点击的隐藏覆盖层。这是一种常见的钓鱼技术，用于将您重定向到恶意网站。",
    transparentHighZIndexOverlay: "检测到高z-index透明覆盖层",
    invisibleClickjackOverlay: "检测到不可见的点击劫持覆盖层",
    fullscreenTransparentOverlay: "检测到全屏透明覆盖层",
    hiddenLinkOverlay: "检测到隐藏链接覆盖层",
    detectionReason: "检测原因",
    closeWarning: "关闭",
    failSafeNetworkTitle: "许可证验证失败",
    failSafeNetworkMessage: "由于网络问题无法验证许可证。保护功能在安全模式下保持激活状态。",
    failSafeGraceTitle: "需要验证许可证",
    failSafeGraceMessage: "请连接互联网以验证您的许可证。保护功能保持激活状态。",
    failSafePreservedTitle: "保护已激活",
    failSafePreservedMessage: "您的保护规则已保留。请在可能时验证您的许可证。",
    failSafeDefaultTitle: "安全模式已激活",
    failSafeDefaultMessage: "LinkShield正在安全模式下运行。保护功能保持激活状态。",
    dismissTooltip: "关闭",
    dontShowAgain: "不再显示？",
    confirmYes: "是",
    confirmNo: "否",
    reportPhishingSuccess: "已举报！感谢您帮助提高安全性。"
  },

  // Thai (th)
  th: {
    visualHijackingDetected: "ตรวจพบการไฮแจ็กภาพ",
    visualHijackingMessage: "ตรวจพบโอเวอร์เลย์ที่ซ่อนอยู่พยายามดักจับการคลิกของคุณ นี่คือเทคนิคฟิชชิ่งทั่วไปเพื่อเปลี่ยนเส้นทางคุณไปยังเว็บไซต์อันตราย",
    transparentHighZIndexOverlay: "ตรวจพบโอเวอร์เลย์โปร่งใสที่มี z-index สูง",
    invisibleClickjackOverlay: "ตรวจพบโอเวอร์เลย์ clickjacking ที่มองไม่เห็น",
    fullscreenTransparentOverlay: "ตรวจพบโอเวอร์เลย์โปร่งใสแบบเต็มหน้าจอ",
    hiddenLinkOverlay: "ตรวจพบโอเวอร์เลย์ลิงก์ที่ซ่อนอยู่",
    detectionReason: "เหตุผลในการตรวจจับ",
    closeWarning: "ปิด",
    failSafeNetworkTitle: "การตรวจสอบใบอนุญาตล้มเหลว",
    failSafeNetworkMessage: "ไม่สามารถตรวจสอบใบอนุญาตได้เนื่องจากปัญหาเครือข่าย การป้องกันยังคงทำงานในโหมดปลอดภัย",
    failSafeGraceTitle: "ต้องการการตรวจสอบใบอนุญาต",
    failSafeGraceMessage: "กรุณาเชื่อมต่ออินเทอร์เน็ตเพื่อตรวจสอบใบอนุญาตของคุณ การป้องกันยังคงทำงาน",
    failSafePreservedTitle: "การป้องกันทำงานอยู่",
    failSafePreservedMessage: "กฎการป้องกันของคุณได้รับการรักษาไว้ กรุณาตรวจสอบใบอนุญาตเมื่อเป็นไปได้",
    failSafeDefaultTitle: "โหมดปลอดภัยทำงานอยู่",
    failSafeDefaultMessage: "LinkShield กำลังทำงานในโหมดปลอดภัย การป้องกันยังคงทำงาน",
    dismissTooltip: "ปิด",
    dontShowAgain: "ไม่ต้องแสดงอีก?",
    confirmYes: "ใช่",
    confirmNo: "ไม่",
    reportPhishingSuccess: "รายงานแล้ว! ขอบคุณที่ช่วยปรับปรุงความปลอดภัย"
  },

  // Vietnamese (vi)
  vi: {
    visualHijackingDetected: "Phát hiện chiếm quyền hình ảnh",
    visualHijackingMessage: "Đã phát hiện lớp phủ ẩn đang cố gắng chặn nhấp chuột của bạn. Đây là kỹ thuật lừa đảo phổ biến để chuyển hướng bạn đến các trang web độc hại.",
    transparentHighZIndexOverlay: "Phát hiện lớp phủ trong suốt có z-index cao",
    invisibleClickjackOverlay: "Phát hiện lớp phủ clickjacking vô hình",
    fullscreenTransparentOverlay: "Phát hiện lớp phủ trong suốt toàn màn hình",
    hiddenLinkOverlay: "Phát hiện lớp phủ liên kết ẩn",
    detectionReason: "Lý do phát hiện",
    closeWarning: "Đóng",
    failSafeNetworkTitle: "Xác minh giấy phép thất bại",
    failSafeNetworkMessage: "Không thể xác minh giấy phép do sự cố mạng. Bảo vệ vẫn hoạt động ở chế độ an toàn.",
    failSafeGraceTitle: "Cần xác minh giấy phép",
    failSafeGraceMessage: "Vui lòng kết nối internet để xác minh giấy phép của bạn. Bảo vệ vẫn hoạt động.",
    failSafePreservedTitle: "Bảo vệ đang hoạt động",
    failSafePreservedMessage: "Các quy tắc bảo vệ của bạn được giữ nguyên. Vui lòng xác minh giấy phép khi có thể.",
    failSafeDefaultTitle: "Chế độ an toàn đang hoạt động",
    failSafeDefaultMessage: "LinkShield đang chạy ở chế độ an toàn. Bảo vệ vẫn hoạt động.",
    dismissTooltip: "Đóng",
    dontShowAgain: "Không hiển thị lại?",
    confirmYes: "Có",
    confirmNo: "Không",
    reportPhishingSuccess: "Đã báo cáo! Cảm ơn bạn đã giúp cải thiện bảo mật."
  },

  // Hindi (hi)
  hi: {
    visualHijackingDetected: "विजुअल हाईजैकिंग का पता चला",
    visualHijackingMessage: "आपके क्लिक को इंटरसेप्ट करने की कोशिश करने वाला एक छिपा हुआ ओवरले पाया गया। यह आपको दुर्भावनापूर्ण साइटों पर रीडायरेक्ट करने की एक आम फ़िशिंग तकनीक है।",
    transparentHighZIndexOverlay: "उच्च z-index वाला पारदर्शी ओवरले पाया गया",
    invisibleClickjackOverlay: "अदृश्य क्लिकजैकिंग ओवरले पाया गया",
    fullscreenTransparentOverlay: "फुलस्क्रीन पारदर्शी ओवरले पाया गया",
    hiddenLinkOverlay: "छिपा हुआ लिंक ओवरले पाया गया",
    detectionReason: "पता लगाने का कारण",
    closeWarning: "बंद करें",
    failSafeNetworkTitle: "लाइसेंस सत्यापन विफल",
    failSafeNetworkMessage: "नेटवर्क समस्याओं के कारण लाइसेंस सत्यापित नहीं हो सका। सुरक्षा सेफ मोड में सक्रिय है।",
    failSafeGraceTitle: "लाइसेंस सत्यापन आवश्यक",
    failSafeGraceMessage: "अपना लाइसेंस सत्यापित करने के लिए इंटरनेट से कनेक्ट करें। सुरक्षा सक्रिय है।",
    failSafePreservedTitle: "सुरक्षा सक्रिय",
    failSafePreservedMessage: "आपके सुरक्षा नियम संरक्षित हैं। जब संभव हो अपना लाइसेंस सत्यापित करें।",
    failSafeDefaultTitle: "सेफ मोड सक्रिय",
    failSafeDefaultMessage: "LinkShield सेफ मोड में चल रहा है। सुरक्षा सक्रिय है।",
    dismissTooltip: "बंद करें",
    dontShowAgain: "फिर से न दिखाएं?",
    confirmYes: "हाँ",
    confirmNo: "नहीं",
    reportPhishingSuccess: "रिपोर्ट किया गया! सुरक्षा बेहतर करने में मदद के लिए धन्यवाद।"
  },

  // Indonesian (id)
  id: {
    visualHijackingDetected: "Pembajakan visual terdeteksi",
    visualHijackingMessage: "Terdeteksi overlay tersembunyi yang mencoba menyadap klik Anda. Ini adalah teknik phishing umum untuk mengarahkan Anda ke situs berbahaya.",
    transparentHighZIndexOverlay: "Terdeteksi overlay transparan dengan z-index tinggi",
    invisibleClickjackOverlay: "Terdeteksi overlay clickjacking tidak terlihat",
    fullscreenTransparentOverlay: "Terdeteksi overlay transparan layar penuh",
    hiddenLinkOverlay: "Terdeteksi overlay tautan tersembunyi",
    detectionReason: "Alasan deteksi",
    closeWarning: "Tutup",
    failSafeNetworkTitle: "Verifikasi lisensi gagal",
    failSafeNetworkMessage: "Tidak dapat memverifikasi lisensi karena masalah jaringan. Perlindungan tetap aktif dalam mode aman.",
    failSafeGraceTitle: "Verifikasi lisensi diperlukan",
    failSafeGraceMessage: "Hubungkan ke internet untuk memverifikasi lisensi Anda. Perlindungan tetap aktif.",
    failSafePreservedTitle: "Perlindungan aktif",
    failSafePreservedMessage: "Aturan perlindungan Anda dipertahankan. Verifikasi lisensi Anda jika memungkinkan.",
    failSafeDefaultTitle: "Mode aman aktif",
    failSafeDefaultMessage: "LinkShield berjalan dalam mode aman. Perlindungan tetap aktif.",
    dismissTooltip: "Tutup",
    dontShowAgain: "Jangan tampilkan lagi?",
    confirmYes: "Ya",
    confirmNo: "Tidak",
    reportPhishingSuccess: "Dilaporkan! Terima kasih telah membantu meningkatkan keamanan."
  },

  // Arabic (ar)
  ar: {
    visualHijackingDetected: "تم اكتشاف اختطاف بصري",
    visualHijackingMessage: "تم اكتشاف طبقة مخفية تحاول اعتراض نقرتك. هذه تقنية تصيد شائعة لإعادة توجيهك إلى مواقع ضارة.",
    transparentHighZIndexOverlay: "تم اكتشاف طبقة شفافة ذات z-index عالي",
    invisibleClickjackOverlay: "تم اكتشاف طبقة clickjacking غير مرئية",
    fullscreenTransparentOverlay: "تم اكتشاف طبقة شفافة بملء الشاشة",
    hiddenLinkOverlay: "تم اكتشاف طبقة رابط مخفي",
    detectionReason: "سبب الاكتشاف",
    closeWarning: "إغلاق",
    failSafeNetworkTitle: "فشل التحقق من الترخيص",
    failSafeNetworkMessage: "تعذر التحقق من الترخيص بسبب مشاكل في الشبكة. تظل الحماية نشطة في الوضع الآمن.",
    failSafeGraceTitle: "مطلوب التحقق من الترخيص",
    failSafeGraceMessage: "يرجى الاتصال بالإنترنت للتحقق من ترخيصك. تظل الحماية نشطة.",
    failSafePreservedTitle: "الحماية نشطة",
    failSafePreservedMessage: "تم الحفاظ على قواعد الحماية الخاصة بك. يرجى التحقق من ترخيصك عندما يكون ذلك ممكناً.",
    failSafeDefaultTitle: "الوضع الآمن نشط",
    failSafeDefaultMessage: "LinkShield يعمل في الوضع الآمن. تظل الحماية نشطة.",
    dismissTooltip: "إغلاق",
    dontShowAgain: "عدم الإظهار مرة أخرى؟",
    confirmYes: "نعم",
    confirmNo: "لا",
    reportPhishingSuccess: "تم الإبلاغ! شكراً لمساعدتك في تحسين الأمان."
  },

  // Turkish (tr)
  tr: {
    visualHijackingDetected: "Görsel ele geçirme algılandı",
    visualHijackingMessage: "Tıklamanızı engellemeye çalışan gizli bir kaplama algılandı. Bu, sizi kötü amaçlı sitelere yönlendirmek için kullanılan yaygın bir oltalama tekniğidir.",
    transparentHighZIndexOverlay: "Yüksek z-index'li şeffaf kaplama algılandı",
    invisibleClickjackOverlay: "Görünmez clickjacking kaplaması algılandı",
    fullscreenTransparentOverlay: "Tam ekran şeffaf kaplama algılandı",
    hiddenLinkOverlay: "Gizli bağlantı kaplaması algılandı",
    detectionReason: "Algılama nedeni",
    closeWarning: "Kapat",
    failSafeNetworkTitle: "Lisans doğrulama başarısız",
    failSafeNetworkMessage: "Ağ sorunları nedeniyle lisans doğrulanamadı. Koruma güvenli modda aktif kalmaya devam ediyor.",
    failSafeGraceTitle: "Lisans doğrulaması gerekli",
    failSafeGraceMessage: "Lisansınızı doğrulamak için internete bağlanın. Koruma aktif kalmaya devam ediyor.",
    failSafePreservedTitle: "Koruma aktif",
    failSafePreservedMessage: "Koruma kurallarınız korundu. Mümkün olduğunda lisansınızı doğrulayın.",
    failSafeDefaultTitle: "Güvenli mod aktif",
    failSafeDefaultMessage: "LinkShield güvenli modda çalışıyor. Koruma aktif kalmaya devam ediyor.",
    dismissTooltip: "Kapat",
    dontShowAgain: "Tekrar gösterme?",
    confirmYes: "Evet",
    confirmNo: "Hayır",
    reportPhishingSuccess: "Bildirildi! Güvenliği iyileştirmeye yardımcı olduğunuz için teşekkürler."
  }
};

// Keys to translate
const keysToTranslate = [
  'visualHijackingDetected', 'visualHijackingMessage', 'transparentHighZIndexOverlay',
  'invisibleClickjackOverlay', 'fullscreenTransparentOverlay', 'hiddenLinkOverlay',
  'detectionReason', 'closeWarning', 'failSafeNetworkTitle', 'failSafeNetworkMessage',
  'failSafeGraceTitle', 'failSafeGraceMessage', 'failSafePreservedTitle', 'failSafePreservedMessage',
  'failSafeDefaultTitle', 'failSafeDefaultMessage', 'dismissTooltip', 'dontShowAgain',
  'confirmYes', 'confirmNo', 'reportPhishingSuccess'
];

console.log('=== SECURITY KEYS TRANSLATION SCRIPT ===');
console.log(`Keys to translate: ${keysToTranslate.length}`);
console.log(`Languages: ${Object.keys(translations).length}`);
console.log('');

let totalUpdated = 0;

for (const [locale, trans] of Object.entries(translations)) {
  const localePath = path.join(localesDir, locale, 'messages.json');

  try {
    const data = require(localePath);
    let updated = 0;

    for (const key of keysToTranslate) {
      if (trans[key] && data[key]) {
        // Update the message with translated text
        data[key].message = trans[key];
        // Update description to indicate it's translated
        data[key].description = `Translated from EN for v8.0.0 security update`;
        updated++;
      }
    }

    // Write back to file
    fs.writeFileSync(localePath, JSON.stringify(data, null, 2) + '\n');

    console.log(`${locale}: Updated ${updated}/21 keys`);
    totalUpdated += updated;

  } catch (e) {
    console.error(`${locale}: ERROR - ${e.message}`);
  }
}

console.log('');
console.log('=== TRANSLATION COMPLETE ===');
console.log(`Total keys translated: ${totalUpdated}`);
console.log(`Average per locale: ${(totalUpdated / Object.keys(translations).length).toFixed(1)}`);
