import { useEffect } from "react";
import "@n8n/chat/style.css"; // ייבוא ה-CSS של הווידג'ט
import { createChat } from "@n8n/chat";

const Chatbot = () => {
  // כתובת ה-Webhook האמיתית שלך מ-n8n
  // זו הכתובת שמקבלים מצומת "When chat message received" במצב "Active"
  const N8N_WEBHOOK_URL =
    "http://localhost:5678/webhook/121979d5-c11b-4186-992a-a74bec9e302d/chat";

  useEffect(() => {
    // ***** הסרנו את שורת הבדיקה שגרמה לבעיה *****

    createChat({
      webhookUrl: N8N_WEBHOOK_URL,
      target: "#n8n-chat-container",
      mode: "window",
      initialMessages: [
        "שלום! איך אוכל לעזור לך היום? 👋",
        "אני כאן כדי לענות על שאלות לגבי המוצרים שלנו ולקבוע פגישות.",
        "או פשוט לקחת את הפרטים שלך ולחזור אליך בהקדם",
      ],
      i18n: {
        en: {
          title: "צ'אט בוט של האתר",
          subtitle: "אנחנו כאן לעזור לך 24/7.",
          footer: "מופעל על ידי n8n",
          getStarted: "שיחה חדשה",
          inputPlaceholder: "הקלד את שאלתך..",
          closeButtonTooltip: "סגור", // הוספתי ערך לטולטיפ סגור, אם רוצים
        },
      },
      // הגדרות נוספות שאתה יכול להתאים אישית
      // showWelcomeScreen: false,
      // defaultLanguage: 'he',
      // chatInputKey: 'message',
      // chatSessionKey: 'myCustomSessionId',
      // loadPreviousSession: true,
      // metadata: { userId: '123', plan: 'premium' },
    });
  }, []); // ריצה רק פעם אחת כשהקומפוננטה נטענת

  return (
    <div
      id="n8n-chat-container"
      style={{
        position: "fixed",
        bottom: "20px",
        right: "20px",
        zIndex: 1000,
      }}
    >
      {/* הווידג'ט של n8n ייטען אוטומטית לתוך הדיב הזה */}
    </div>
  );
};

export default Chatbot;
