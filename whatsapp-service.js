'use strict';

/**
 * 📱 DenTrust WhatsApp Notification Service
 * Sends rich, detailed WhatsApp order alerts to the 5 admin numbers and confirmation to the doctor.
 */

const ADMIN_PHONES = [
  '01157004081',
  '01123144277',
  '01123144288',
  '01014067776',
  '01011222763'
];

function normalizeEgyptPhone(phone) {
  if (!phone) return '';
  let clean = String(phone).replace(/[^\d+]/g, '');
  if (clean.startsWith('01')) clean = '2' + clean;
  else if (clean.startsWith('+20')) clean = clean.replace('+', '');
  else if (clean.startsWith('20') && clean.length === 12) { /* already standard */ }
  else if (clean.startsWith('+')) clean = clean.replace('+', '');
  return clean;
}

/**
 * Formats ultra-detailed order message for warehouse & admin staff.
 */
function formatAdminOrderMessage(data) {
  const orderId = data.dentrust_order_id || data.id || '—';
  const name = data.customer_name || 'طبيب';
  const phone = data.customer_phone || '—';
  const city = data.customer_city || data.city || '—';
  const addr = data.customer_address || data.address || city || '—';
  const total = parseFloat(data.total_amount || data.total || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
  const payment = data.payment_method === 'instapay' ? 'انستاباي (InstaPay)' : 'دفع عند الاستلام (COD)';
  const notes = data.order_notes || data.notes || data.customer_notes || 'لا توجد ملاحظات خاصة';

  const items = Array.isArray(data.items) ? data.items : [];
  let itemsText = '';
  let totalItemsCount = 0;

  if (items.length > 0) {
    itemsText = items.map((item, idx) => {
      const pName = item.product_name || item.name || 'صنف';
      const qty = parseInt(item.quantity || 1, 10);
      totalItemsCount += qty;
      const opt = item.selected_option || item.selectedOption || null;
      const uPrice = parseFloat(item.unit_price || 0);
      const sub = (uPrice * qty).toLocaleString('en-US', { minimumFractionDigits: 2 });

      let optLine = '';
      if (opt) {
        optLine = `\n   • *المقاس / الخيار:* ${opt} 📏`;
      }

      return `${idx + 1}️⃣ *${pName}*${optLine}\n   • *الكمية:* ${qty} قطع | *السعر:* ${uPrice} ج (الإجمالي: ${sub} ج)`;
    }).join('\n\n');
  } else if (data.items_summary) {
    itemsText = `• ${data.items_summary}`;
  } else {
    itemsText = '• لا توجد أصناف مسجلة';
  }

  const now = new Date();
  const timeStr = now.toLocaleDateString('ar-EG', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });

  return (
`🛒 *طلب جديد من المتجر الإلكتروني (#${orderId})*
━━━━━━━━━━━━━━━━━━━━
👨‍⚕️ *الطبيب:* ${name}
📞 *الهاتف:* ${phone}
🏥 *العنوان:* ${addr}
🚚 *المحافظة:* ${city}
💵 *إجمالي الفاتورة:* ${total} ج.م
💳 *طريقة الدفع:* ${payment}
📦 *عدد الأصناف:* ${items.length} صنف (${totalItemsCount} قطعة)
━━━━━━━━━━━━━━━━━━━━
📦 *تفاصيل الأصناف والمقاسات بالكامل:*

${itemsText}

━━━━━━━━━━━━━━━━━━━━
📝 *ملاحظات الطبيب:*
"${notes}"

⏰ *الوقت:* ${timeStr}`
  );
}

/**
 * Formats polite confirmation message for the ordering doctor.
 */
function formatDoctorConfirmationMessage(data) {
  const orderId = data.dentrust_order_id || data.id || '—';
  const name = data.customer_name || 'دكتور';
  const total = parseFloat(data.total_amount || data.total || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });

  return (
`أهلاً بك د. ${name} 👋
تم استلام طلبك رقم *(#${orderId})* بنجاح من متجر *DenTrust* بقيمة *${total} ج.م* ✅

فريق العمل يقوم بمراجعة وتجهيز طلبيتك بالمقاسات والمواصفات المطلوبة وسيقوم مندوب الشحن بالتواصل معك للتوصيل للعيادة.

شكراً لثقتك في DenTrust 🌸`
  );
}

/**
 * Sends a single WhatsApp message via UltraMsg / generic HTTP API gateway if configured.
 */
async function sendViaGateway(toPhone, message, config = {}) {
  const instanceId = config.instance_id || process.env.WHATSAPP_INSTANCE_ID;
  const token = config.token || process.env.WHATSAPP_TOKEN;

  if (!instanceId || !token) {
    // Gateway not configured yet — return false silently without throwing
    return { ok: false, reason: 'gateway_not_configured' };
  }

  const formattedPhone = normalizeEgyptPhone(toPhone);
  if (!formattedPhone) return { ok: false, reason: 'invalid_phone' };

  try {
    const url = `https://api.ultramsg.com/${instanceId}/messages/chat`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token,
        to: formattedPhone,
        body: message
      }),
      signal: AbortSignal.timeout(12000)
    });

    const data = await res.json().catch(() => ({}));
    if (res.ok && (data.sent === 'true' || data.sent === true || data.id)) {
      console.log(`[WhatsApp] Sent successfully to ${formattedPhone}`);
      return { ok: true, data };
    } else {
      console.warn(`[WhatsApp] Gateway response for ${formattedPhone}:`, data);
      return { ok: false, data };
    }
  } catch (err) {
    console.error(`[WhatsApp] Send error to ${formattedPhone}:`, err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * Dispatches WhatsApp order notifications to all 5 admin numbers + the doctor.
 */
async function notifyNewOrder(orderData, posDb) {
  const adminMsg = formatAdminOrderMessage(orderData);
  const doctorMsg = formatDoctorConfirmationMessage(orderData);

  // 1. Fetch any custom WhatsApp gateway config stored in DB
  let gatewayConfig = {};
  if (posDb) {
    try {
      const { rows: [setting] } = await posDb.query(
        "SELECT value FROM settings WHERE key='whatsapp_config' LIMIT 1"
      ).catch(() => ({ rows: [] }));
      if (setting?.value) {
        gatewayConfig = typeof setting.value === 'string' ? JSON.parse(setting.value) : setting.value;
      }
    } catch (_) {}
  }

  // 2. Dispatch to 5 Admin Numbers
  console.log(`[WhatsApp] Dispatching order #${orderData.dentrust_order_id || orderData.id} alerts to 5 admins...`);
  const adminPromises = ADMIN_PHONES.map(phone => sendViaGateway(phone, adminMsg, gatewayConfig));

  // 3. Dispatch to Doctor if valid phone provided
  if (orderData.customer_phone) {
    adminPromises.push(sendViaGateway(orderData.customer_phone, doctorMsg, gatewayConfig));
  }

  const results = await Promise.allSettled(adminPromises);
  return {
    adminMessage: adminMsg,
    doctorMessage: doctorMsg,
    results
  };
}

module.exports = {
  ADMIN_PHONES,
  normalizeEgyptPhone,
  formatAdminOrderMessage,
  formatDoctorConfirmationMessage,
  sendViaGateway,
  notifyNewOrder
};
