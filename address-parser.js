'use strict';

const EGYPT_GOVERNORATES = {
  'القاهرة': ['النزهة', 'مدينة نصر', 'المعادي', 'مصر الجديدة', 'الزيتون', 'شبرا', 'المطرية', 'عين شمس', 'الزمالك', 'وسط البلد', 'المنيل', 'الدقي', 'بولاق', 'السيدة زينب', 'الخليفة', 'مصر القديمة', 'حلوان', 'المعصرة', '15 مايو', 'التجمع الخامس', 'التجمع', 'القاهرة الجديدة', 'القطامية', 'البساتين', 'دار السلام', 'الأميرية', 'منشأة ناصر', 'الشرابية', 'روض الفرج', 'العمرانية', 'فيصل', 'الهرم', 'عين الصيرة', 'طره', 'الباجور', 'المقطم', 'الخصوص', 'شبرا الخيمة الجديدة', 'مدينة بدر', 'العبور', 'أكتوبر (جيزة)', 'الشيخ زايد', 'مدينتي', 'الرحاب', 'الشروق'],
  'الجيزة': ['الدقي', 'العجوزة', 'المهندسين', 'فيصل', 'الهرم', 'البدرشين', 'البراجيل', 'أوسيم', 'أبو رواش', 'العياط', 'الواحات البحرية', 'الصف', '6 أكتوبر', 'أكتوبر', 'الشيخ زايد', 'حدائق الأهرام', 'طموه', 'الحوامدية', 'إمبابة', 'بولاق الدكرور', 'أبو النمرس', 'كرداسة', 'أبو الغيط', 'العمرانية', 'ميدان الجيزة'],
  'الاسكندرية': ['المنتزه', 'شرق', 'وسط', 'غرب', 'الجمرك', 'العجمي', 'العامرية', 'برج العرب', 'سيدي جابر', 'سموحة', 'محرم بك', 'ميامي', 'لوران', 'سيدي بشر', 'رشدي', 'كفر عبده', 'ستانلي', 'جليم', 'الإبراهيمية', 'كامب شيزار', 'الشاطبي', 'بحري', 'المندرة', 'العصافرة', 'المعمورة', 'أبو قير'],
  'الدقهلية': ['المنصورة', 'ميت غمر', 'السنبلاوين', 'دكرنس', 'بلقاس', 'شربين', 'المنزلة', 'طلخا', 'الجمالية', 'منية النصر', 'أجا', 'بني عبيد', 'تمى الأمديد', 'ميت سلسيل', 'نبروه'],
  'الشرقية': ['الزقازيق', 'العاشر من رمضان', 'منيا القمح', 'بلبيس', 'مشتول السوق', 'القنايات', 'أبو حماد', 'القرين', 'فاقوس', 'أبو كبير', 'الحسينية', 'كفر صقر', 'أولاد صقر', 'ديرب نجم', 'الإبراهيمية', 'صان الحجر'],
  'الغربية': ['طنطا', 'المحلة الكبرى', 'المحلة', 'كفر الزيات', 'زفتى', 'السنطة', 'قطور', 'بسيون', 'سمنود'],
  'المنوفية': ['شبين الكوم', 'مدينة السادات', 'السادات', 'منوف', 'أشمون', 'الباجور', 'قويسنا', 'بركة السبع', 'تلا', 'الشهداء'],
  'القليوبية': ['بنها', 'قليوب', 'شبرا الخيمة', 'القناطر الخيرية', 'الخانكة', 'كفر شكر', 'طوخ', 'قها', 'العبور', 'الخصوص', 'شبين القناطر'],
  'البحيرة': ['دمنهور', 'كفر الدوار', 'رشيد', 'إدكو', 'أبو المطامير', 'أبو حمص', 'الدلنجات', 'المحمودية', 'الرحمانية', 'إيتاي البارود', 'حوش عيسى', 'كوم حمادة', 'بدر', 'وادي النطرون', 'النوبارية'],
  'كفر الشيخ': ['كفر الشيخ', 'دسوق', 'فوه', 'مطوبس', 'قلين', 'سيدي سالم', 'الرياض', 'بيلا', 'الحامول', 'بلطيم', 'سيدي غازي'],
  'دمياط': ['دمياط', 'دمياط الجديدة', 'رأس البر', 'فارسكور', 'الزرقا', 'كفر سعد', 'كفر البطيخ', 'عزبة البرج'],
  'بورسعيد': ['حي الشرق', 'حي العرب', 'حي المناخ', 'حي الضواحي', 'حي الزهور', 'بورفؤاد', 'بورسعيد'],
  'الإسماعيلية': ['الإسماعيلية', 'فايد', 'القنطرة شرق', 'القنطرة غرب', 'التل الكبير', 'أبو صوير', 'القصاصين'],
  'السويس': ['السويس', 'حي الأربعين', 'حي عتاقة', 'حي فيصل', 'العين السخنة'],
  'بني سويف': ['بني سويف', 'الواسطى', 'ناصر', 'إهناسيا', 'ببا', 'سمسطا', 'الفشن'],
  'الفيوم': ['الفيوم', 'سنورس', 'إطسا', 'طامية', 'أبشواي'],
  'المنيا': ['المنيا', 'ملوي', 'مغاغة', 'بني مزار', 'مطاي', 'سمالوط', 'أبو قرقاص', 'دير مواس'],
  'أسيوط': ['أسيوط', 'ديروط', 'القوصية', 'أبنوب', 'منفلوط', 'أبو تيج'],
  'سوهاج': ['سوهاج', 'أخميم', 'جرجا', 'طهطا', 'طما', 'البلينا', 'المراغة'],
  'قنا': ['قنا', 'نجع حمادي', 'دشنا', 'قوص', 'فرشوط', 'أبو تشت'],
  'الأقصر': ['الأقصر', 'إسنا', 'أرمنت'],
  'أسوان': ['أسوان', 'إدفو', 'كوم أمبو', 'نصر النوبة'],
  'البحر الأحمر': ['الغردقة', 'الجونة', 'سفاجا', 'القصير', 'مرسى علم'],
  'مطروح': ['مرسى مطروح', 'العلمين', 'الحمام', 'الساحل الشمالي', 'مارينا', 'سيدي عبد الرحمن'],
  'جنوب سيناء': ['شرم الشيخ', 'طور سيناء', 'دهب', 'نويبع', 'طابا', 'رأس سدر'],
  'شمال سيناء': ['العريش', 'بئر العبد']
};

function normalizeArabicText(str) {
  return (str || '')
    .replace(/[أإآ]/g, 'ا')
    .replace(/[ة]/g, 'ه')
    .replace(/[ى]/g, 'ي')
    .replace(/[\u064B-\u065F]/g, '')
    .toLowerCase();
}

function parseEgyptianAddress(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const cleanRaw = raw.trim();
  if (!cleanRaw) return null;

  const normRaw = normalizeArabicText(cleanRaw);

  let detectedCity = '';
  let detectedRegion = '';

  for (const city of Object.keys(EGYPT_GOVERNORATES)) {
    const normCity = normalizeArabicText(city);
    if (normRaw.includes(normCity)) {
      detectedCity = city;
      break;
    }
  }

  const allRegions = [];
  for (const [gov, districts] of Object.entries(EGYPT_GOVERNORATES)) {
    for (const d of districts) {
      allRegions.push({ gov, district: d, norm: normalizeArabicText(d) });
    }
  }
  allRegions.sort((a, b) => b.norm.length - a.norm.length);

  for (const item of allRegions) {
    if (normRaw.includes(item.norm)) {
      detectedRegion = item.district;
      if (!detectedCity) {
        detectedCity = item.gov;
      }
      break;
    }
  }

  if (!detectedCity && !detectedRegion) {
    detectedCity = 'القاهرة';
    detectedRegion = 'وسط البلد';
  } else if (!detectedCity && detectedRegion) {
    detectedCity = 'القاهرة';
  } else if (detectedCity && !detectedRegion) {
    const govDistricts = EGYPT_GOVERNORATES[detectedCity];
    detectedRegion = (govDistricts && govDistricts[0]) || detectedCity;
  }

  let title = 'العيادة الرئيسية';
  if (detectedRegion && detectedRegion !== 'وسط البلد') {
    title = 'عيادة ' + detectedRegion;
  } else if (detectedCity && detectedCity !== 'القاهرة') {
    title = 'عيادة ' + detectedCity;
  }

  let details = cleanRaw;
  const parts = cleanRaw.split(/[-–—,،|\/]/).map(p => p.trim()).filter(Boolean);
  if (parts.length > 1) {
    const filtered = parts.filter(p => {
      const np = normalizeArabicText(p);
      return np !== normalizeArabicText(detectedCity) && np !== normalizeArabicText(detectedRegion);
    });
    if (filtered.length > 0) {
      details = filtered.join(' - ');
    }
  }

  return {
    id: 'addr_' + Math.random().toString(36).substring(2, 9),
    title,
    city: detectedCity,
    region: detectedRegion,
    details,
    address: cleanRaw,
    is_default: true
  };
}

function normalizeEgyptianAddresses(addrs, legacyAddress) {
  let list = Array.isArray(addrs) ? addrs : [];
  if (typeof addrs === 'string') {
    try { list = JSON.parse(addrs); } catch (_) { list = []; }
  }

  if ((!list || list.length === 0) && legacyAddress && typeof legacyAddress === 'string' && legacyAddress.trim()) {
    const parsed = parseEgyptianAddress(legacyAddress.trim());
    if (parsed) list = [parsed];
  }

  list = list.map((item, idx) => {
    if (typeof item === 'string') {
      return parseEgyptianAddress(item) || {
        id: 'addr_' + (idx + 1),
        title: 'عيادة #' + (idx + 1),
        city: 'القاهرة',
        region: 'وسط البلد',
        details: item,
        address: item,
        is_default: idx === 0
      };
    }
    if (item && (!item.city || !item.region)) {
      const rawText = item.address || item.details || item.title || '';
      const parsed = parseEgyptianAddress(rawText);
      if (parsed) {
        return {
          ...item,
          city: item.city || parsed.city,
          region: item.region || parsed.region,
          details: item.details || parsed.details || rawText,
          address: item.address || parsed.address || rawText,
          is_default: item.is_default !== undefined ? item.is_default : (idx === 0)
        };
      }
    }
    return item;
  });

  return list;
}

module.exports = {
  EGYPT_GOVERNORATES,
  normalizeArabicText,
  parseEgyptianAddress,
  normalizeEgyptianAddresses
};
