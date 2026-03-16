// ─────────────────────────────────────────────
//  server.js — Backend do portfólio Marta Isabelle
//  Dependências: npm install express helmet cors express-rate-limit zod dotenv
// ─────────────────────────────────────────────

import 'dotenv/config';
import express    from 'express';
import helmet     from 'helmet';
import cors       from 'cors';
import rateLimit  from 'express-rate-limit';
import { z }      from 'zod';

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middlewares globais ──────────────────────

// Headers de segurança automáticos (XSS, clickjacking, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc : ["'self'"],
      scriptSrc  : ["'self'"],
      styleSrc   : ["'self'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      fontSrc    : ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      imgSrc     : ["'self'", "data:", "https://martaisabelle.dev"],
      connectSrc : ["'self'", "https://formspree.io"],
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy       : { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// Parse JSON no body
app.use(express.json({ limit: '10kb' }));

// CORS — permite apenas o seu domínio chamar a API
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5500')
  .split(',')
  .map(o => o.trim());

const isProduction = process.env.NODE_ENV === 'production';

app.use(cors({
  origin: (origin, callback) => {
    // Em produção, exige origin válida; em dev permite sem origin (curl, Postman)
    if (!isProduction && !origin) {
      callback(null, true);
    } else if (origin && allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origem não permitida pelo CORS'));
    }
  }
}));

// ── Rate limit anti-spam ─────────────────────
// Máximo 5 envios por IP a cada 10 minutos
const contactLimiter = rateLimit({
  windowMs : 10 * 60 * 1000, // 10 minutos
  max      : 5,
  message  : { error: 'Muitas tentativas. Aguarde 10 minutos.' },
  standardHeaders: true,
  legacyHeaders  : false,
});

// ── Schema de validação com Zod ───────────────
const contactSchema = z.object({
  name   : z.string().min(2,  'Nome muito curto.')
                     .max(100, 'Nome máximo 100 caracteres.'),
  company: z.string().max(100, 'Empresa máximo 100 caracteres.').optional(),
  email  : z.string().email('E-mail inválido.'),
  message: z.string().min(10,  'Mensagem muito curta.')
                     .max(1000, 'Mensagem máximo 1000 caracteres.'),
  website: z.string().max(0).optional(), // honeypot — deve vir vazio
});

// ── Sanitização simples ──────────────────────
// Remove tags HTML do texto para evitar injeção
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/&(?!(?:amp|lt|gt|quot|apos);)/g, '&amp;')
    .trim();
}

// ── Rota de contato ──────────────────────────
app.post('/api/contact', contactLimiter, async (req, res) => {
  try {
    // 1. Honeypot — bots preenchem campos invisíveis
    if (req.body.website && req.body.website.length > 0) {
      // Retorna 200 para não avisar o bot que foi bloqueado
      return res.status(200).json({ ok: true });
    }

    // 2. Validar com Zod
    const parsed = contactSchema.safeParse(req.body);
    if (!parsed.success) {
      const errors = parsed.error.errors.map(e => e.message);
      return res.status(400).json({ error: errors.join(' ') });
    }

    const { name, company, email, message } = parsed.data;

    // 3. Sanitizar campos de texto
    const safe = {
      name   : sanitize(name),
      company: sanitize(company || ''),
      email  : sanitize(email),
      message: sanitize(message),
    };

    // 4. Enviar para o Formspree
    const formspreeRes = await fetch(
      `https://formspree.io/f/${process.env.FORMSPREE_ID}`,
      {
        method : 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept'      : 'application/json',
        },
        body: JSON.stringify({
          name   : safe.name,
          company: safe.company,
          email  : safe.email,
          message: safe.message,
          _replyto: safe.email,
          _subject: `[Portfolio] Nova mensagem de ${safe.name}`,
        }),
      }
    );

    const formspreeData = await formspreeRes.json();

    if (!formspreeRes.ok) {
      console.error('Formspree error:', formspreeData);
      return res.status(502).json({ error: 'Erro ao enviar mensagem. Tente novamente.' });
    }

    return res.status(200).json({ ok: true, message: 'Mensagem enviada com sucesso!' });

  } catch (err) {
    console.error('Server error:', err);
    return res.status(500).json({ error: 'Erro interno. Tente novamente mais tarde.' });
  }
});

// ── Health check ─────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── 404 para rotas desconhecidas ─────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

// ── Start ─────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
