require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { v2: cloudinary } = require('cloudinary');

// ── Config ────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

// ── Middleware ────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Demasiadas peticiones.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api', generalLimiter);

// ── Helper auth ───────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  const token = header.split(' ')[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
  req.userId = user.id;
  next();
}

// ── Health ────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'red-social-server' });
});

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, username } = req.body;

  if (!email || !password || !username) {
    return res.status(400).json({ error: 'Email, contraseña y username son requeridos' });
  }
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username debe tener entre 3 y 30 caracteres' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Username solo puede tener letras, números y _' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });
  }

  const { data: existing } = await supabase
    .from('profiles')
    .select('id')
    .eq('username', username)
    .single();

  if (existing) {
    return res.status(409).json({ error: 'Username ya en uso' });
  }

  const { data: authData, error: authError } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  if (authError) {
    if (authError.message.includes('already registered')) {
      return res.status(409).json({ error: 'Email ya registrado' });
    }
    return res.status(400).json({ error: authError.message });
  }

  const { error: profileError } = await supabase
    .from('profiles')
    .insert({ id: authData.user.id, username });

  if (profileError) {
    await supabase.auth.admin.deleteUser(authData.user.id);
    return res.status(500).json({ error: 'Error creando perfil' });
  }

  const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (loginError) {
    return res.status(500).json({ error: 'Cuenta creada pero error al iniciar sesión' });
  }

  res.status(201).json({
    token: loginData.session.access_token,
    user: { id: authData.user.id, email, username },
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña requeridos' });
  }

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('username')
    .eq('id', data.user.id)
    .single();

  res.json({
    token: data.session.access_token,
    user: {
      id: data.user.id,
      email: data.user.email,
      username: profile?.username ?? 'Usuario',
    },
  });
});

// ══════════════════════════════════════════════════════════════
// VIDEOS
// ══════════════════════════════════════════════════════════════

app.get('/api/videos', requireAuth, async (req, res) => {
  const userId = req.userId;

  const { data: videos, error } = await supabase
    .from('videos')
    .select('id, cloudinary_url, title, created_at, profiles(username)')
    .order('created_at', { ascending: false });

  if (error) {
    return res.status(500).json({ error: 'Error obteniendo videos' });
  }

  const enriched = await Promise.all(
    videos.map(async (v) => {
      const [likesResult, userLikedResult] = await Promise.all([
        supabase
          .from('likes')
          .select('id', { count: 'exact', head: true })
          .eq('video_id', v.id),
        supabase
          .from('likes')
          .select('id')
          .eq('video_id', v.id)
          .eq('user_id', userId)
          .maybeSingle(),
      ]);
      return {
        id: v.id,
        url: v.cloudinary_url,
        title: v.title,
        uploader: v.profiles?.username ?? 'Desconocido',
        likes_count: likesResult.count ?? 0,
        user_liked: !!userLikedResult.data,
        created_at: v.created_at,
      };
    })
  );

  res.json({ videos: enriched });
});

app.post('/api/videos', requireAuth, async (req, res) => {
  const { cloudinary_url, cloudinary_public_id, title } = req.body;
  const userId = req.userId;

  if (!cloudinary_url) {
    return res.status(400).json({ error: 'cloudinary_url es requerida' });
  }

  if (!cloudinary_url.startsWith(`https://res.cloudinary.com/${process.env.CLOUDINARY_CLOUD_NAME}/`)) {
    return res.status(400).json({ error: 'URL de Cloudinary inválida' });
  }

  const { data, error } = await supabase
    .from('videos')
    .insert({
      cloudinary_url,
      cloudinary_public_id: cloudinary_public_id ?? null,
      title: title ?? 'Sin título',
      uploaded_by: userId,
    })
    .select('id, cloudinary_url, title, created_at')
    .single();

  if (error) {
    return res.status(500).json({ error: 'Error guardando video' });
  }

  res.status(201).json({ video: { ...data, likes_count: 0, user_liked: false } });
});

// ══════════════════════════════════════════════════════════════
// LIKES
// ══════════════════════════════════════════════════════════════

app.post('/api/likes/toggle', requireAuth, async (req, res) => {
  const { video_id } = req.body;
  const userId = req.userId;

  if (!video_id) {
    return res.status(400).json({ error: 'video_id requerido' });
  }

  const { data: existing } = await supabase
    .from('likes')
    .select('id')
    .eq('user_id', userId)
    .eq('video_id', video_id)
    .maybeSingle();

  let liked;
  if (existing) {
    await supabase.from('likes').delete().eq('id', existing.id);
    liked = false;
  } else {
    await supabase.from('likes').insert({ user_id: userId, video_id });
    liked = true;
  }

  const { count } = await supabase
    .from('likes')
    .select('id', { count: 'exact', head: true })
    .eq('video_id', video_id);

  res.json({ liked, likes_count: count ?? 0 });
});

// ══════════════════════════════════════════════════════════════
// COMENTARIOS
// ══════════════════════════════════════════════════════════════

app.get('/api/comments/:videoId', requireAuth, async (req, res) => {
  const { videoId } = req.params;

  const { data, error } = await supabase
    .from('comments')
    .select('id, text, created_at, profiles(username)')
    .eq('video_id', videoId)
    .order('created_at', { ascending: true });

  if (error) {
    return res.status(500).json({ error: 'Error obteniendo comentarios' });
  }

  const comments = data.map((c) => ({
    id: c.id,
    text: c.text,
    username: c.profiles?.username ?? 'Usuario',
    created_at: c.created_at,
  }));

  res.json({ comments });
});

app.post('/api/comments', requireAuth, async (req, res) => {
  const { video_id, text } = req.body;
  const userId = req.userId;

  if (!video_id || !text) {
    return res.status(400).json({ error: 'video_id y text son requeridos' });
  }
  if (text.trim().length === 0) {
    return res.status(400).json({ error: 'El comentario no puede estar vacío' });
  }
  if (text.length > 500) {
    return res.status(400).json({ error: 'Comentario máximo 500 caracteres' });
  }

  const { data, error } = await supabase
    .from('comments')
    .insert({ user_id: userId, video_id, text: text.trim() })
    .select('id, text, created_at')
    .single();

  if (error) {
    return res.status(500).json({ error: 'Error guardando comentario' });
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('username')
    .eq('id', userId)
    .single();

  res.status(201).json({
    comment: {
      id: data.id,
      text: data.text,
      username: profile?.username ?? 'Usuario',
      created_at: data.created_at,
    },
  });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
