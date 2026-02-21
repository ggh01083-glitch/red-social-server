require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1); // requerido para que rate limiter funcione en Render
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true, legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 200,
  message: { error: 'Demasiadas peticiones.' },
  standardHeaders: true, legacyHeaders: false,
});

app.use('/api', generalLimiter);

// ── Middleware auth ───────────────────────────────────────────

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
  const { email, password, username, birth_date, avatar_url } = req.body;

  if (!email || !password || !username || !birth_date) {
    return res.status(400).json({
      error: 'Email, contraseña, username y fecha de nacimiento son requeridos',
    });
  }
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username debe tener entre 3 y 30 caracteres' });
  }
  if (!/^[a-zA-Z0-9_.]+$/.test(username)) {
    return res.status(400).json({ error: 'Username solo puede tener letras, números, _ y .' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });
  }

  // Validar edad mínima 13 años
  const dob = new Date(birth_date);
  const today = new Date();
  const age = today.getFullYear() - dob.getFullYear();
  const monthDiff = today.getMonth() - dob.getMonth();
  const realAge = monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())
    ? age - 1 : age;

  if (realAge < 13) {
    return res.status(400).json({ error: 'Debes tener al menos 13 años para registrarte' });
  }

  // Username único
  const { data: existingUsername } = await supabase
    .from('profiles')
    .select('id')
    .eq('username', username)
    .single();

  if (existingUsername) {
    return res.status(409).json({ error: 'Ese username ya está en uso' });
  }

  // Crear usuario en Supabase Auth
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

  // Crear perfil con birth_date y avatar_url
  const { error: profileError } = await supabase.from('profiles').insert({
    id: authData.user.id,
    username,
    birth_date,
    avatar_url: avatar_url ?? null,
  });

  if (profileError) {
    console.error('Profile insert error:', profileError);
    await supabase.auth.admin.deleteUser(authData.user.id);
    return res.status(500).json({ error: `Error creando perfil: ${profileError.message}` });
  }

  // Login inmediato para devolver token
  const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
    email, password,
  });

  if (loginError) {
    return res.status(500).json({ error: 'Cuenta creada pero error al iniciar sesión' });
  }

  res.status(201).json({
    token: loginData.session.access_token,
    user: {
      id: authData.user.id,
      email,
      username,
      birth_date,
      avatar_url: avatar_url ?? null,
    },
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
    .select('username, birth_date, avatar_url')
    .eq('id', data.user.id)
    .single();

  res.json({
    token: data.session.access_token,
    user: {
      id: data.user.id,
      email: data.user.email,
      username: profile?.username ?? data.user.email.split('@')[0],
      birth_date: profile?.birth_date ?? null,
      avatar_url: profile?.avatar_url ?? null,
    },
  });
});

// GET perfil propio
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { data: profile, error } = await supabase
    .from('profiles')
    .select('username, birth_date, avatar_url, created_at')
    .eq('id', req.userId)
    .single();

  if (error || !profile) {
    return res.status(404).json({ error: 'Perfil no encontrado' });
  }

  res.json({ profile });
});

// PATCH actualizar perfil
app.patch('/api/auth/me', requireAuth, async (req, res) => {
  const { username, avatar_url } = req.body;
  const updates = {};

  if (username) {
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: 'Username inválido' });
    }
    if (!/^[a-zA-Z0-9_.]+$/.test(username)) {
      return res.status(400).json({ error: 'Username con caracteres inválidos' });
    }
    const { data: existing } = await supabase
      .from('profiles')
      .select('id')
      .eq('username', username)
      .neq('id', req.userId)
      .single();

    if (existing) {
      return res.status(409).json({ error: 'Username ya en uso' });
    }
    updates.username = username;
  }

  if (avatar_url !== undefined) updates.avatar_url = avatar_url;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'Nada que actualizar' });
  }

  const { data, error } = await supabase
    .from('profiles')
    .update(updates)
    .eq('id', req.userId)
    .select('username, birth_date, avatar_url')
    .single();

  if (error) {
    return res.status(500).json({ error: `Error actualizando perfil: ${error.message}` });
  }

  res.json({ profile: data });
});

// ══════════════════════════════════════════════════════════════
// VIDEOS — Feed estilo TikTok
// ══════════════════════════════════════════════════════════════

app.get('/api/videos', requireAuth, async (req, res) => {
  const userId = req.userId;
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const offset = parseInt(req.query.offset) || 0;

  const { data: videos, error } = await supabase
    .from('videos')
    .select('id, cloudinary_url, cloudinary_public_id, title, created_at, profiles(username, avatar_url)')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    console.error('Error obteniendo videos:', error);
    return res.status(500).json({ error: `Error obteniendo videos: ${error.message}` });
  }

  const enriched = await Promise.all(
    videos.map(async (v) => {
      const [likesResult, userLikedResult] = await Promise.all([
        supabase.from('likes').select('id', { count: 'exact', head: true }).eq('video_id', v.id),
        supabase.from('likes').select('id').eq('video_id', v.id).eq('user_id', userId).maybeSingle(),
      ]);
      return {
        id: v.id,
        url: v.cloudinary_url,
        title: v.title,
        uploader: v.profiles?.username ?? 'Desconocido',
        uploader_avatar: v.profiles?.avatar_url ?? null,
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

  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  if (!cloudinary_url.startsWith(`https://res.cloudinary.com/${cloudName}/`)) {
    return res.status(400).json({ error: 'URL de Cloudinary inválida' });
  }

  const videoId = cloudinary_public_id?.split('/').pop() ?? 
    `vid_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const { data, error } = await supabase
    .from('videos')
    .insert({
      id: videoId,
      cloudinary_url,
      cloudinary_public_id: cloudinary_public_id ?? null,
      title: title ?? 'Sin título',
      uploaded_by: userId,
    })
    .select('id, cloudinary_url, title, created_at')
    .single();

  if (error) {
    console.error('Error insertando video:', error);
    return res.status(500).json({ error: `Error guardando video: ${error.message}` });
  }

  res.status(201).json({ video: { ...data, likes_count: 0, user_liked: false } });
});

// ══════════════════════════════════════════════════════════════
// LIKES
// ══════════════════════════════════════════════════════════════

app.post('/api/likes/toggle', requireAuth, async (req, res) => {
  const { video_id } = req.body;
  const userId = req.userId;

  if (!video_id) return res.status(400).json({ error: 'video_id requerido' });

  const { data: existing } = await supabase
    .from('likes').select('id')
    .eq('user_id', userId).eq('video_id', video_id).maybeSingle();

  let liked;
  if (existing) {
    await supabase.from('likes').delete().eq('id', existing.id);
    liked = false;
  } else {
    await supabase.from('likes').insert({ user_id: userId, video_id });
    liked = true;
  }

  const { count } = await supabase
    .from('likes').select('id', { count: 'exact', head: true }).eq('video_id', video_id);

  res.json({ liked, likes_count: count ?? 0 });
});

// ══════════════════════════════════════════════════════════════
// COMENTARIOS
// ══════════════════════════════════════════════════════════════

app.get('/api/comments/:videoId', requireAuth, async (req, res) => {
  const { videoId } = req.params;

  const { data, error } = await supabase
    .from('comments')
    .select('id, text, created_at, profiles(username, avatar_url)')
    .eq('video_id', videoId)
    .order('created_at', { ascending: true });

  if (error) {
    return res.status(500).json({ error: `Error obteniendo comentarios: ${error.message}` });
  }

  res.json({
    comments: data.map((c) => ({
      id: c.id,
      text: c.text,
      username: c.profiles?.username ?? 'Usuario',
      avatar_url: c.profiles?.avatar_url ?? null,
      created_at: c.created_at,
    })),
  });
});

app.post('/api/comments', requireAuth, async (req, res) => {
  const { video_id, text } = req.body;
  const userId = req.userId;

  if (!video_id || !text) return res.status(400).json({ error: 'video_id y text requeridos' });
  if (text.trim().length === 0) return res.status(400).json({ error: 'Comentario vacío' });
  if (text.length > 500) return res.status(400).json({ error: 'Máximo 500 caracteres' });

  const { data, error } = await supabase
    .from('comments')
    .insert({ user_id: userId, video_id, text: text.trim() })
    .select('id, text, created_at')
    .single();

  if (error) {
    return res.status(500).json({ error: `Error guardando comentario: ${error.message}` });
  }

  const { data: profile } = await supabase
    .from('profiles').select('username, avatar_url').eq('id', userId).single();

  res.status(201).json({
    comment: {
      id: data.id,
      text: data.text,
      username: profile?.username ?? 'Usuario',
      avatar_url: profile?.avatar_url ?? null,
      created_at: data.created_at,
    },
  });
});

app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
