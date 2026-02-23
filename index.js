require('dotenv').config();
const express = require('express');
const { randomUUID } = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
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

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token requerido' });
  const token = header.split(' ')[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user)
    return res.status(401).json({ error: 'Token inválido o expirado' });
  req.userId = user.id;
  next();
}

app.get('/', (req, res) => res.json({ status: 'ok', service: 'red-social-server' }));

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, username, birth_date, avatar_url } = req.body;
  if (!email || !password || !username || !birth_date)
    return res.status(400).json({ error: 'Email, contraseña, username y fecha de nacimiento son requeridos' });
  if (username.length < 3 || username.length > 30)
    return res.status(400).json({ error: 'Username debe tener entre 3 y 30 caracteres' });
  if (!/^[a-zA-Z0-9_.]+$/.test(username))
    return res.status(400).json({ error: 'Username solo puede tener letras, números, _ y .' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });

  const dob = new Date(birth_date);
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  if (age < 13)
    return res.status(400).json({ error: 'Debes tener al menos 13 años para registrarte' });

  const { data: existingUsername } = await supabase
    .from('profiles').select('id').eq('username', username).single();
  if (existingUsername)
    return res.status(409).json({ error: 'Ese username ya está en uso' });

  const { data: authData, error: authError } = await supabase.auth.admin.createUser({
    email, password, email_confirm: true,
  });
  if (authError) {
    if (authError.message.includes('already registered'))
      return res.status(409).json({ error: 'Email ya registrado' });
    return res.status(400).json({ error: authError.message });
  }

  const { error: profileError } = await supabase.from('profiles').insert({
    id: authData.user.id, username, birth_date, avatar_url: avatar_url ?? null,
  });
  if (profileError) {
    console.error('Profile insert error:', profileError);
    await supabase.auth.admin.deleteUser(authData.user.id);
    return res.status(500).json({ error: `Error creando perfil: ${profileError.message}` });
  }

  const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({ email, password });
  if (loginError)
    return res.status(500).json({ error: 'Cuenta creada pero error al iniciar sesión' });

  res.status(201).json({
    token: loginData.session.access_token,
    user: { id: authData.user.id, email, username, birth_date, avatar_url: avatar_url ?? null },
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error)
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  const { data: profile } = await supabase
    .from('profiles').select('username, birth_date, avatar_url').eq('id', data.user.id).single();
  res.json({
    token: data.session.access_token,
    user: {
      id: data.user.id, email: data.user.email,
      username: profile?.username ?? data.user.email.split('@')[0],
      birth_date: profile?.birth_date ?? null,
      avatar_url: profile?.avatar_url ?? null,
    },
  });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { data: profile, error } = await supabase
    .from('profiles').select('username, birth_date, avatar_url, created_at').eq('id', req.userId).single();
  if (error || !profile) return res.status(404).json({ error: 'Perfil no encontrado' });
  res.json({ profile });
});

app.patch('/api/auth/me', requireAuth, async (req, res) => {
  const { username, avatar_url } = req.body;
  const updates = {};
  if (username) {
    if (username.length < 3 || username.length > 30)
      return res.status(400).json({ error: 'Username inválido' });
    if (!/^[a-zA-Z0-9_.]+$/.test(username))
      return res.status(400).json({ error: 'Username con caracteres inválidos' });
    const { data: existing } = await supabase.from('profiles').select('id')
      .eq('username', username).neq('id', req.userId).single();
    if (existing) return res.status(409).json({ error: 'Username ya en uso' });
    updates.username = username;
  }
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  if (Object.keys(updates).length === 0)
    return res.status(400).json({ error: 'Nada que actualizar' });
  const { data, error } = await supabase.from('profiles').update(updates)
    .eq('id', req.userId).select('username, birth_date, avatar_url').single();
  if (error) return res.status(500).json({ error: `Error actualizando perfil: ${error.message}` });
  res.json({ profile: data });
});

// ══════════════════════════════════════════════════════════════
// VIDEOS
// ══════════════════════════════════════════════════════════════

app.get('/api/videos', requireAuth, async (req, res) => {
  const userId = req.userId;
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const offset = parseInt(req.query.offset) || 0;

  const { data: videos, error } = await supabase
    .from('videos')
    .select('id, cloudinary_url, title, created_at, profiles(username, avatar_url)')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);
  if (error) return res.status(500).json({ error: `Error obteniendo videos: ${error.message}` });

  const enriched = await Promise.all(videos.map(async (v) => {
    const [likesResult, userLikedResult, savedResult] = await Promise.all([
      supabase.from('likes').select('id', { count: 'exact', head: true }).eq('video_id', v.id),
      supabase.from('likes').select('id').eq('video_id', v.id).eq('user_id', userId).maybeSingle(),
      supabase.from('saved_videos').select('id').eq('video_id', v.id).eq('user_id', userId).maybeSingle(),
    ]);
    return {
      id: v.id, url: v.cloudinary_url, title: v.title,
      uploader: v.profiles?.username ?? 'Desconocido',
      uploader_avatar: v.profiles?.avatar_url ?? null,
      likes_count: likesResult.count ?? 0,
      user_liked: !!userLikedResult.data,
      user_saved: !!savedResult.data,
      created_at: v.created_at,
    };
  }));
  res.json({ videos: enriched });
});

app.post('/api/videos', requireAuth, async (req, res) => {
  const { cloudinary_url, cloudinary_public_id, title } = req.body;
  const userId = req.userId;
  if (!cloudinary_url) return res.status(400).json({ error: 'cloudinary_url es requerida' });
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  if (!cloudinary_url.startsWith(`https://res.cloudinary.com/${cloudName}/`))
    return res.status(400).json({ error: 'URL de Cloudinary inválida' });
  // Generar UUID como string (la tabla videos tiene id TEXT PRIMARY KEY)
  const videoId = randomUUID();
  const { data, error } = await supabase.from('videos').insert({
    id: videoId, cloudinary_url, cloudinary_public_id: cloudinary_public_id ?? null,
    title: title ?? 'Sin título', uploaded_by: userId,
  }).select('id, cloudinary_url, title, created_at').single();
  if (error) return res.status(500).json({ error: `Error guardando video: ${error.message}` });
  res.status(201).json({ video: { ...data, likes_count: 0, user_liked: false, user_saved: false } });
});

// ══════════════════════════════════════════════════════════════
// LIKES DE VIDEOS
// ══════════════════════════════════════════════════════════════

app.post('/api/likes/toggle', requireAuth, async (req, res) => {
  const { video_id } = req.body;
  const userId = req.userId;
  if (!video_id) return res.status(400).json({ error: 'video_id requerido' });
  const { data: existing } = await supabase.from('likes').select('id')
    .eq('user_id', userId).eq('video_id', video_id).maybeSingle();
  let liked;
  if (existing) {
    await supabase.from('likes').delete().eq('id', existing.id);
    liked = false;
  } else {
    await supabase.from('likes').insert({ user_id: userId, video_id });
    liked = true;
  }
  const { count } = await supabase.from('likes').select('id', { count: 'exact', head: true }).eq('video_id', video_id);
  res.json({ liked, likes_count: count ?? 0 });
});

// ══════════════════════════════════════════════════════════════
// GUARDADOS
// ══════════════════════════════════════════════════════════════

app.post('/api/saved/toggle', requireAuth, async (req, res) => {
  const { video_id } = req.body;
  const userId = req.userId;
  if (!video_id) return res.status(400).json({ error: 'video_id requerido' });
  const { data: existing } = await supabase.from('saved_videos').select('id')
    .eq('user_id', userId).eq('video_id', video_id).maybeSingle();
  let saved;
  if (existing) {
    await supabase.from('saved_videos').delete().eq('id', existing.id);
    saved = false;
  } else {
    await supabase.from('saved_videos').insert({ user_id: userId, video_id });
    saved = true;
  }
  res.json({ saved });
});

// ══════════════════════════════════════════════════════════════
// COMENTARIOS
// ══════════════════════════════════════════════════════════════

// Obtener comentarios principales + sus respuestas, con likes y ocultos
app.get('/api/comments/:videoId', requireAuth, async (req, res) => {
  const { videoId } = req.params;
  const userId = req.userId;

  // Comentarios principales (sin parent)
  const { data: comments, error } = await supabase.from('comments')
    .select('id, text, created_at, user_id, profiles(username, avatar_url)')
    .eq('video_id', videoId)
    .is('parent_id', null)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: `Error obteniendo comentarios: ${error.message}` });

  // Ocultos por este usuario
  const { data: hidden } = await supabase.from('hidden_comments')
    .select('comment_id').eq('user_id', userId);
  const hiddenSet = new Set((hidden ?? []).map(h => h.comment_id));

  // Enriquecer con likes y respuestas
  const enriched = await Promise.all(comments.map(async (c) => {
    const [likesRes, userLikedRes, repliesRes] = await Promise.all([
      supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', c.id),
      supabase.from('comment_likes').select('id').eq('comment_id', c.id).eq('user_id', userId).maybeSingle(),
      supabase.from('comments')
        .select('id, text, created_at, user_id, profiles(username, avatar_url)')
        .eq('parent_id', c.id)
        .order('created_at', { ascending: true }),
    ]);

    const replies = await Promise.all((repliesRes.data ?? []).map(async (r) => {
      const [rLikesRes, rUserLikedRes] = await Promise.all([
        supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', r.id),
        supabase.from('comment_likes').select('id').eq('comment_id', r.id).eq('user_id', userId).maybeSingle(),
      ]);
      return {
        id: r.id, text: r.text, created_at: r.created_at,
        user_id: r.user_id,
        username: r.profiles?.username ?? 'Usuario',
        avatar_url: r.profiles?.avatar_url ?? null,
        likes_count: rLikesRes.count ?? 0,
        user_liked: !!rUserLikedRes.data,
        hidden: hiddenSet.has(r.id),
        is_mine: r.user_id === userId,
      };
    }));

    return {
      id: c.id, text: c.text, created_at: c.created_at,
      user_id: c.user_id,
      username: c.profiles?.username ?? 'Usuario',
      avatar_url: c.profiles?.avatar_url ?? null,
      likes_count: likesRes.count ?? 0,
      user_liked: !!userLikedRes.data,
      hidden: hiddenSet.has(c.id),
      is_mine: c.user_id === userId,
      replies,
    };
  }));

  res.json({ comments: enriched });
});

// Nuevo comentario principal
app.post('/api/comments', requireAuth, async (req, res) => {
  const { video_id, text } = req.body;
  const userId = req.userId;
  if (!video_id || !text) return res.status(400).json({ error: 'video_id y text requeridos' });
  if (text.trim().length === 0) return res.status(400).json({ error: 'Comentario vacío' });
  if (text.length > 500) return res.status(400).json({ error: 'Máximo 500 caracteres' });
  const { data, error } = await supabase.from('comments')
    .insert({ user_id: userId, video_id, text: text.trim() })
    .select('id, text, created_at, user_id').single();
  if (error) return res.status(500).json({ error: `Error guardando comentario: ${error.message}` });
  const { data: profile } = await supabase.from('profiles').select('username, avatar_url').eq('id', userId).single();
  res.status(201).json({
    comment: {
      id: data.id, text: data.text, created_at: data.created_at,
      user_id: data.user_id,
      username: profile?.username ?? 'Usuario',
      avatar_url: profile?.avatar_url ?? null,
      likes_count: 0, user_liked: false, hidden: false, is_mine: true, replies: [],
    },
  });
});

// Responder a un comentario
app.post('/api/comments/:parentId/reply', requireAuth, async (req, res) => {
  const { parentId } = req.params;
  const { text, video_id } = req.body;
  const userId = req.userId;
  if (!text || !video_id) return res.status(400).json({ error: 'text y video_id requeridos' });
  if (text.trim().length === 0) return res.status(400).json({ error: 'Respuesta vacía' });
  if (text.length > 500) return res.status(400).json({ error: 'Máximo 500 caracteres' });
  const { data, error } = await supabase.from('comments')
    .insert({ user_id: userId, video_id, text: text.trim(), parent_id: parentId })
    .select('id, text, created_at, user_id').single();
  if (error) return res.status(500).json({ error: `Error guardando respuesta: ${error.message}` });
  const { data: profile } = await supabase.from('profiles').select('username, avatar_url').eq('id', userId).single();
  res.status(201).json({
    reply: {
      id: data.id, text: data.text, created_at: data.created_at,
      user_id: data.user_id,
      username: profile?.username ?? 'Usuario',
      avatar_url: profile?.avatar_url ?? null,
      likes_count: 0, user_liked: false, hidden: false, is_mine: true,
    },
  });
});

// Eliminar comentario propio
app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId;
  const { data: comment } = await supabase.from('comments').select('user_id').eq('id', id).single();
  if (!comment) return res.status(404).json({ error: 'Comentario no encontrado' });
  if (comment.user_id !== userId) return res.status(403).json({ error: 'No puedes eliminar este comentario' });
  await supabase.from('comments').delete().eq('id', id);
  res.json({ deleted: true });
});

// Ocultar comentario para mí
app.post('/api/comments/:id/hide', requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId;
  const { data: existing } = await supabase.from('hidden_comments').select('id')
    .eq('user_id', userId).eq('comment_id', id).maybeSingle();
  if (existing) {
    await supabase.from('hidden_comments').delete().eq('id', existing.id);
    res.json({ hidden: false });
  } else {
    await supabase.from('hidden_comments').insert({ user_id: userId, comment_id: id });
    res.json({ hidden: true });
  }
});

// Denunciar comentario (por ahora solo log, sin tabla dedicada)
app.post('/api/comments/:id/report', requireAuth, async (req, res) => {
  const { id } = req.params;
  console.log(`Comentario denunciado: ${id} por usuario: ${req.userId}`);
  res.json({ reported: true });
});

// ══════════════════════════════════════════════════════════════
// LIKES DE COMENTARIOS
// ══════════════════════════════════════════════════════════════

app.post('/api/comment-likes/toggle', requireAuth, async (req, res) => {
  const { comment_id } = req.body;
  const userId = req.userId;
  if (!comment_id) return res.status(400).json({ error: 'comment_id requerido' });
  const { data: existing } = await supabase.from('comment_likes').select('id')
    .eq('user_id', userId).eq('comment_id', comment_id).maybeSingle();
  let liked;
  if (existing) {
    await supabase.from('comment_likes').delete().eq('id', existing.id);
    liked = false;
  } else {
    await supabase.from('comment_likes').insert({ user_id: userId, comment_id });
    liked = true;
  }
  const { count } = await supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', comment_id);
  res.json({ liked, likes_count: count ?? 0 });
});

app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
