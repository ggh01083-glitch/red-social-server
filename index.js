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
  windowMs: 15 * 60 * 1000, max: 300,
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

// Helper: crear notificación solo si el destinatario es distinto al actor
async function createNotif(userId, fromUserId, type, referenceId) {
  if (!userId || userId === fromUserId) return;
  await supabase.from('notifications').insert({
    user_id: userId, from_user_id: fromUserId,
    type, reference_id: referenceId,
  });
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
// PROFILES (para perfil de extraños)
// ══════════════════════════════════════════════════════════════

app.get('/api/profiles/:username', requireAuth, async (req, res) => {
  const { username } = req.params;
  const userId = req.userId;

  const { data: profile, error } = await supabase
    .from('profiles').select('id, username, avatar_url, birth_date, created_at')
    .eq('username', username).single();
  if (error || !profile) return res.status(404).json({ error: 'Usuario no encontrado' });

  // Follow status: solo mira si existe la fila, ignora status column (puede tener valores viejos)
  const [{ data: iFollowRow }, { data: theyFollowRow }] = await Promise.all([
    supabase.from('friendships').select('id').eq('requester_id', userId).eq('addressee_id', profile.id).maybeSingle(),
    supabase.from('friendships').select('id').eq('requester_id', profile.id).eq('addressee_id', userId).maybeSingle(),
  ]);
  // none | following | follower | friends
  let friendStatus = 'none';
  if (iFollowRow && theyFollowRow) friendStatus = 'friends';
  else if (iFollowRow) friendStatus = 'following';
  else if (theyFollowRow) friendStatus = 'follower'; // me sigue pero yo no

  // Videos subidos (busca por uploaded_by O por el username en profiles join)
  const { data: videos } = await supabase.from('videos')
    .select('id, cloudinary_url, title, created_at, uploaded_by')
    .eq('uploaded_by', profile.id)
    .order('created_at', { ascending: false });

  res.json({
    profile: {
      id: profile.id, username: profile.username,
      avatar_url: profile.avatar_url, created_at: profile.created_at,
    },
    friend_status: friendStatus,
    videos: (videos ?? []).map(v => ({
      id: v.id, url: v.cloudinary_url, title: v.title, created_at: v.created_at,
    })),
  });
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
    .select('id, cloudinary_url, title, created_at, uploaded_by, profiles(username, avatar_url)')
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
      uploaded_by: v.uploaded_by,
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
  const videoId = randomUUID();
  const { data, error } = await supabase.from('videos').insert({
    id: videoId, cloudinary_url, cloudinary_public_id: cloudinary_public_id ?? null,
    title: title ?? 'Sin título', uploaded_by: userId,
  }).select('id, cloudinary_url, title, created_at').single();
  if (error) return res.status(500).json({ error: `Error guardando video: ${error.message}` });
  res.status(201).json({ video: { ...data, likes_count: 0, user_liked: false, user_saved: false } });
});

// GET /api/videos/:id → un video específico (para abrir desde notificaciones)
app.get('/api/videos/:videoId', requireAuth, async (req, res) => {
  const { videoId } = req.params;
  const userId = req.userId;

  const { data: v, error } = await supabase
    .from('videos')
    .select('id, cloudinary_url, title, created_at, uploaded_by, profiles(username, avatar_url)')
    .eq('id', videoId).single();
  if (error || !v) return res.status(404).json({ error: 'Video no encontrado' });

  const [likesRes, userLikedRes, savedRes] = await Promise.all([
    supabase.from('likes').select('id', { count: 'exact', head: true }).eq('video_id', videoId),
    supabase.from('likes').select('id').eq('video_id', videoId).eq('user_id', userId).maybeSingle(),
    supabase.from('saved_videos').select('id').eq('video_id', videoId).eq('user_id', userId).maybeSingle(),
  ]);

  res.json({ video: {
    id: v.id, url: v.cloudinary_url, title: v.title,
    uploaded_by: v.uploaded_by,
    uploader: v.profiles?.username ?? 'Desconocido',
    uploader_avatar: v.profiles?.avatar_url ?? null,
    likes_count: likesRes.count ?? 0,
    user_liked: !!userLikedRes.data,
    user_saved: !!savedRes.data,
    created_at: v.created_at,
  }});
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
    // Notificar al dueño del video
    const { data: video } = await supabase.from('videos').select('uploaded_by').eq('id', video_id).single();
    if (video?.uploaded_by) await createNotif(video.uploaded_by, userId, 'like_video', video_id);
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

app.get('/api/comments/:videoId', requireAuth, async (req, res) => {
  const { videoId } = req.params;
  const userId = req.userId;

  const { data: comments, error } = await supabase.from('comments')
    .select('id, text, created_at, user_id, profiles(username, avatar_url)')
    .eq('video_id', videoId).is('parent_id', null)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: `Error obteniendo comentarios: ${error.message}` });

  const { data: hidden } = await supabase.from('hidden_comments')
    .select('comment_id').eq('user_id', userId);
  const hiddenSet = new Set((hidden ?? []).map(h => h.comment_id));

  const enriched = await Promise.all(comments.map(async (c) => {
    const [likesRes, userLikedRes, repliesRes] = await Promise.all([
      supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', c.id),
      supabase.from('comment_likes').select('id').eq('comment_id', c.id).eq('user_id', userId).maybeSingle(),
      supabase.from('comments')
        .select('id, text, created_at, user_id, profiles(username, avatar_url)')
        .eq('parent_id', c.id).order('created_at', { ascending: true }),
    ]);

    const replies = await Promise.all((repliesRes.data ?? []).map(async (r) => {
      const [rLikesRes, rUserLikedRes] = await Promise.all([
        supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', r.id),
        supabase.from('comment_likes').select('id').eq('comment_id', r.id).eq('user_id', userId).maybeSingle(),
      ]);
      return {
        id: r.id, text: r.text, created_at: r.created_at, user_id: r.user_id,
        username: r.profiles?.username ?? 'Usuario', avatar_url: r.profiles?.avatar_url ?? null,
        likes_count: rLikesRes.count ?? 0, user_liked: !!rUserLikedRes.data,
        hidden: hiddenSet.has(r.id), is_mine: r.user_id === userId,
      };
    }));

    return {
      id: c.id, text: c.text, created_at: c.created_at, user_id: c.user_id,
      username: c.profiles?.username ?? 'Usuario', avatar_url: c.profiles?.avatar_url ?? null,
      likes_count: likesRes.count ?? 0, user_liked: !!userLikedRes.data,
      hidden: hiddenSet.has(c.id), is_mine: c.user_id === userId, replies,
    };
  }));

  res.json({ comments: enriched });
});

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
  // Notificar dueño del video
  const { data: video } = await supabase.from('videos').select('uploaded_by').eq('id', video_id).single();
  if (video?.uploaded_by) await createNotif(video.uploaded_by, userId, 'comment_video', data.id);
  res.status(201).json({
    comment: {
      id: data.id, text: data.text, created_at: data.created_at, user_id: data.user_id,
      username: profile?.username ?? 'Usuario', avatar_url: profile?.avatar_url ?? null,
      likes_count: 0, user_liked: false, hidden: false, is_mine: true, replies: [],
    },
  });
});

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
  // Notificar al dueño del comentario padre
  const { data: parent } = await supabase.from('comments').select('user_id').eq('id', parentId).single();
  if (parent?.user_id) await createNotif(parent.user_id, userId, 'reply_comment', data.id);
  res.status(201).json({
    reply: {
      id: data.id, text: data.text, created_at: data.created_at, user_id: data.user_id,
      username: profile?.username ?? 'Usuario', avatar_url: profile?.avatar_url ?? null,
      likes_count: 0, user_liked: false, hidden: false, is_mine: true,
    },
  });
});

app.delete('/api/comments/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId;
  const { data: comment } = await supabase.from('comments').select('user_id').eq('id', id).single();
  if (!comment) return res.status(404).json({ error: 'Comentario no encontrado' });
  if (comment.user_id !== userId) return res.status(403).json({ error: 'No puedes eliminar este comentario' });
  await supabase.from('comments').delete().eq('id', id);
  res.json({ deleted: true });
});

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

app.post('/api/comments/:id/report', requireAuth, async (req, res) => {
  console.log(`Comentario denunciado: ${req.params.id} por: ${req.userId}`);
  res.json({ reported: true });
});

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
    // Notificar al dueño del comentario
    const { data: comment } = await supabase.from('comments').select('user_id').eq('id', comment_id).single();
    if (comment?.user_id) await createNotif(comment.user_id, userId, 'like_comment', comment_id);
  }
  const { count } = await supabase.from('comment_likes').select('id', { count: 'exact', head: true }).eq('comment_id', comment_id);
  res.json({ liked, likes_count: count ?? 0 });
});

// ══════════════════════════════════════════════════════════════
// NOTIFICACIONES
// ══════════════════════════════════════════════════════════════

app.get('/api/notifications', requireAuth, async (req, res) => {
  const userId = req.userId;

  // Query simple sin joins complejos
  const { data: notifs, error } = await supabase
    .from('notifications')
    .select('id, type, reference_id, read, created_at, from_user_id')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) {
    console.error('Notifications query error:', error.message);
    return res.status(500).json({ error: error.message });
  }

  const { count: unread } = await supabase
    .from('notifications').select('id', { count: 'exact', head: true })
    .eq('user_id', userId).eq('read', false);

  if (!notifs || notifs.length === 0) {
    return res.json({ notifications: [], unread_count: unread ?? 0 });
  }

  // Obtener perfiles de los "from_user_id" en una sola query
  const fromUserIds = [...new Set(notifs.map(n => n.from_user_id).filter(Boolean))];
  const { data: fromProfiles } = await supabase
    .from('profiles').select('id, username, avatar_url').in('id', fromUserIds);
  const profileMap = {};
  for (const p of fromProfiles ?? []) profileMap[p.id] = p;

  // Enriquecer con contexto de navegación (queries separadas, sin joins encadenados)
  const enriched = await Promise.all(notifs.map(async (n) => {
    const fromP = profileMap[n.from_user_id] ?? {};
    const base = {
      id: n.id, type: n.type, reference_id: n.reference_id,
      read: n.read, created_at: n.created_at,
      from_username: fromP.username ?? 'Usuario',
      from_avatar: fromP.avatar_url ?? null,
      video_id: null, video_title: null,
      comment_id: null, comment_text: null,
      chat_user_id: null, chat_username: null, chat_avatar: null,
      uploader_username: null,
    };

    try {
      if (n.type === 'like_video') {
        // reference_id = video_id
        const { data: v } = await supabase.from('videos')
          .select('id, title, uploaded_by').eq('id', n.reference_id).maybeSingle();
        if (v) {
          base.video_id = v.id;
          base.video_title = v.title;
          if (v.uploaded_by) {
            const { data: up } = await supabase.from('profiles')
              .select('username').eq('id', v.uploaded_by).maybeSingle();
            base.uploader_username = up?.username ?? null;
          }
        }

      } else if (n.type === 'comment_video' || n.type === 'like_comment') {
        // reference_id = comment_id
        const { data: c } = await supabase.from('comments')
          .select('id, text, video_id').eq('id', n.reference_id).maybeSingle();
        if (c) {
          base.comment_id = c.id;
          base.comment_text = (c.text ?? '').substring(0, 80);
          base.video_id = c.video_id;
          if (c.video_id) {
            const { data: v } = await supabase.from('videos')
              .select('title, uploaded_by').eq('id', c.video_id).maybeSingle();
            if (v) {
              base.video_title = v.title;
              if (v.uploaded_by) {
                const { data: up } = await supabase.from('profiles')
                  .select('username').eq('id', v.uploaded_by).maybeSingle();
                base.uploader_username = up?.username ?? null;
              }
            }
          }
        }

      } else if (n.type === 'reply_comment') {
        // reference_id = reply comment_id
        const { data: r } = await supabase.from('comments')
          .select('id, text, video_id, parent_id').eq('id', n.reference_id).maybeSingle();
        if (r) {
          base.comment_id = r.parent_id ?? r.id;
          base.comment_text = (r.text ?? '').substring(0, 80);
          base.video_id = r.video_id;
          if (r.video_id) {
            const { data: v } = await supabase.from('videos')
              .select('title, uploaded_by').eq('id', r.video_id).maybeSingle();
            if (v) {
              base.video_title = v.title;
              if (v.uploaded_by) {
                const { data: up } = await supabase.from('profiles')
                  .select('username').eq('id', v.uploaded_by).maybeSingle();
                base.uploader_username = up?.username ?? null;
              }
            }
          }
        }

      } else if (n.type === 'new_message') {
        // reference_id = message_id
        const { data: msg } = await supabase.from('messages')
          .select('id, sender_id').eq('id', n.reference_id).maybeSingle();
        if (msg?.sender_id) {
          const { data: sp } = await supabase.from('profiles')
            .select('username, avatar_url').eq('id', msg.sender_id).maybeSingle();
          base.chat_user_id = msg.sender_id;
          base.chat_username = sp?.username ?? null;
          base.chat_avatar = sp?.avatar_url ?? null;
        }
      }
      // followed_you: no necesita contexto extra
    } catch (enrichErr) {
      console.error('Enrich error for notif', n.id, ':', enrichErr.message);
    }

    return base;
  }));

  res.json({ notifications: enriched, unread_count: unread ?? 0 });
});

app.post('/api/notifications/read', requireAuth, async (req, res) => {
  await supabase.from('notifications').update({ read: true })
    .eq('user_id', req.userId).eq('read', false);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
// AMIGOS / SEGUIR
// ══════════════════════════════════════════════════════════════

// GET /api/friends → mutuos + gente con historial de mensajes (aunque ya no se sigan)
app.get('/api/friends', requireAuth, async (req, res) => {
  const userId = req.userId;

  // Follows en ambas direcciones
  const [{ data: followingRows }, { data: followerRows }] = await Promise.all([
    supabase.from('friendships').select('addressee_id').eq('requester_id', userId),
    supabase.from('friendships').select('requester_id').eq('addressee_id', userId),
  ]);

  const followingSet = new Set((followingRows ?? []).map(r => r.addressee_id));
  const followerSet  = new Set((followerRows  ?? []).map(r => r.requester_id));

  // Mutuos
  const mutualIds = [...followingSet].filter(id => followerSet.has(id));

  // Personas con las que hay historial de mensajes (aunque ya no se sigan)
  const [{ data: sentMsgs }, { data: recvMsgs }] = await Promise.all([
    supabase.from('messages').select('receiver_id').eq('sender_id', userId),
    supabase.from('messages').select('sender_id').eq('receiver_id', userId),
  ]);
  const chatPartners = new Set([
    ...(sentMsgs ?? []).map(m => m.receiver_id),
    ...(recvMsgs ?? []).map(m => m.sender_id),
  ]);

  // Unión: mutuos + historial (sin duplicados, sin el propio userId)
  const allIds = [...new Set([...mutualIds, ...chatPartners])].filter(id => id !== userId);

  if (allIds.length === 0) return res.json({ friends: [] });

  // Obtener perfiles
  const { data: profiles } = await supabase.from('profiles')
    .select('id, username, avatar_url').in('id', allIds);

  // Mensajes no leídos
  const { data: unreadMsgs } = await supabase.from('messages')
    .select('sender_id').eq('receiver_id', userId).eq('read', false);
  const unreadByUser = {};
  for (const m of unreadMsgs ?? []) {
    unreadByUser[m.sender_id] = (unreadByUser[m.sender_id] ?? 0) + 1;
  }

  const friends = (profiles ?? []).map(p => {
    const iFollow   = followingSet.has(p.id);
    const theyFollow = followerSet.has(p.id);
    let followStatus = 'none';
    if (iFollow && theyFollow) followStatus = 'friends';
    else if (iFollow)          followStatus = 'following';
    else if (theyFollow)       followStatus = 'follower';
    return {
      id: p.id, username: p.username, avatar_url: p.avatar_url,
      follow_status: followStatus,
      unread_messages: unreadByUser[p.id] ?? 0,
    };
  });

  res.json({ friends });
});

// POST /api/follow → seguir a alguien
app.post('/api/follow', requireAuth, async (req, res) => {
  const { username } = req.body;
  const userId = req.userId;
  if (!username) return res.status(400).json({ error: 'username requerido' });

  const { data: target, error: targetErr } = await supabase.from('profiles')
    .select('id').eq('username', username).single();
  if (targetErr || !target) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (target.id === userId) return res.status(400).json({ error: 'No puedes seguirte a ti mismo' });

  // Ver si ya existe la fila
  const { data: existing } = await supabase.from('friendships').select('id')
    .eq('requester_id', userId).eq('addressee_id', target.id).maybeSingle();

  if (!existing) {
    // Intentar insert. Si la tabla tiene columna status con default, no la mandamos.
    // Si falla por constraint, intentamos con status explícito como fallback.
    let insertError = null;
    const attempt1 = await supabase.from('friendships')
      .insert({ requester_id: userId, addressee_id: target.id });
    if (attempt1.error) {
      console.error('Follow insert attempt 1:', attempt1.error.message);
      const attempt2 = await supabase.from('friendships')
        .insert({ requester_id: userId, addressee_id: target.id, status: 'accepted' });
      if (attempt2.error) {
        console.error('Follow insert attempt 2:', attempt2.error.message);
        return res.status(500).json({ error: 'Error al seguir: ' + attempt2.error.message });
      }
    }
    await createNotif(target.id, userId, 'followed_you', userId);
  }

  // Verificar resultado real en DB
  const [{ data: myRow }, { data: theirRow }] = await Promise.all([
    supabase.from('friendships').select('id').eq('requester_id', userId).eq('addressee_id', target.id).maybeSingle(),
    supabase.from('friendships').select('id').eq('requester_id', target.id).eq('addressee_id', userId).maybeSingle(),
  ]);

  console.log(`Follow: ${userId} -> ${target.id} | myRow: ${!!myRow} | theirRow: ${!!theirRow}`);

  if (!myRow) return res.status(500).json({ error: 'Follow no se guardó en DB' });

  res.json({ ok: true, status: (myRow && theirRow) ? 'friends' : 'following' });
});

// DELETE /api/follow/:targetId → dejar de seguir
app.delete('/api/follow/:targetId', requireAuth, async (req, res) => {
  const { targetId } = req.params;
  const userId = req.userId;
  const { error } = await supabase.from('friendships')
    .delete().eq('requester_id', userId).eq('addressee_id', targetId);
  if (error) {
    console.error('Unfollow error:', error.message);
    return res.status(500).json({ error: 'Error al dejar de seguir: ' + error.message });
  }
  // Verificar que realmente se borró
  const { data: stillExists } = await supabase.from('friendships').select('id')
    .eq('requester_id', userId).eq('addressee_id', targetId).maybeSingle();
  if (stillExists) {
    console.error('Unfollow: row still exists after delete!');
  }
  console.log(`Unfollow: ${userId} -> ${targetId} | stillExists: ${!!stillExists}`);
  res.json({ ok: true, status: 'none' });
});

// ══════════════════════════════════════════════════════════════
// MENSAJES
// ══════════════════════════════════════════════════════════════

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  const { userId: otherId } = req.params;
  const myId = req.userId;

  // Obtener follow status en ambas direcciones
  const [{ data: iFollowRow }, { data: theyFollowRow }] = await Promise.all([
    supabase.from('friendships').select('id').eq('requester_id', myId).eq('addressee_id', otherId).maybeSingle(),
    supabase.from('friendships').select('id').eq('requester_id', otherId).eq('addressee_id', myId).maybeSingle(),
  ]);
  const iFollow    = !!iFollowRow;
  const theyFollow = !!theyFollowRow;
  const canSend    = iFollow && theyFollow;

  // Obtener historial (aunque no puedan enviar, pueden ver el historial)
  const { data: messages, error } = await supabase.from('messages')
    .select('id, sender_id, receiver_id, text, read, created_at')
    .in('sender_id', [myId, otherId])
    .in('receiver_id', [myId, otherId])
    .order('created_at', { ascending: true })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });

  // Solo marcar como leídos si pueden chatear
  if (canSend) {
    await supabase.from('messages').update({ read: true })
      .eq('sender_id', otherId).eq('receiver_id', myId).eq('read', false);
  }

  res.json({ messages: messages ?? [], can_send: canSend, i_follow: iFollow, they_follow: theyFollow });
});

app.post('/api/messages', requireAuth, async (req, res) => {
  const { receiver_id, text } = req.body;
  const senderId = req.userId;
  if (!receiver_id || !text) return res.status(400).json({ error: 'receiver_id y text requeridos' });
  if (text.trim().length === 0) return res.status(400).json({ error: 'Mensaje vacío' });
  if (text.length > 1000) return res.status(400).json({ error: 'Máximo 1000 caracteres' });

  // Verificar amistad
  const [{ data: sf1 }, { data: sf2 }] = await Promise.all([
    supabase.from('friendships').select('id').eq('requester_id', senderId).eq('addressee_id', receiver_id).maybeSingle(),
    supabase.from('friendships').select('id').eq('requester_id', receiver_id).eq('addressee_id', senderId).maybeSingle(),
  ]);
  if (!sf1 || !sf2) return res.status(403).json({ error: 'Error al mandar mensaje (ambas personas deben seguirse)' });

  const { data, error } = await supabase.from('messages')
    .insert({ sender_id: senderId, receiver_id, text: text.trim() })
    .select('id, sender_id, receiver_id, text, read, created_at').single();
  if (error) return res.status(500).json({ error: error.message });

  // Notificar al receptor
  await createNotif(receiver_id, senderId, 'new_message', data.id);

  res.status(201).json({ message: data });
});

// POST /api/messages/nudge → mensaje predeterminado sin requerir follow mutuo (máx 3 veces)
app.post('/api/messages/nudge', requireAuth, async (req, res) => {
  const { receiver_id } = req.body;
  const senderId = req.userId;
  if (!receiver_id) return res.status(400).json({ error: 'receiver_id requerido' });
  if (receiver_id === senderId) return res.status(400).json({ error: 'No puedes enviarte un nudge a ti mismo' });

  const NUDGE_TEXT = 'Sígueme para poder enviarte un mensaje, debo decirte algo';
  const MAX_NUDGES = 3;

  // Contar cuántos nudges ya mandé a este usuario
  const { count } = await supabase.from('messages')
    .select('id', { count: 'exact', head: true })
    .eq('sender_id', senderId)
    .eq('receiver_id', receiver_id)
    .eq('text', NUDGE_TEXT);

  if ((count ?? 0) >= MAX_NUDGES) {
    return res.status(429).json({ error: 'Ya enviaste el máximo de mensajes de este tipo (3)', nudge_count: count });
  }

  const { data, error } = await supabase.from('messages')
    .insert({ sender_id: senderId, receiver_id, text: NUDGE_TEXT })
    .select('id, sender_id, receiver_id, text, read, created_at').single();
  if (error) return res.status(500).json({ error: error.message });

  await createNotif(receiver_id, senderId, 'new_message', data.id);

  res.status(201).json({ message: data, nudge_count: (count ?? 0) + 1, nudges_left: MAX_NUDGES - (count ?? 0) - 1 });
});

app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
