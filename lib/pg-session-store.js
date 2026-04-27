function createPgSessionStore(session, pool, logger = console) {
  class PgSessionStore extends session.Store {
    get(sid, callback) {
      pool.query("SELECT sess FROM sessions WHERE sid = $1 AND expire > NOW()", [sid])
        .then((result) => callback(null, result.rows[0]?.sess || null))
        .catch((err) => callback(err));
    }

    set(sid, sess, callback = () => {}) {
      const expires = sess?.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + 86400000);
      pool.query(
        `INSERT INTO sessions (sid, sess, expire)
         VALUES ($1, $2::jsonb, $3)
         ON CONFLICT (sid)
         DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire`,
        [sid, JSON.stringify(sess), expires]
      )
        .then(() => callback(null))
        .catch((err) => callback(err));
    }

    destroy(sid, callback = () => {}) {
      pool.query("DELETE FROM sessions WHERE sid = $1", [sid])
        .then(() => callback(null))
        .catch((err) => callback(err));
    }

    touch(sid, sess, callback = () => {}) {
      const expires = sess?.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + 86400000);
      pool.query("UPDATE sessions SET expire = $2 WHERE sid = $1", [sid, expires])
        .then(() => callback(null))
        .catch((err) => callback(err));
    }

    clearExpired() {
      pool.query("DELETE FROM sessions WHERE expire <= NOW()").catch((err) => {
        logger.error?.(`Session cleanup failed: ${err.message}`);
      });
    }
  }

  const store = new PgSessionStore();
  const cleanupTimer = setInterval(() => store.clearExpired(), 60 * 60 * 1000);
  cleanupTimer.unref?.();
  return store;
}

module.exports = { createPgSessionStore };
