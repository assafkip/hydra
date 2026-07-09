// Chunk-6 auth: the founder's Supabase project — identity only. Both values are PUBLIC by design:
// the anon key is meant to live in the client bundle (Supabase protects data with row-level security,
// not by hiding this key), and the URL is the public project endpoint. The founder's Supabase stores
// only the email + a password hash + login metadata; it never receives the data key or any case data.
export const SUPABASE_URL = "https://yvermtklysygaeetxcyb.supabase.co";
export const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl2ZXJtdGtseXN5Z2FlZXR4Y3liIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODE3MzYxMDYsImV4cCI6MjA5NzMxMjEwNn0.l0tOxlbH0Z0yt398hDpQtPB5y10AogXRe2tOhB2qdpU";
