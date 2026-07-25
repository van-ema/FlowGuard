# Flowguard Landing Page

This directory contains a static landing-page draft for Flowguard.

Open it locally:

```sh
open website/index.html
```

Or serve it from the repository root:

```sh
python3 -m http.server 8080
```

Then visit:

```text
http://127.0.0.1:8080/website/
```

The page is intentionally framework-free so it can later be deployed through
GitHub Pages, Cloudflare Pages, Netlify, or another static host without a build
step.

## Demo Request Form

The `Book a demo` form inserts email addresses into Supabase.

The landing page loads Supabase settings from `website/config.js`. The
publishable key is browser-safe when Row Level Security is enabled and the table
only allows anonymous inserts.

To point the page at another Supabase project, copy the example config:

```sh
cp website/config.example.js website/config.js
```

Then edit `website/config.js`:

```js
window.FlowguardSupabase = {
  url: "https://YOUR_PROJECT_REF.supabase.co",
  publishableKey: "YOUR_SUPABASE_PUBLISHABLE_KEY",
  table: "demo_requests",
};
```

Use the Supabase publishable key, never the service role key.

The table only needs:

```sql
create table demo_requests (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  created_at timestamptz not null default now()
);
```

Enable Row Level Security and allow anonymous inserts only. Do not add public
`select`, `update`, or `delete` policies for this table.
