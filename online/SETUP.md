# Turning on online play (about 10 minutes, free)

The game works without this. Until it's done, only **Guest mode (offline)** and Single Player work.
Accounts, Friends and Play with friend need a small free online database. We use **Supabase**.

## 1. Make a Supabase project
1. Go to https://supabase.com and click **Start your project**. Sign in with GitHub.
2. Click **New project**.
   - Name: `the-smasher`
   - Database password: click **Generate a password** and keep it somewhere safe. **Never send it to anyone, Claude included.**
   - Region: **Northeast Asia (Seoul)**. This keeps the game fast in Korea.
   - Plan: **Free**.
3. Wait 1 to 2 minutes while it sets up.

## 2. Allow guest-style sign-in
Players don't use email. Each browser signs in "anonymously" first, and then our own ID and password are checked.
1. Left menu: **Authentication**, then **Sign In / Providers** (on some screens it's under **Settings**).
2. Turn on **Allow anonymous sign-ins** and click **Save**.

## 3. Create the tables
1. Left menu: **SQL Editor**, then **New query**.
2. Open [`setup.sql`](setup.sql), copy everything, and paste it in.
3. Click **Run**. You should see "Success. No rows returned".

## 4. Send Claude two public values
Left menu: **Project Settings**, then **API** (or **API Keys**). Copy these two:
- **Project URL**, which looks like `https://abcdefgh.supabase.co`
- **anon public** key, or the **publishable** key (`sb_publishable_...`)

These two are made to be public, so it's safe to paste them in the chat.
**Never send** the `service_role` or **secret** key, or the database password.

Claude puts them at the top of the online script (`ONLINE_CONFIG`) in `index.html` and pushes the update.

## Good to know
- The free plan pauses a project after about a week with no players. Open the Supabase dashboard and click **Restore** to wake it.
- The game allows 15 players online at the same time. Player 16 sees "Server full".
- In a match, the two players' computers talk to each other directly. If that's blocked, the game sends the data through Supabase instead.
