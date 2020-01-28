# discord-inviter

Discord invite generator which creates a unique invite and records requestor information for combating abuse. The
requestor's IP address, user agent, and client language are recorded by default. The recorded information is saved in
a SQLite database and posted to a channel on the server (determined by the `CHANNEL_ID` environment variable). Invites
are valid for 5 minutes and limited to a single use by default.