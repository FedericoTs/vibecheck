# Launch copy

Draft for Show HN, X, and Reddit. Written to be edited, not pasted blind.

---

## Show HN

**Title**

```
Show HN: Vibecheck - see what a stranger can already read from your app
```

**Body**

```
I kept seeing the same thing in apps built with Lovable, v0, Bolt and Cursor. The
database is wide open, the API key is sitting in the JavaScript bundle, and the
person who shipped it has no idea, because nothing looks broken from the outside.

So I built a scanner for it. You paste your URL, it takes about 30 seconds, and it
shows you what any visitor could already get.

It runs 110+ checks. Some of the ones people are usually surprised by:

- Can anyone read your database tables with the public key your app ships?
- Are your storage buckets listable by strangers?
- Is a Stripe, AWS, OpenAI or database password sitting in your bundle?
- Are your source maps public, so your original code can be reconstructed?
- Is a dev build or a dev-only endpoint live in production?
- Are /admin, /api/users or /.env answering without a login?
- Is there invisible Unicode text on your page that a human cannot see but an AI
  reading your site will follow?
- Can someone send email that looks like it came from your domain?
- Can ChatGPT and Claude actually read your site, or are you blocking them?

The part I care most about: when it finds something, it gives you the exact curl
command that proves it. You paste it into your own terminal and watch your own
rows come back. A grade is arguable. A request you can re-run is not.

The database check runs in your browser using the public key your app already
ships, so your key and your data never touch my server. Everything else is a
plain GET of pages that are already public.

While building it I audited it against real sites and found six cases where it
accused an app of something that was not true. Every single one came from a check
that pattern matches and concludes. None came from the check that actually runs a
request and observes the answer. That changed how I built the rest of it. Where I
cannot rule out an innocent explanation, it reports the finding but refuses to
let it move your grade.

Free, no signup, MIT licensed. I am not selling anything.

https://ismyappleaking.com
https://github.com/FedericoTs/vibecheck

Happy to answer anything, including where it is still wrong.
```

**Notes before posting**

- Post Tuesday to Thursday, around 8 to 10am ET.
- Do not ask for upvotes anywhere. It gets flagged.
- Sit on the thread for the first 3 hours and reply to everything.
- When someone finds a false positive, thank them and fix it that day. On HN that
  earns more than the launch does.

---

## X / Twitter

**Post 1**

```
Most apps built with AI have their database wide open and nobody notices,
because nothing looks broken from the outside.

Built a free scanner for it. Paste your URL, 30 seconds, 110+ checks.

If it finds something it hands you the curl command so you can prove it yourself.

ismyappleaking.com
```

**Post 2 (reply, this is the one that travels)**

```
The uncomfortable part.

While building it I ran it against real sites and found 6 cases where it accused
an app of something untrue.

Every one came from a check that guesses. Zero came from the check that actually
runs a request and looks at the answer.

So I stopped adding checks that guess.
```

**Post 3 (reply)**

```
What it looks at:

- tables anyone can read with your public key
- keys left in your JS bundle
- public source maps
- dev builds shipped to production
- /admin and /.env answering without a login
- invisible text on your page aimed at AI crawlers
- whether anyone can spoof email from your domain

Free, open source, no signup.
```

---

## Reddit

r/SideProject, r/webdev, r/Supabase, r/nextjs. One at a time, a few days apart.
Rewrite the opening line for each so it does not read as copy paste.

```
Title: I built a free tool that shows you what a stranger can already read from
your app

If you built something with Lovable, v0, Bolt or Cursor, there is a decent chance
your database is readable by anyone with your public key. Not because you did
anything stupid, but because the default is open and nothing tells you.

Paste your URL, wait 30 seconds, get a report. 110+ checks. If it finds something
it gives you the exact command to prove it yourself, so you are not taking my word
for it.

The database check runs in your browser, so your key never reaches me.

Free, open source, no signup: ismyappleaking.com
```

---

## Second wave: the aggregate study

This is the thing that actually travels, and it needs the launch to happen first
so there are numbers to report.

Nobody can currently answer a basic question: of the apps being built with AI
right now, how many are shipping an open database? You will be able to.

**The safe and much better version of the YC idea**

The instinct is right, but scanning named companies and posting what you find is
the version that backfires. Here is the version that gets the same reach without
the risk:

- **Public repos only.** Source that is already published. No scanning of anyone's
  live app without their say so.
- **Never name anyone.** Publish counts, not companies. "Of 120 public repos from
  funded startups, 14 had a committed credential" is a story. "Company X leaked a
  key" is a fight you do not want and cannot win.
- **Tell them privately first, and give them time.** Email every affected repo
  before you publish anything. Two weeks is normal. This is the step that turns
  it from an attack into a favour.
- **Say in the post that you did that.** "I found these, I emailed all of them
  first, here are the numbers." That sentence is worth more than the findings.

Why this works better than the callout version: the callout gets you one angry
news cycle and a reputation as the person who dunks on startups. The disclosure
version gets you the same numbers, plus a pile of founders who now owe you one.
For a security tool, being the person who told them quietly is the whole
business.

**What to publish**

- % of scanned repos with a credential committed to source
- % where the credential was still live
- most common single mistake
- which AI tool's default scaffolding shows up most often

Nobody else has this data. It is a genuine contribution and it is unrepeatable by
anyone who did not build the scanner.

---

## Before you post

Verified in the pre-launch readiness pass (25 Aug 2026), all green:

- [x] SPF and DMARC on ismyappleaking.com — live: `v=spf1 -all` and DMARC
      `p=reject`. The tool grades its own domain A, so a curious commenter finds
      it locked down.
- [x] Scanned the tool's own site — grade A, 61/61 checks pass, 0 to fix.
      Screenshot that result for the post.
- [x] Repo is public, MIT, README matches the claims. No server secret anywhere
      in the 122-commit history (checked).
- [x] Every link in this copy resolves (200). `/terms` and `/privacy` now
      redirect to `/legal` instead of 404.
- [ ] Watch the partial-scan rate for the first few hours. Above 10% means
      something upstream is throttling and reports are degrading.
