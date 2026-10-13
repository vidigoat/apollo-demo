# apollo-demo

A tiny project whose only job is to show [Apollo](https://apollo-watch.vercel.app) on a real pull request.

It depends on `source-map-js`. The open pull request bumps it from 1.2.1 to 1.2.2 — a patch release
with 137 million downloads a week. Apollo's live watch ran that pair in two Nebius Sandboxes when it
was published, and 1.2.2 builds and runs code at import that 1.2.1 never did (`Function("return 0")`).

The workflow in `.github/workflows/apollo.yml` asks Apollo's published record about every version a
pull request changes. It installs nothing and runs nobody's code; it reads what was already watched.
"Alarming" means *read this before merging*, never *malicious*.

`.github/apollo/cli.cjs` is the Apollo CLI bundled into one file from
[github.com/vidigoat/apollo](https://github.com/vidigoat/apollo), so the check needs nothing but
Node. MIT.
