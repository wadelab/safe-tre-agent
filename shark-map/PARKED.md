# Parked copy of Shark Map

This folder is a backup of the Shark Map site, which belongs in its own repository,
`wadelab/shark-map`. It is parked on this session branch only because the session could not
create that repository. Nothing here is part of SafeTRE, and this branch should not be merged.

To move it once the empty repository exists:

```bash
git clone --branch ccr-86e32277-qyua3m https://github.com/wadelab/safe-tre-agent.git tmp
cp -r tmp/shark-map shark-map && cd shark-map && rm PARKED.md
git init -b main && git add -A && git commit -m "Add static shark occurrence map"
git remote add origin https://github.com/wadelab/shark-map.git && git push -u origin main
```
