# Pigeon Mail × Docker (remote stdio)

When Pigeon runs in a container, the cleanest local connection is **`docker
exec`**: the agent talks stdio to a process *inside* the container, so the
database and master key never leave it and nothing has to be copied to the host.

## 1. Find the container name and the binary path

```bash
docker ps --format '{{.Names}}\t{{.Image}}' | grep -i pigeon
# the shipped configs use the container_name from docker-compose.example.yml
# (a bare `docker compose up` without container_name derives pigeon-<project>-<service>-1)

docker exec pigeon-mail /usr/local/bin/pigeon --version
```

The Compose service is defined in [`../../docker-compose.yml`](../../docker-compose.yml);
the image is distroless, so the binary is the only thing you can execute there —
which is exactly what `docker exec -i` needs.

## 2. Where the file goes

`mcp-docker.json` is a ready `mcpServers` map. Put it wherever your agent's
SETUP.md says (`~/.cursor/mcp.json`, `~/.pi/agent/mcp.json`, …) and adjust the
container name in `args` if yours differs.

## 3. Environment

The container already defines the paths (see the image `ENV` and
`docker-compose.yml`), so the `--env` entries in `args` are explicit rather than
required:

| Variable | Value inside the container |
|---|---|
| `PIGEON_DB_PATH` | `/var/lib/pigeon/pigeon.db` (the `pigeon-data` volume) |
| `PIGEON_MASTER_KEY_FILE` | `/etc/pigeon/master.key` (mounted `./secrets`, read-only) |

No API key and no `PIGEON_URL` are needed on this path: the exec'd process opens
the real store and key.

## 4. Quick test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | docker exec -i pigeon-mail /usr/local/bin/pigeon mcp \
  | grep -o '"name"' | wc -l     # expect 27
```

Then point the agent at the same command line and check that its MCP panel lists
`pigeon-mail` (add `container_name: pigeon-mail` to your compose service, or
edit the config to your derived name — config and container must match).

## 5. Notes

- **Permissions** — the user running the agent needs to talk to the Docker
  daemon (`docker` group membership). That is root-equivalent access on the host;
  prefer the remote/REST path when the agent is not trusted.
- **`-i` is mandatory** — without it stdin is not attached and the stdio
  transport gets EOF immediately.
- **Do not use `docker run --rm … pigeon mcp`** unless you mount the same
  `pigeon-data` volume and `secrets` directory; a bare `docker run` gets an empty
  database and no master key.
- **Docker Desktop / remote contexts** work the same way as long as the container
  is visible from the agent's Docker context.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `permission denied while trying to connect to the Docker daemon socket` | add the user to the `docker` group and start a new session |
| `No such container` | the Compose project name differs — read it from `docker ps` |
| Server starts and exits at once | the container lost its `secrets/master.key` mount; check `docker compose logs pigeon` |
