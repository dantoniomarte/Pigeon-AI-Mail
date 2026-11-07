# Instrucciones para agentes (plantilla — vale para todos los proyectos)

## Aislamiento de sesión — OBLIGATORIO

Antes de escribir el primer archivo de una tarea nueva:

1. Si ya estás en un worktree propio de esta tarea, continuá ahí.
2. Si no, creá un worktree aislado en una rama nueva, siempre desde `origin/<rama-default>`
   recién sincronizada, sin arrastrar otras ramas, sesiones ni PRs — por ejemplo
   `git worktree add ../<repo>-worktrees/<tarea> -b feat/<tarea> origin/main` — y trabajá
   exclusivamente ahí.
3. Nunca trabajes, commitees ni cambies de rama en el checkout principal ni en worktrees que
   no creó esta sesión. Si `git status` muestra archivos que no creaste vos, reportálos.
4. Cada sesión abre, mergea y despliega SÓLO los PRs que abrió ella.
5. Al terminar y mergear el PR, eliminá el worktree (`git worktree remove <ruta>`) para limpiar.

## Revisión independiente antes del merge

Todo PR lleva una sección `## Independent review` en su cuerpo, hecha por un agente distinto
del que escribió el cambio. Sin ese artefacto, el PR no está listo para mergear.

## Convenciones del flujo

- 1 tarea = 1 rama (cortada desde `origin/main` fresco) = 1 PR.
- El merge es squash (1 commit por PR) y la rama se borra sola.
- Test primero, con mutación para verificar que el test puede fallar.
- Si el proyecto usa Postgres: todo SQL nuevo se prueba contra Postgres desde el día uno.
