# Flujo de trabajo (plantilla — condensado)

## El ciclo

```
reproducir el error → test que falla → arreglo (verde) → rama nueva → PR
→ revisión independiente → merge (squash) → deploy verificado
```

## Reglas

1. **Rama desde `origin/main` fresco**, nunca desde un main local viejo ni desde otra rama:
   creá un worktree aislado en una rama nueva cortada desde `origin/main` recién sincronizado,
   por ejemplo `git worktree add ../<repo>-worktrees/<tarea> -b feat/<tarea> origin/main`.
2. **Un commit por cambio lógico**, con su test y su doc en el mismo commit.
3. **Test primero** y verificar el test con una mutación: si sigue verde con el código roto,
   el test no sirve.
4. **Postgres primero** (si aplica): SQL nuevo sin prueba contra Postgres no está probado.
5. **PR con cuerpo completo**: síntoma, causa, cambio, verificación + sección
   `## Independent review` (agente distinto del autor).
6. **Merge squash** con la CI del carril de PR en verde; la suite completa corre en `main`
   antes del deploy.
7. **Limpieza**: eliminá el worktree (`git worktree remove <ruta>`) después del merge.

## Consulta antes de mergear (sin excepciones)

Cambios sin vuelta atrás: facturación, autenticación/permisos, datos guardados, secretos.
