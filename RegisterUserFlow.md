# Contexto: Componente de Registro de Usuarios

## Archivos involucrados
- `Register.razor` — componente a modificar
- `AuthEndpoints.cs` — referencia de endpoints (no modificar)

## Objetivo
Implementar la lógica de registro con flujos distintos según el estado de autenticación
y el rol del usuario actual.

## Flujos requeridos

### 1. Usuario no autenticado
- Mostrar dos opciones:
  - Registrarse como `User` regular (ingresa sus propias credenciales).
  - Registrarse como `Guest` (el sistema genera las credenciales automáticamente;
    el usuario no ingresa nada).

### 2. Usuario autenticado con rol `SuperAdmin` (claim en JWT)
- Mostrar únicamente la opción de registrar un nuevo `Admin`.

### 3. Usuario autenticado sin rol `SuperAdmin`
- Redirigir inmediatamente al home (`/`).
- No renderizar ningún contenido del componente.

## Reglas de negocio
- La detección del rol debe hacerse leyendo los claims del JWT desde el contexto actual.
- La opción de registrar un `Admin` nunca debe ser visible para usuarios no autenticados
  ni para usuarios sin el claim `SuperAdmin`.
- El flujo `Guest` no requiere ningún input del usuario; las credenciales son generadas
  completamente por el sistema.

## Restricciones
- No modificar `AuthEndpoints.cs`.
- Mantener la estructura y convenciones de código del componente existente.

## Endpoints disponibles (`AuthEndpoints.cs`)
| Endpoint           | Método | Descripción                                 | Requiere auth        |
|--------------------|--------|---------------------------------------------|----------------------|
| `/register`        | POST   | Registra un usuario con rol `User` o `Guest`| No                   |
| `/register-admin`  | POST   | Registra un usuario con rol `Admin`         | Sí (`SuperAdminPolicy`) |
| `/login`           | POST   | Autentica y devuelve JWT + refresh token    | No                   |
| `/refresh`         | POST   | Renueva el access token                     | No                   |

### Payload de `/register` y `/register-admin`
```json
{
  "UserName": "string",
  "Password": "string",
  "Role": "string"
}
```
