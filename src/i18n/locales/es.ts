const es = {
  // App shell
  "app.title": "LocalVault",

  // Create vault
  "create.title": "Crear Bóveda",
  "create.password": "Contraseña Maestra",
  "create.confirm": "Confirmar Contraseña",
  "create.submit": "Crear Bóveda",
  "create.policy.length": "Al menos 12 caracteres",
  "create.policy.uppercase": "Al menos una letra mayúscula",
  "create.policy.lowercase": "Al menos una letra minúscula",
  "create.policy.digit": "Al menos un dígito",
  "create.policy.symbol": "Al menos un símbolo",
  "create.creating": "Creando bóveda…",

  // Unlock
  "unlock.title": "Desbloquear Bóveda",
  "unlock.password": "Contraseña Maestra",
  "unlock.submit": "Desbloquear",
  "unlock.unlocking": "Desbloqueando…",

  // Vault list
  "list.title": "Credenciales",
  "list.empty": "Aún no hay credenciales. ¡Crea la primera!",
  "list.search": "Buscar credenciales…",
  "list.category": "Categoría",
  "list.username": "Usuario",
  "list.service": "Servicio",
  "list.password": "Contraseña",
  "list.show_password": "Mostrar contraseña",
  "list.hide_password": "Ocultar contraseña",
  "list.edit": "Editar",
  "list.delete": "Eliminar",
  "list.create": "Nueva Credencial",

  // Credential form
  "form.create_title": "Nueva Credencial",
  "form.edit_title": "Editar Credencial",
  "form.service_name": "Nombre del Servicio",
  "form.username": "Usuario",
  "form.password": "Contraseña",
  "form.url": "URL",
  "form.category": "Categoría",
  "form.notes": "Notas",
  "form.save": "Guardar",
  "form.cancel": "Cancelar",
  "form.required": "Requerido",

  // Confirm dialog
  "confirm.title": "Confirmar Eliminación",
  "confirm.message":
    "¿Estás seguro de que deseas eliminar esta credencial? Esta acción no se puede deshacer.",
  "confirm.yes": "Eliminar",
  "confirm.no": "Cancelar",

  // Toast messages
  "toast.credential_created": "Credencial creada exitosamente.",
  "toast.credential_updated": "Credencial actualizada exitosamente.",
  "toast.credential_deleted": "Credencial eliminada.",
  "toast.vault_locked": "Bóveda bloqueada.",
  "toast.language_changed": "Idioma cambiado.",

  // Errors (CRY-04: single opaque message)
  "errors.unlock_failed":
    "No se pudo desbloquear la bóveda. Verifica tu contraseña e intenta de nuevo.",
  "errors.no_vault": "No existe una bóveda. Crea una primero.",
  "errors.already_exists": "Ya existe una bóveda.",
  "errors.vault_locked": "La bóveda está bloqueada. Desbloquéala primero.",
  "errors.not_found": "Credencial no encontrada.",
  "errors.internal": "Ocurrió un error inesperado. Intenta de nuevo.",

  // Validation errors
  "errors.password_too_short": "La contraseña debe tener al menos {{min}} caracteres.",
  "errors.password_missing_uppercase":
    "La contraseña debe contener al menos una letra mayúscula.",
  "errors.password_missing_lowercase":
    "La contraseña debe contener al menos una letra minúscula.",
  "errors.password_missing_digit": "La contraseña debe contener al menos un dígito.",
  "errors.password_missing_symbol": "La contraseña debe contener al menos un símbolo.",
  "errors.passwords_mismatch": "Las contraseñas no coinciden.",
  "errors.empty_service_name": "El nombre del servicio no debe estar vacío.",
  "errors.empty_username": "El usuario no debe estar vacío.",
  "errors.field_too_long": "El campo debe tener como máximo {{max}} caracteres.",

  // Theme
  "theme.dark": "Oscuro",
  "theme.light": "Claro",
  "theme.system": "Sistema",
} as const;

export default es;
