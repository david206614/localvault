const en = {
  // App shell
  "app.title": "LocalVault",

  // Create vault
  "create.title": "Create Vault",
  "create.password": "Master Password",
  "create.confirm": "Confirm Password",
  "create.submit": "Create Vault",
  "create.policy.length": "At least 12 characters",
  "create.policy.uppercase": "At least one uppercase letter",
  "create.policy.lowercase": "At least one lowercase letter",
  "create.policy.digit": "At least one digit",
  "create.policy.symbol": "At least one symbol",
  "create.creating": "Creating vault…",

  // Unlock
  "unlock.title": "Unlock Vault",
  "unlock.password": "Master Password",
  "unlock.submit": "Unlock",
  "unlock.unlocking": "Unlocking…",

  // Vault list
  "list.title": "Credentials",
  "list.empty": "No credentials yet. Create your first one!",
  "list.search": "Search credentials…",
  "list.category": "Category",
  "list.username": "Username",
  "list.service": "Service",
  "list.password": "Password",
  "list.show_password": "Show password",
  "list.hide_password": "Hide password",
  "list.edit": "Edit",
  "list.delete": "Delete",
  "list.create": "New Credential",

  // Credential form
  "form.create_title": "New Credential",
  "form.edit_title": "Edit Credential",
  "form.service_name": "Service Name",
  "form.username": "Username",
  "form.password": "Password",
  "form.url": "URL",
  "form.category": "Category",
  "form.notes": "Notes",
  "form.save": "Save",
  "form.cancel": "Cancel",
  "form.required": "Required",

  // Confirm dialog
  "confirm.title": "Confirm Deletion",
  "confirm.message": "Are you sure you want to delete this credential? This action cannot be undone.",
  "confirm.yes": "Delete",
  "confirm.no": "Cancel",

  // Toast messages
  "toast.credential_created": "Credential created successfully.",
  "toast.credential_updated": "Credential updated successfully.",
  "toast.credential_deleted": "Credential deleted.",
  "toast.vault_locked": "Vault locked.",
  "toast.language_changed": "Language changed.",

  // Errors — unlocked failed (CRY-04: single opaque message)
  "errors.unlock_failed": "Unable to unlock the vault. Check your password and try again.",
  "errors.no_vault": "No vault exists. Create one first.",
  "errors.already_exists": "A vault already exists.",
  "errors.vault_locked": "Vault is locked. Unlock it first.",
  "errors.not_found": "Credential not found.",
  "errors.internal": "An unexpected error occurred. Please try again.",

  // Validation errors (SES-01 + credential validation)
  "errors.password_too_short": "Password must be at least {{min}} characters.",
  "errors.password_missing_uppercase": "Password must contain at least one uppercase letter.",
  "errors.password_missing_lowercase": "Password must contain at least one lowercase letter.",
  "errors.password_missing_digit": "Password must contain at least one digit.",
  "errors.password_missing_symbol": "Password must contain at least one symbol.",
  "errors.passwords_mismatch": "Passwords do not match.",
  "errors.empty_service_name": "Service name must not be empty.",
  "errors.empty_username": "Username must not be empty.",
  "errors.field_too_long": "Field must be at most {{max}} characters.",

  // Theme
  "theme.dark": "Dark",
  "theme.light": "Light",
  "theme.system": "System",
} as const;

export default en;
