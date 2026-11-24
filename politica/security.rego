package internaldesk.security

import rego.v1

deny contains msg if {
	input.run_as_root == true
	msg := "POLITICA VIOLADA: el contenedor no debe ejecutarse como root (run_as_root=true)."
}

deny contains msg if {
	input.debug_mode == true
	msg := "POLITICA VIOLADA: el modo debug debe estar desactivado fuera de desarrollo (debug_mode=true)."
}

deny contains msg if {
	input.allow_public_admin == true
	msg := "POLITICA VIOLADA: los endpoints administrativos no pueden exponerse públicamente."
}